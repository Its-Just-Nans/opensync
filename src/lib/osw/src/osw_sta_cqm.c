/*
Copyright (c) 2015, Plume Design Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
   1. Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
   3. Neither the name of the Plume Design Inc. nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL Plume Design Inc. BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/**
 * osw_sta_cqm.c - Station Client Quality Monitoring for OpenSync
 *
 * This module tracks Wi-Fi client (station) connection quality in OpenSync.
 * It keeps per-station and per-link statistics such as packet success rates,
 * average PHY rates, and SNR. Logs are maintained for each link, and basic
 * heuristics are used to flag links with potentially poor quality.
 *
 * Features:
 * - Tracks associations and links for each station
 * - Periodically logs connection statistics
 * - Flags links with low SNR, PSR, or Mbps as "troubled"
 * - Manages log memory and cleans up on disconnect
 *
 * Purpose:
 * - Helps monitor client connection quality over time
 * - Can assist with troubleshooting and basic diagnostics
 * - Designed to be lightweight and efficient
 */

/* libc */
#include <stdint.h>
#include <stddef.h>

/* 3rd party */
#include <ev.h>

/* opensync */
#include <log.h>
#include <os.h>
#include <os_time.h>
#include <ds_dlist.h>
#include <ds_tree.h>

/* osw */
#include <osw_types.h>
#include <osw_module.h>
#include <osw_sta_assoc.h>
#include <osw_state.h>
#include <osw_time.h>
#include <osw_timer.h>
#include <osw_stats.h>
#include <osw_stats_defs.h>
#include <osw_diag.h>

#define OSW_STA_CQM_STATS_REPORT_SECONDS   1
#define OSW_STA_CQM_STATS_POLL_SECONDS     1
#define OSW_STA_CQM_LOG_MAX_AGE_SECONDS    120
#define OSW_STA_CQM_LOG_MERGE_PERCENT_DIFF 10
#define OSW_STA_CQM_LOG_MERGE_DB_DIFF      10
#define OSW_STA_CQM_DESTROY_SECONDS        (OSW_STA_CQM_STATS_REPORT_SECONDS + 1)

/* These are some rule of thumb values that aren't
 * necessarily guaranteed to indicate poor link
 * quality, but in many cases can be associated
 * with it.
 */
#define OSW_STA_CQM_LOW_SNR_DB      10
#define OSW_STA_CQM_LOW_PSR_PERCENT 50
#define OSW_STA_CQM_LOW_MBPS        10

#define ABS_DIFF(a, b) ((a) > (b) ? (a) - (b) : (b) - (a))

#define LOG_PREFIX(fmt, ...) "osw_sta_cqm: " fmt, ##__VA_ARGS__

#define LOG_PREFIX_ASSOC(assoc, fmt, ...) \
    LOG_PREFIX("assoc: " OSW_HWADDR_FMT ": " fmt, OSW_HWADDR_ARG(&assoc->assoc_addr), ##__VA_ARGS__)

#define LOG_PREFIX_LINK(link, fmt, ...) \
    LOG_PREFIX_ASSOC(link->assoc, "link: %s: " fmt, link->vif_name ?: "*", ##__VA_ARGS__)

#define TROUBLED_REASON_MASK_FMT "%s%s%s%s%s%s"
#define TROUBLED_REASON_MASK_ARG(mask)                                                                             \
    (mask == 0) ? "no" : "yes:", (mask & (1 << OSW_STA_CQM_ASSOC_LINK_TROUBLED_REASON_LOW_SNR)) ? " low_snr" : "", \
            (mask & (1 << OSW_STA_CQM_ASSOC_LINK_TROUBLED_REASON_LOW_TX_PSR)) ? " low_tx_psr" : "",                \
            (mask & (1 << OSW_STA_CQM_ASSOC_LINK_TROUBLED_REASON_LOW_TX_MBPS)) ? " low_tx_mbps" : "",              \
            (mask & (1 << OSW_STA_CQM_ASSOC_LINK_TROUBLED_REASON_LOW_RX_PSR)) ? " low_rx_psr" : "",                \
            (mask & (1 << OSW_STA_CQM_ASSOC_LINK_TROUBLED_REASON_LOW_RX_MBPS)) ? " low_rx_mbps" : ""

/* This uses strdupa() to workaround ambiguity of the
 * ({ ... }) expression vs stack allocations. Without
 * strdupa() the buffers can clash and overwrite one
 * another.
 */
#define LOG_PREFIX_LINK_LOG_ENTRY(log, fmt, ...)                                                      \
    LOG_PREFIX_LINK(                                                                                  \
            log->link,                                                                                \
            "log: %s..+%u sec:"                                                                       \
            " idle(%u sec)"                                                                           \
            " tx(pkts:%u mbps:%u psr:%u%%)"                                                           \
            " rx(pkts:%u mbps:%u psr:%u%% snr:%u)"                                                    \
            " troubled=" TROUBLED_REASON_MASK_FMT ": " fmt,                                           \
            ({                                                                                        \
                char buf[64];                                                                         \
                const bool ok = time_to_str(log->timestamp, buf, sizeof(buf));                        \
                ok ? strdupa(buf) : "invalid";                                                        \
            }),                                                                                       \
            log->duration_sec,                                                                        \
            (log->duration_sec - log->activity_sec),                                                  \
            log->tx_pkts,                                                                             \
            log->tx_avg_phyrate_mbps,                                                                 \
            log->tx_psr_percent,                                                                      \
            log->rx_pkts,                                                                             \
            log->rx_avg_phyrate_mbps,                                                                 \
            log->rx_psr_percent,                                                                      \
            log->rx_snr,                                                                              \
            TROUBLED_REASON_MASK_ARG(osw_sta_cqm_assoc_link_log_entry_get_troubled_reason_mask(log)), \
            ##__VA_ARGS__)

typedef struct osw_sta_cqm osw_sta_cqm_t;
typedef struct osw_sta_cqm_assoc osw_sta_cqm_assoc_t;
typedef struct osw_sta_cqm_assoc_link_id osw_sta_cqm_assoc_link_id_t;
typedef struct osw_sta_cqm_assoc_link osw_sta_cqm_assoc_link_t;
typedef struct osw_sta_cqm_assoc_link_log_entry osw_sta_cqm_assoc_link_log_entry_t;

struct osw_sta_cqm
{
    ds_tree_t assocs; /**< see osw_sta_cqm_assoc_t; keyed by assoc_addr */
    ds_tree_t links;  /**< see osw_sta_cqm_assoc_link_t; keyed by link id, global for fast lookup */
    struct osw_stats_subscriber *stats_sub; /**< subscription handle for stats reporting */
    osw_sta_assoc_observer_t *assoc_obs;    /** association observer handle */
    ev_signal sigusr1;                      /**< signal handler for SIGUSR1 to dump state */
};

struct osw_sta_cqm_assoc
{
    ds_tree_node_t node;
    osw_sta_cqm_t *m;
    struct osw_hwaddr assoc_addr; /**< this can be the MLD addr in case of MLO associations */
    ds_tree_t links;              /**< see: osw_sta_cqm_assoc_link_t */
    struct osw_timer destroy_timer;
};

struct osw_sta_cqm_assoc_link_id
{
    struct osw_hwaddr local_addr;
    struct osw_hwaddr remote_addr;
};

struct osw_sta_cqm_assoc_link
{
    ds_tree_node_t node_m;
    ds_tree_node_t node_assoc;
    osw_sta_cqm_assoc_t *assoc;
    ds_dlist_t logs; /**< see: osw_sta_cqm_assoc_link_log_entry_t */
    osw_sta_cqm_assoc_link_id_t id;
    char *vif_name;
    uint8_t troubled_mask;
};

/* Log entry may end up representing a time frame of
 * multiples of OSW_STA_CQM_STATS_REPORT_SECONDS. This is
 * done to reduce the number of log entries and memory
 * usage.
 */
struct osw_sta_cqm_assoc_link_log_entry
{
    ds_dlist_node_t node;
    osw_sta_cqm_assoc_link_t *link;
    time_t timestamp;
    uint32_t duration_sec; /**< time frame entry covers since timestamp */
    uint32_t activity_sec;
    uint32_t tx_pkts;
    uint32_t rx_pkts;
    uint32_t tx_avg_phyrate_mbps;
    uint32_t rx_avg_phyrate_mbps;
    uint8_t tx_psr_percent;
    uint8_t rx_psr_percent;
    uint8_t rx_snr;
    bool displayed;
} __attribute__((__packed__));

enum osw_sta_cqm_assoc_link_troubled_reason
{
    OSW_STA_CQM_ASSOC_LINK_TROUBLED_REASON_LOW_SNR,
    OSW_STA_CQM_ASSOC_LINK_TROUBLED_REASON_LOW_TX_PSR,
    OSW_STA_CQM_ASSOC_LINK_TROUBLED_REASON_LOW_TX_MBPS,
    OSW_STA_CQM_ASSOC_LINK_TROUBLED_REASON_LOW_RX_PSR,
    OSW_STA_CQM_ASSOC_LINK_TROUBLED_REASON_LOW_RX_MBPS,
};

enum osw_sta_cqm_assoc_link_log_entry_merge_result
{
    OSW_STA_CQM_ASSOC_LINK_LOG_ENTRY_MERGE_RESULT_OK,
    OSW_STA_CQM_ASSOC_LINK_LOG_ENTRY_MERGE_RESULT_TX_MBPS_TOO_DIFFERENT,
    OSW_STA_CQM_ASSOC_LINK_LOG_ENTRY_MERGE_RESULT_RX_MBPS_TOO_DIFFERENT,
    OSW_STA_CQM_ASSOC_LINK_LOG_ENTRY_MERGE_RESULT_TX_PSR_TOO_DIFFERENT,
    OSW_STA_CQM_ASSOC_LINK_LOG_ENTRY_MERGE_RESULT_RX_PSR_TOO_DIFFERENT,
    OSW_STA_CQM_ASSOC_LINK_LOG_ENTRY_MERGE_RESULT_SNR_TOO_DIFFERENT,
    OSW_STA_CQM_ASSOC_LINK_LOG_ENTRY_MERGE_RESULT_OVERFLOW_RISK_OLDER,
    OSW_STA_CQM_ASSOC_LINK_LOG_ENTRY_MERGE_RESULT_OVERFLOW_RISK_NEWER,
    OSW_STA_CQM_ASSOC_LINK_LOG_ENTRY_MERGE_RESULT_TROUBLED_REASON_MASK_DIFFERENT,
    OSW_STA_CQM_ASSOC_LINK_LOG_ENTRY_MERGE_RESULT_OLDER_IS_NULL,
    OSW_STA_CQM_ASSOC_LINK_LOG_ENTRY_MERGE_RESULT_NEWER_IS_NULL,
    OSW_STA_CQM_ASSOC_LINK_LOG_ENTRY_MERGE_RESULT_WRONG_LINK,
};

static int osw_sta_cqm_assoc_link_id_cmp(const void *a, const void *b)
{
    const osw_sta_cqm_assoc_link_id_t *x = a;
    const osw_sta_cqm_assoc_link_id_t *y = b;
    const int d = osw_hwaddr_cmp(&x->local_addr, &y->local_addr);
    if (d != 0) return d;
    return osw_hwaddr_cmp(&x->remote_addr, &y->remote_addr);
}

static char *osw_sta_cqm_assoc_get_vif_name(const struct osw_hwaddr *local_addr)
{
    if (local_addr == NULL) return NULL;

    const struct osw_state_vif_info *vif_info = osw_state_vif_lookup_by_mac_addr(local_addr);
    if (vif_info == NULL) return NULL;

    return STRDUP(vif_info->vif_name);
}

static osw_sta_cqm_assoc_link_t *osw_sta_cqm_assoc_link_alloc(
        osw_sta_cqm_assoc_t *assoc,
        const osw_sta_cqm_assoc_link_id_t *id)
{
    osw_sta_cqm_assoc_link_t *link = CALLOC(1, sizeof(*link));
    link->assoc = assoc;
    link->id = *id;
    link->vif_name = osw_sta_cqm_assoc_get_vif_name(&id->local_addr);
    ds_dlist_init(&link->logs, osw_sta_cqm_assoc_link_log_entry_t, node);
    ds_tree_insert(&assoc->m->links, link, &link->id);
    ds_tree_insert(&assoc->links, link, &link->id);
    LOGD(LOG_PREFIX_LINK(link, "allocated"));
    return link;
}

static void osw_sta_cqm_assoc_link_log_entry_drop(osw_sta_cqm_assoc_link_log_entry_t *log)
{
    if (log == NULL) return;

    ds_dlist_remove(&log->link->logs, log);
    FREE(log);
}

static void osw_sta_cqm_assoc_link_drop(osw_sta_cqm_assoc_link_t *link)
{
    if (link == NULL) return;

    LOGD(LOG_PREFIX_LINK(link, "dropping"));

    osw_sta_cqm_assoc_link_log_entry_t *log;
    while ((log = ds_dlist_head(&link->logs)) != NULL)
    {
        osw_sta_cqm_assoc_link_log_entry_drop(log);
    }

    ds_tree_remove(&link->assoc->m->links, link);
    ds_tree_remove(&link->assoc->links, link);
    FREE(link->vif_name);
    FREE(link);
}

static uint8_t osw_sta_cqm_assoc_link_log_entry_get_troubled_reason_mask(const osw_sta_cqm_assoc_link_log_entry_t *log)
{
    if (log == NULL) return 0;

    uint8_t mask = 0;

    if (log->rx_pkts > 0 && log->rx_snr < OSW_STA_CQM_LOW_SNR_DB)
        mask |= (1 << OSW_STA_CQM_ASSOC_LINK_TROUBLED_REASON_LOW_SNR);

    if (log->tx_pkts > 0 && log->tx_psr_percent < OSW_STA_CQM_LOW_PSR_PERCENT)
        mask |= (1 << OSW_STA_CQM_ASSOC_LINK_TROUBLED_REASON_LOW_TX_PSR);

    if (log->rx_pkts > 0 && log->rx_psr_percent < OSW_STA_CQM_LOW_PSR_PERCENT)
        mask |= (1 << OSW_STA_CQM_ASSOC_LINK_TROUBLED_REASON_LOW_RX_PSR);

    if (log->tx_pkts > 0 && log->tx_avg_phyrate_mbps < OSW_STA_CQM_LOW_MBPS)
        mask |= (1 << OSW_STA_CQM_ASSOC_LINK_TROUBLED_REASON_LOW_TX_MBPS);

    if (log->rx_pkts > 0 && log->rx_avg_phyrate_mbps < OSW_STA_CQM_LOW_MBPS)
        mask |= (1 << OSW_STA_CQM_ASSOC_LINK_TROUBLED_REASON_LOW_RX_MBPS);

    return mask;
}

static int osw_sta_cqm_assoc_link_log_entry_get_time_gap_between(
        const osw_sta_cqm_assoc_link_log_entry_t *older,
        const osw_sta_cqm_assoc_link_log_entry_t *newer)
{
    if (older == NULL || newer == NULL) return 0;

    const time_t older_ends_on = older->timestamp + older->duration_sec;
    const time_t newer_starts_on = newer->timestamp;

    if (newer_starts_on < older_ends_on) return 0;

    return newer_starts_on - older_ends_on;
}

static void osw_sta_cqm_assoc_display(osw_sta_cqm_assoc_t *assoc, const char *reason)
{
    if (assoc == NULL) return;

    osw_sta_cqm_assoc_link_t *link;
    ds_tree_foreach (&assoc->links, link)
    {
        osw_sta_cqm_assoc_link_log_entry_t *log;
        ds_dlist_foreach (&link->logs, log)
        {
            if (log->displayed) continue;
            LOGI(LOG_PREFIX_LINK_LOG_ENTRY(log, "%s", reason));
            osw_sta_cqm_assoc_link_log_entry_t *next = ds_dlist_next(&link->logs, log);
            const int time_gap = osw_sta_cqm_assoc_link_log_entry_get_time_gap_between(log, next);
            if (time_gap > 0)
            {
                LOGI(LOG_PREFIX_LINK(link, "next log entry starts in %d seconds", time_gap));
            }
            log->displayed = true;
        }
    }
}

static void osw_sta_cqm_assoc_drop(osw_sta_cqm_assoc_t *assoc)
{
    if (assoc == NULL) return;

    LOGD(LOG_PREFIX_ASSOC(assoc, "dropping"));

    osw_timer_disarm(&assoc->destroy_timer);

    osw_sta_cqm_assoc_link_t *link;
    while ((link = ds_tree_head(&assoc->links)) != NULL)
    {
        osw_sta_cqm_assoc_link_drop(link);
    }

    ds_tree_remove(&assoc->m->assocs, assoc);
    FREE(assoc);
}

static void osw_sta_cqm_assoc_destroy_timer_cb(struct osw_timer *timer)
{
    osw_sta_cqm_assoc_t *assoc = container_of(timer, osw_sta_cqm_assoc_t, destroy_timer);

    LOGD(LOG_PREFIX_ASSOC(assoc, "destroying"));
    osw_sta_cqm_assoc_display(assoc, "destroying");
    osw_sta_cqm_assoc_drop(assoc);
}

static osw_sta_cqm_assoc_t *osw_sta_cqm_assoc_alloc(osw_sta_cqm_t *m, const osw_sta_assoc_entry_t *e)
{
    if (m == NULL) return NULL;

    osw_sta_cqm_assoc_t *assoc = CALLOC(1, sizeof(*assoc));
    assoc->m = m;
    assoc->assoc_addr = *osw_sta_assoc_entry_get_addr(e);
    ds_tree_init(&assoc->links, osw_sta_cqm_assoc_link_id_cmp, osw_sta_cqm_assoc_link_t, node_assoc);
    ds_tree_insert(&m->assocs, assoc, &assoc->assoc_addr);
    osw_timer_init(&assoc->destroy_timer, osw_sta_cqm_assoc_destroy_timer_cb);

    const osw_sta_assoc_links_t *l = osw_sta_assoc_entry_get_active_links(e);
    size_t i;
    for (i = 0; i < l->count; i++)
    {
        const osw_sta_cqm_assoc_link_id_t id = {
            .local_addr = l->links[i].local_sta_addr,
            .remote_addr = l->links[i].remote_sta_addr,
        };

        osw_sta_cqm_assoc_link_t *link = ds_tree_find(&assoc->links, &id);
        if (link != NULL)
        {
            LOGW(LOG_PREFIX_LINK(link, "already exists, dropping"));
            osw_sta_cqm_assoc_link_drop(link);
        }

        osw_sta_cqm_assoc_link_alloc(assoc, &id);
    }

    LOGD(LOG_PREFIX_ASSOC(assoc, "allocated"));
    return assoc;
}

static osw_sta_cqm_assoc_link_t *osw_sta_cqm_assoc_link_lookup(
        osw_sta_cqm_t *m,
        const struct osw_hwaddr *local_addr,
        const struct osw_hwaddr *remote_addr)
{
    if (m == NULL) return NULL;
    if (local_addr == NULL) return NULL;
    if (remote_addr == NULL) return NULL;

    const osw_sta_cqm_assoc_link_id_t id = {
        .local_addr = *local_addr,
        .remote_addr = *remote_addr,
    };

    osw_sta_cqm_assoc_link_t *link = ds_tree_find(&m->links, &id);
    return link;
}

static time_t osw_sta_cqm_assoc_link_log_valid_until(const osw_sta_cqm_assoc_link_log_entry_t *log)
{
    if (log == NULL) return 0;
    return log->timestamp + log->duration_sec;
}

static bool osw_sta_cqm_assoc_link_log_entry_is_at_risk_of_overflow(const osw_sta_cqm_assoc_link_log_entry_t *log)
{
    if (log == NULL) return false;

    /* This is trying to avoid overflowing by making sure
     * the constituent values are not too large before
     * it's too late.
     */
    const uint32_t u32_limit = UINT32_MAX / 2;

    if (log->tx_pkts >= u32_limit || log->rx_pkts >= u32_limit || log->duration_sec >= u32_limit)
    {
        return true;
    }

    return false;
}

static bool osw_sta_cqm_assoc_mbps_too_different(uint32_t a_mbps, uint32_t a_pkts, uint32_t b_mbps, uint32_t b_pkts)
{
    if (a_mbps == 0 || b_mbps == 0) return false;
    if (a_pkts == 0 || b_pkts == 0) return false;

    const uint32_t diff = ABS_DIFF(a_mbps, b_mbps);
    const uint32_t avg = (a_mbps + b_mbps) / 2;
    const uint32_t diff_percent = (diff * 100) / avg;

    return diff_percent > OSW_STA_CQM_LOG_MERGE_PERCENT_DIFF;
}

static bool osw_sta_cqm_assoc_link_log_entry_tx_mbps_too_different(
        const osw_sta_cqm_assoc_link_log_entry_t *a,
        const osw_sta_cqm_assoc_link_log_entry_t *b)
{
    if (a == NULL || b == NULL) return false;

    return osw_sta_cqm_assoc_mbps_too_different(a->tx_avg_phyrate_mbps, a->tx_pkts, b->tx_avg_phyrate_mbps, b->tx_pkts);
}

static bool osw_sta_cqm_assoc_link_log_entry_rx_mbps_too_different(
        const osw_sta_cqm_assoc_link_log_entry_t *a,
        const osw_sta_cqm_assoc_link_log_entry_t *b)
{
    if (a == NULL || b == NULL) return false;

    return osw_sta_cqm_assoc_mbps_too_different(a->rx_avg_phyrate_mbps, a->rx_pkts, b->rx_avg_phyrate_mbps, b->rx_pkts);
}

static bool osw_sta_cqm_assoc_psr_too_different(uint8_t a_psr, uint32_t a_pkts, uint8_t b_psr, uint32_t b_pkts)
{
    if (a_psr == 0 || b_psr == 0) return false;
    if (a_pkts == 0 || b_pkts == 0) return false;

    const uint8_t diff = ABS_DIFF(a_psr, b_psr);
    const uint8_t avg = (a_psr + b_psr) / 2;
    const uint8_t diff_percent = (diff * 100) / avg;

    return (diff_percent > OSW_STA_CQM_LOG_MERGE_PERCENT_DIFF);
}

static bool osw_sta_cqm_assoc_link_log_entry_tx_psr_too_different(
        const osw_sta_cqm_assoc_link_log_entry_t *a,
        const osw_sta_cqm_assoc_link_log_entry_t *b)
{
    if (a == NULL || b == NULL) return false;

    return osw_sta_cqm_assoc_psr_too_different(a->tx_psr_percent, a->tx_pkts, b->tx_psr_percent, b->tx_pkts);
}

static bool osw_sta_cqm_assoc_link_log_entry_rx_psr_too_different(
        const osw_sta_cqm_assoc_link_log_entry_t *a,
        const osw_sta_cqm_assoc_link_log_entry_t *b)
{
    if (a == NULL || b == NULL) return false;

    return osw_sta_cqm_assoc_psr_too_different(a->rx_psr_percent, a->rx_pkts, b->rx_psr_percent, b->rx_pkts);
}

static bool osw_sta_cqm_assoc_link_log_entry_snr_too_different(
        const osw_sta_cqm_assoc_link_log_entry_t *a,
        const osw_sta_cqm_assoc_link_log_entry_t *b)
{
    if (a == NULL || b == NULL) return false;

    if (a->rx_pkts == 0 || b->rx_pkts == 0) return false;

    const uint8_t a_snr = a->rx_snr;
    const uint8_t b_snr = b->rx_snr;
    const uint8_t snr_diff = ABS_DIFF(a_snr, b_snr);

    return (snr_diff > OSW_STA_CQM_LOG_MERGE_DB_DIFF);
}

static bool osw_sta_cqm_assoc_link_log_entry_troubled_is_different(
        const osw_sta_cqm_assoc_link_log_entry_t *older,
        const osw_sta_cqm_assoc_link_log_entry_t *newer)
{
    if (older == NULL || newer == NULL) return false;

    const uint8_t older_troubled_mask = osw_sta_cqm_assoc_link_log_entry_get_troubled_reason_mask(older);
    const uint8_t newer_troubled_mask = osw_sta_cqm_assoc_link_log_entry_get_troubled_reason_mask(newer);
    return (older_troubled_mask != newer_troubled_mask);
}

static enum osw_sta_cqm_assoc_link_log_entry_merge_result osw_sta_cqm_assoc_link_log_can_be_merged(
        const osw_sta_cqm_assoc_link_log_entry_t *older,
        const osw_sta_cqm_assoc_link_log_entry_t *newer)
{
    if (older == NULL) return OSW_STA_CQM_ASSOC_LINK_LOG_ENTRY_MERGE_RESULT_OLDER_IS_NULL;
    if (newer == NULL) return OSW_STA_CQM_ASSOC_LINK_LOG_ENTRY_MERGE_RESULT_NEWER_IS_NULL;
    if (older->link != newer->link) return OSW_STA_CQM_ASSOC_LINK_LOG_ENTRY_MERGE_RESULT_WRONG_LINK;
    if (osw_sta_cqm_assoc_link_log_entry_is_at_risk_of_overflow(older))
        return OSW_STA_CQM_ASSOC_LINK_LOG_ENTRY_MERGE_RESULT_OVERFLOW_RISK_OLDER;
    if (osw_sta_cqm_assoc_link_log_entry_is_at_risk_of_overflow(newer))
        return OSW_STA_CQM_ASSOC_LINK_LOG_ENTRY_MERGE_RESULT_OVERFLOW_RISK_NEWER;
    if (osw_sta_cqm_assoc_link_log_entry_tx_mbps_too_different(older, newer))
        return OSW_STA_CQM_ASSOC_LINK_LOG_ENTRY_MERGE_RESULT_TX_MBPS_TOO_DIFFERENT;
    if (osw_sta_cqm_assoc_link_log_entry_rx_mbps_too_different(older, newer))
        return OSW_STA_CQM_ASSOC_LINK_LOG_ENTRY_MERGE_RESULT_RX_MBPS_TOO_DIFFERENT;
    if (osw_sta_cqm_assoc_link_log_entry_tx_psr_too_different(older, newer))
        return OSW_STA_CQM_ASSOC_LINK_LOG_ENTRY_MERGE_RESULT_TX_PSR_TOO_DIFFERENT;
    if (osw_sta_cqm_assoc_link_log_entry_rx_psr_too_different(older, newer))
        return OSW_STA_CQM_ASSOC_LINK_LOG_ENTRY_MERGE_RESULT_RX_PSR_TOO_DIFFERENT;
    if (osw_sta_cqm_assoc_link_log_entry_snr_too_different(older, newer))
        return OSW_STA_CQM_ASSOC_LINK_LOG_ENTRY_MERGE_RESULT_SNR_TOO_DIFFERENT;
    if (osw_sta_cqm_assoc_link_log_entry_troubled_is_different(older, newer))
        return OSW_STA_CQM_ASSOC_LINK_LOG_ENTRY_MERGE_RESULT_TROUBLED_REASON_MASK_DIFFERENT;
    return OSW_STA_CQM_ASSOC_LINK_LOG_ENTRY_MERGE_RESULT_OK;
}

static uint8_t osw_sta_cqm_weighted_average_u8(uint8_t a, uint32_t a_weight, uint8_t b, uint32_t b_weight)
{
    const uint32_t sum = a_weight + b_weight;
    if (sum == 0) return 0;
    const uint32_t weighted = (a * a_weight) + (b * b_weight);
    return (uint8_t)(weighted / sum);
}

static uint32_t osw_sta_cqm_weighted_average_u32(uint32_t a, uint32_t a_weight, uint32_t b, uint32_t b_weight)
{
    const uint32_t sum = a_weight + b_weight;
    if (sum == 0) return 0;
    const uint64_t weighted = ((uint64_t)a * a_weight) + ((uint64_t)b * b_weight);
    return (uint32_t)(weighted / sum);
}

static uint8_t osw_sta_cqm_merge_percent(
        uint8_t older_percent,
        uint32_t older_pkts,
        uint8_t newer_percent,
        uint32_t newer_pkts)
{
    if (older_pkts == 0 && newer_pkts == 0) return 100;
    if (older_pkts == 0) return newer_percent;
    if (newer_pkts == 0) return older_percent;
    return osw_sta_cqm_weighted_average_u8(older_percent, older_pkts, newer_percent, newer_pkts);
}

static uint32_t osw_sta_cqm_merge_rate(
        uint32_t older_rate,
        uint32_t older_pkts,
        uint32_t newer_rate,
        uint32_t newer_pkts)
{
    if (older_pkts == 0 && newer_pkts == 0) return 0;
    if (older_pkts == 0) return newer_rate;
    if (newer_pkts == 0) return older_rate;
    return osw_sta_cqm_weighted_average_u32(older_rate, older_pkts, newer_rate, newer_pkts);
}

static void osw_sta_cqm_assoc_link_log_entry_merge(
        osw_sta_cqm_assoc_link_log_entry_t *older,
        const osw_sta_cqm_assoc_link_log_entry_t *newer)
{
    if (older == NULL || newer == NULL) return;

    const time_t newer_starts_on = newer->timestamp;
    const time_t older_ends_on = older->timestamp + older->duration_sec;
    const uint32_t gap = newer_starts_on - older_ends_on;
    const uint32_t newer_duration_sec = newer->duration_sec + gap;
    const uint32_t total_duration_sec = older->duration_sec + newer_duration_sec;
    if (total_duration_sec == 0) return;

    older->rx_snr =
            osw_sta_cqm_weighted_average_u8(older->rx_snr, older->duration_sec, newer->rx_snr, newer_duration_sec);

    older->tx_psr_percent =
            osw_sta_cqm_merge_percent(older->tx_psr_percent, older->tx_pkts, newer->tx_psr_percent, newer->tx_pkts);

    older->rx_psr_percent =
            osw_sta_cqm_merge_percent(older->rx_psr_percent, older->rx_pkts, newer->rx_psr_percent, newer->rx_pkts);

    older->tx_avg_phyrate_mbps = osw_sta_cqm_merge_rate(
            older->tx_avg_phyrate_mbps,
            older->tx_pkts,
            newer->tx_avg_phyrate_mbps,
            newer->tx_pkts);

    older->rx_avg_phyrate_mbps = osw_sta_cqm_merge_rate(
            older->rx_avg_phyrate_mbps,
            older->rx_pkts,
            newer->rx_avg_phyrate_mbps,
            newer->rx_pkts);

    older->displayed = false;
    older->duration_sec = total_duration_sec;
    older->activity_sec += newer->activity_sec;
    older->tx_pkts += newer->tx_pkts;
    older->rx_pkts += newer->rx_pkts;
}

/* Try to merge two log entries if they are compatible. If
 * they can be merged, the older entry is updated and the
 * newer one is dropped.
 *
 * This optimizes memory usage by avoiding duplicate log
 * entries. This may drift the log entries slightly, but it
 * is not expected to cause any issues in practice.
 */
static void osw_sta_cqm_assoc_link_log_entry_try_merge(
        osw_sta_cqm_assoc_link_log_entry_t *older,
        osw_sta_cqm_assoc_link_log_entry_t *newer)
{
    if (older == NULL || newer == NULL) return;

    const enum osw_sta_cqm_assoc_link_log_entry_merge_result res =
            osw_sta_cqm_assoc_link_log_can_be_merged(older, newer);
    if (res != OSW_STA_CQM_ASSOC_LINK_LOG_ENTRY_MERGE_RESULT_OK) return;

    osw_sta_cqm_assoc_link_log_entry_merge(older, newer);
    osw_sta_cqm_assoc_link_log_entry_drop(newer);
}

static void osw_sta_cqm_assoc_disconnect(osw_sta_cqm_assoc_t *assoc)
{
    if (assoc == NULL) return;

    LOGD(LOG_PREFIX_ASSOC(assoc, "disconnecting"));

    /* Stats are reported independently of the
     * association, so we need to ensure that the
     * association is dropped after a while. This way the
     * last-breath stats are still reported.
     */
    const uint64_t at = osw_time_mono_clk() + OSW_TIME_SEC(OSW_STA_CQM_DESTROY_SECONDS);
    osw_timer_arm_at_nsec(&assoc->destroy_timer, at);
}

static void osw_sta_cqm_assoc_link_log_truncate(osw_sta_cqm_assoc_link_t *link)
{
    if (link == NULL) return;

    const time_t now = time_real();
    osw_sta_cqm_assoc_link_log_entry_t *log;
    osw_sta_cqm_assoc_link_log_entry_t *tmp;
    ds_dlist_foreach_safe (&link->logs, log, tmp)
    {
        /* The intention of this exception to the rule is
         * meant to allow the next log to come to be
         * possibly merged into this (old) entry if they are
         * mergable. This provides the opportunity to
         * keep track of long running links that don't
         * change much over time. Providing more insight
         * into cases like: "device was idle for hours, and
         * then dropped off the network".
         */
        const bool only_one_log = (ds_dlist_len(&link->logs) == 1);
        if (only_one_log) break;

        const uint64_t valid_until = osw_sta_cqm_assoc_link_log_valid_until(log);
        const uint64_t invalid_before = now - OSW_STA_CQM_LOG_MAX_AGE_SECONDS;
        if (valid_until < invalid_before)
        {
            osw_sta_cqm_assoc_link_log_entry_drop(log);
        }
    }
}

static void osw_sta_cqm_assoc_cb(void *priv, const osw_sta_assoc_entry_t *e, const osw_sta_assoc_event_e ev)
{
    osw_sta_cqm_t *m = priv;
    const struct osw_hwaddr *assoc_addr = osw_sta_assoc_entry_get_addr(e);
    osw_sta_cqm_assoc_t *assoc = ds_tree_find(&m->assocs, assoc_addr);
    switch (ev)
    {
        case OSW_STA_ASSOC_UNDEFINED:
            /* eg. IEs changed - irrelevant for now */
            break;
        case OSW_STA_ASSOC_CONNECTED:
            if (assoc != NULL)
            {
                LOGW(LOG_PREFIX_ASSOC(assoc, "already exists, dropping now"));
                osw_sta_cqm_assoc_display(assoc, "overlap connected");
                osw_sta_cqm_assoc_drop(assoc);
            }
            osw_sta_cqm_assoc_alloc(m, e);
            break;
        case OSW_STA_ASSOC_RECONNECTED:
            osw_sta_cqm_assoc_display(assoc, "overlap reconnected");
            osw_sta_cqm_assoc_drop(assoc);
            osw_sta_cqm_assoc_alloc(m, e);
            break;
        case OSW_STA_ASSOC_DISCONNECTED:
            osw_sta_cqm_assoc_display(assoc, "disconnected");
            osw_sta_cqm_assoc_disconnect(assoc);
            break;
    }
}

static void osw_sta_cqm_stats_report_cb(
        const enum osw_stats_id stats_id,
        const struct osw_tlv *delta,
        const struct osw_tlv *last,
        void *priv)
{
    /* Stats reporting callback: called periodically by the stats subsystem.
     * Parses TLV data, updates per-link logs, and triggers display/merge/truncate logic.
     */
    osw_sta_cqm_t *m = priv;

    if (stats_id != OSW_STATS_STA) return;

    const struct osw_stats_defs *defs = osw_stats_defs_lookup(stats_id);
    const size_t tb_size = defs->size;
    const struct osw_tlv_policy *policy = defs->tpolicy;

    const struct osw_tlv_hdr *tb[tb_size];
    memset(tb, 0, tb_size * sizeof(tb[0]));

    const size_t left = osw_tlv_parse(delta->data, delta->used, policy, tb, tb_size);
    WARN_ON(left != 0);

    const struct osw_tlv_hdr *mac = tb[OSW_STATS_STA_MAC_ADDRESS];
    const struct osw_tlv_hdr *bss = tb[OSW_STATS_STA_VIF_ADDRESS];
    const struct osw_tlv_hdr *snr = tb[OSW_STATS_STA_SNR_DB];
    const struct osw_tlv_hdr *tx_mpdu = tb[OSW_STATS_STA_TX_FRAMES];
    const struct osw_tlv_hdr *rx_mpdu = tb[OSW_STATS_STA_RX_FRAMES];
    const struct osw_tlv_hdr *tx_retries = tb[OSW_STATS_STA_TX_RETRIES];
    const struct osw_tlv_hdr *rx_retries = tb[OSW_STATS_STA_RX_RETRIES];
    const struct osw_tlv_hdr *tx_rate = tb[OSW_STATS_STA_TX_RATE_MBPS];
    const struct osw_tlv_hdr *rx_rate = tb[OSW_STATS_STA_RX_RATE_MBPS];

    if (mac == NULL) return;
    if (bss == NULL) return;

    struct osw_hwaddr remote_addr;
    struct osw_hwaddr local_addr;
    osw_tlv_get_hwaddr(&remote_addr, mac);
    osw_tlv_get_hwaddr(&local_addr, bss);

    const uint32_t snr_db = snr ? osw_tlv_get_u32(snr) : 0;
    const uint32_t tx_mpdus = (tx_mpdu ? osw_tlv_get_u32(tx_mpdu) : 0);
    const uint32_t rx_mpdus = rx_mpdu ? osw_tlv_get_u32(rx_mpdu) : 0;
    const uint32_t tx_attempts = (tx_retries ? osw_tlv_get_u32(tx_retries) : 0) + tx_mpdus;
    const uint32_t rx_attempts = (rx_retries ? osw_tlv_get_u32(rx_retries) : 0) + rx_mpdus;
    const uint32_t tx_psr = tx_attempts > 0 ? (100 * tx_mpdus / tx_attempts) : 100;
    const uint32_t rx_psr = rx_attempts > 0 ? (100 * rx_mpdus / rx_attempts) : 100;
    const uint32_t tx_mbps = tx_rate ? osw_tlv_get_u32(tx_rate) : 0;
    const uint32_t rx_mbps = rx_rate ? osw_tlv_get_u32(rx_rate) : 0;

    const bool bad_tx_report = (tx_mpdus > 0 && tx_psr == 100 && tx_mbps == 0);
    const bool bad_rx_report = (rx_mpdus > 0 && rx_psr == 100 && rx_mbps == 0);
    const bool bad_report = bad_tx_report || bad_rx_report;
    if (bad_report) return;

    osw_sta_cqm_assoc_link_t *link = osw_sta_cqm_assoc_link_lookup(m, &local_addr, &remote_addr);
    if (link == NULL) return;

    if (tx_mpdus == 0 && rx_mpdus == 0) return;

    osw_sta_cqm_assoc_link_log_entry_t *log = CALLOC(1, sizeof(*log));
    if (log == NULL) return;

    log->link = link;
    log->timestamp = time_real() - OSW_STA_CQM_STATS_REPORT_SECONDS;
    log->duration_sec = OSW_STA_CQM_STATS_REPORT_SECONDS;
    log->activity_sec = OSW_STA_CQM_STATS_REPORT_SECONDS;
    log->rx_snr = snr_db;
    log->tx_pkts = tx_mpdus;
    log->rx_pkts = rx_mpdus;
    log->tx_psr_percent = (uint8_t)tx_psr;
    log->rx_psr_percent = (uint8_t)rx_psr;
    log->tx_avg_phyrate_mbps = tx_mbps;
    log->rx_avg_phyrate_mbps = rx_mbps;
    ds_dlist_insert_tail(&link->logs, log);

    const uint8_t old_troubled_reason_mask = link->troubled_mask;
    const uint8_t new_troubled_reason_mask = osw_sta_cqm_assoc_link_log_entry_get_troubled_reason_mask(log);
    const bool first_log = (ds_dlist_len(&link->logs) == 1);
    const bool troubled_reason_mask_changed = new_troubled_reason_mask != old_troubled_reason_mask;

    link->troubled_mask = new_troubled_reason_mask;

    if (first_log)
    {
        LOGI(LOG_PREFIX_LINK_LOG_ENTRY(log, "first log"));
    }
    else if (troubled_reason_mask_changed)
    {
        LOGI(LOG_PREFIX_LINK(
                log->link,
                "troubled changed: from=" TROUBLED_REASON_MASK_FMT " to=" TROUBLED_REASON_MASK_FMT,
                TROUBLED_REASON_MASK_ARG(old_troubled_reason_mask),
                TROUBLED_REASON_MASK_ARG(new_troubled_reason_mask)));
        osw_sta_cqm_assoc_display(link->assoc, "troubled changed");
    }

    osw_sta_cqm_assoc_link_log_entry_t *log_before_log = ds_dlist_prev(&link->logs, log);
    osw_sta_cqm_assoc_link_log_entry_try_merge(log_before_log, log);
    osw_sta_cqm_assoc_link_log_truncate(link);
}

static size_t osw_sta_cqm_compute_memory_size(osw_sta_cqm_t *m)
{
    if (m == NULL) return 0;

    size_t size = sizeof(*m);
    size += ds_tree_len(&m->assocs) * sizeof(osw_sta_cqm_assoc_t);
    size += ds_tree_len(&m->links) * sizeof(osw_sta_cqm_assoc_link_t);

    osw_sta_cqm_assoc_link_t *link;
    ds_tree_foreach (&m->links, link)
    {
        if (link != NULL)
        {
            size += strlen(link->vif_name) + 1; /* +1 for the null terminator */
        }
    }

    /* This doesn't account for the stats_sub and assoc_obs.
     * They don't have a way to get their true memory size
     * now. This is fine for now. That's O(1) from this
     * module's point of view. It's more important to
     * account for the O(n) nature of the associations and
     * links.
     */

    return size;
}

static void osw_sta_cqm_sigusr1_cb(struct ev_loop *loop, ev_signal *w, int revents)
{
    osw_sta_cqm_t *m = w->data;

    osw_diag_pipe_t *pipe = osw_diag_pipe_open();
    if (pipe == NULL) return;

    osw_diag_pipe_writef(pipe, LOG_PREFIX("memory size: %zu bytes"), osw_sta_cqm_compute_memory_size(m));
    osw_sta_cqm_assoc_t *assoc;
    ds_tree_foreach (&m->assocs, assoc)
    {
        osw_diag_pipe_writef(pipe, LOG_PREFIX_ASSOC(assoc, "links:"));
        osw_sta_cqm_assoc_link_t *link;
        ds_tree_foreach (&assoc->links, link)
        {
            osw_diag_pipe_writef(pipe, LOG_PREFIX_LINK(link, "logs:"));
            osw_sta_cqm_assoc_link_log_entry_t *log;
            ds_dlist_foreach (&link->logs, log)
            {
                osw_diag_pipe_writef(pipe, LOG_PREFIX_LINK_LOG_ENTRY(log, "dump"));
                osw_sta_cqm_assoc_link_log_entry_t *next = ds_dlist_next(&link->logs, log);
                const int time_gap = osw_sta_cqm_assoc_link_log_entry_get_time_gap_between(log, next);
                if (time_gap > 0)
                {
                    osw_diag_pipe_writef(pipe, LOG_PREFIX_LINK(link, "next log entry starts in %d seconds", time_gap));
                }
            }
        }
    }
    osw_diag_pipe_close(pipe);
}

static void osw_sta_cqm_init(osw_sta_cqm_t *m)
{
    if (m == NULL) return;

    ds_tree_init(&m->assocs, (ds_key_cmp_t *)osw_hwaddr_cmp, osw_sta_cqm_assoc_t, node);
    ds_tree_init(&m->links, osw_sta_cqm_assoc_link_id_cmp, osw_sta_cqm_assoc_link_t, node_m);
    ev_signal_init(&m->sigusr1, osw_sta_cqm_sigusr1_cb, SIGUSR1);
    m->sigusr1.data = m;
}

static void osw_sta_cqm_attach(osw_sta_cqm_t *m)
{
    if (m == NULL) return;

    OSW_MODULE_LOAD(osw_stats);
    m->stats_sub = osw_stats_subscriber_alloc();
    osw_stats_subscriber_set_sta(m->stats_sub, true);
    osw_stats_subscriber_set_report_fn(m->stats_sub, osw_sta_cqm_stats_report_cb, m);
    osw_stats_subscriber_set_report_seconds(m->stats_sub, OSW_STA_CQM_STATS_REPORT_SECONDS);
    osw_stats_subscriber_set_poll_seconds(m->stats_sub, OSW_STA_CQM_STATS_POLL_SECONDS);
    osw_stats_register_subscriber(m->stats_sub);

    osw_sta_assoc_t *assoc = OSW_MODULE_LOAD(osw_sta_assoc);
    osw_sta_assoc_observer_params_t *params = osw_sta_assoc_observer_params_alloc();
    osw_sta_assoc_observer_params_set_changed_fn(params, osw_sta_cqm_assoc_cb, m);
    osw_sta_assoc_observer_params_set_addr(params, NULL);
    m->assoc_obs = osw_sta_assoc_observer_alloc(assoc, params);

    ev_signal_start(EV_DEFAULT_ & m->sigusr1);
    ev_unref(EV_DEFAULT);
}

OSW_MODULE(osw_sta_cqm)
{
    static osw_sta_cqm_t m;
    osw_sta_cqm_init(&m);
    osw_sta_cqm_attach(&m);
    return &m;
}
