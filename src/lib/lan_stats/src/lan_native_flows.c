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

#include <sys/socket.h>
#include <netdb.h>
#include <time.h>

#include "lan_stats.h"
#include "nf_utils.h"
#include "memutil.h"
#include "neigh_table.h"
#include "log.h"
#include "os_random.h"
#include "fcm_report_filter.h"


static bool
lan_stats_apply_filter(struct net_md_stats_accumulator *acc)
{
    lan_stats_instance_t *lan_stats_instance;
    fcm_collect_plugin_t *collector;
    struct net_md_flow_key *key;
    struct flow_key *fkey;
    char *device_tag;
    bool is_eth_dev;
    bool rc;

    lan_stats_instance = lan_stats_get_active_instance();
    if (lan_stats_instance == NULL)
    {
        LOGD("%s: No active instance found", __func__);
        return false;
    }

    collector = lan_stats_instance->collector;

    fcm_filter_context_init(collector);

    /* check if it is ethernet traffic */
    device_tag = (lan_stats_instance->parent_tag != NULL) ?
                  lan_stats_instance->parent_tag : ETH_DEVICES_TAG;

    key = acc->key;
    fkey = acc->fkey;

    /* Check if the device is an ethernet device */
    is_eth_dev = (lan_stats_is_mac_in_tag(device_tag, key->smac) ||
                  lan_stats_is_mac_in_tag(device_tag, key->dmac));

    if (!is_eth_dev) return false;

    if (key) key->isparent_of_smac = lan_stats_is_mac_in_tag(device_tag, key->smac);
    if (key) key->isparent_of_dmac = lan_stats_is_mac_in_tag(device_tag, key->dmac);
    if (fkey) fkey->isparent_of_smac = key->isparent_of_smac;
    if (fkey) fkey->isparent_of_dmac = key->isparent_of_dmac;

    rc = fcm_collect_filter_nmd_callback(key);
    LOGT("%s: flow %s", __func__, rc ? "included" : "filtered out");

    return rc;
}


void lan_stats_process_flows(ds_tree_t *tree)
{
    struct net_md_flow *flow;

    flow = ds_tree_head(tree);
    while (flow != NULL)
    {
        struct net_md_stats_accumulator *acc;
        struct net_md_flow *next;
        bool select;

        next = ds_tree_next(tree, flow);
        acc = flow->tuple_stats;

        select = lan_stats_apply_filter(acc);
        if (!select)
        {
            ds_tree_remove(tree, flow);
            net_md_free_flow(flow);
            FREE(flow);
        }

        flow = next;
    }
}

static void
lan_stats_process_eth_acc(struct net_md_eth_pair *eth_pair)
{
    struct net_md_stats_accumulator *eth_acc;
    lan_stats_instance_t *lan_stats_instance;
    struct net_md_flow_key *key;
    struct flow_key *fkey;
    char *device_tag;

    if (eth_pair == NULL || eth_pair->mac_stats == NULL) return;

    lan_stats_instance = lan_stats_get_active_instance();
    if (lan_stats_instance == NULL)
    {
        LOGD("%s: No active instance found", __func__);
        return;
    }
    eth_acc = eth_pair->mac_stats;

    device_tag = (lan_stats_instance->parent_tag != NULL) ?
                  lan_stats_instance->parent_tag : ETH_DEVICES_TAG;

    key = eth_acc->key;
    fkey = eth_acc->fkey;

    key->isparent_of_smac = lan_stats_is_mac_in_tag(device_tag, key->smac);
    key->isparent_of_dmac = lan_stats_is_mac_in_tag(device_tag, key->dmac);
    fkey->isparent_of_smac = key->isparent_of_smac;
    fkey->isparent_of_dmac = key->isparent_of_dmac;
}

void lan_stats_process_aggr(struct net_md_aggregator *to, struct net_md_aggregator *from)
{
    struct net_md_eth_pair *eth_pair;
    u_int64_t eth_pairs_count;

    if (from == NULL || to == NULL) return;
    eth_pairs_count = 0;

    to->total_flows = from->total_flows;
    to->total_eth_pairs = from->total_eth_pairs;
    to->eth_pairs = from->eth_pairs;
    to->five_tuple_flows = from->five_tuple_flows;
    to->active_accs = from->active_accs;

    net_md_log_aggr(to);

    /* Process eth_pairs in the aggregator */
    eth_pair = ds_tree_head(to->eth_pairs);
    while (eth_pair != NULL)
    {
        eth_pairs_count += 1;
        /* Process ethernet flows */
        lan_stats_process_eth_acc(eth_pair);

        eth_pair = ds_tree_next(to->eth_pairs, eth_pair);
    }
    LOGN("%s: processed %llu eth pairs",
         __func__, (unsigned long long)eth_pairs_count);
}
