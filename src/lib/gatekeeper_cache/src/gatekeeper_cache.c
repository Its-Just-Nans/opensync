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

#include <stdint.h>
#include <time.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "gatekeeper_cache.h"
#include "log.h"
#include "os_types.h"
#include "memutil.h"
#include "os.h"

static struct gk_cache_mgr mgr = {
    .initialized = false,
};

size_t GK_MAX_CACHE_ENTRIES = 100000;

struct gk_cache_mgr *
gk_cache_get_mgr(void)
{
    return &mgr;
}

/**
 * @brief setter for the number of entries in the cache
 *        (only if the cache is not yet being used)
 *
 * @param n maximum number of records in the cache.
 */
void
gk_cache_set_size(size_t n)
{
    size_t current_usage;

    current_usage = gk_get_cache_count();
    if (current_usage == 0)
    {
        GK_MAX_CACHE_ENTRIES = n;
    }
    else
    {
        LOGD("%s(): Cache already in use. Will not change its size to %zu", __func__, n);
    }
}

/**
 * @brief getter for the number of entries in the cache
 *
 * @return max number of records allowed in the cache.
 */
size_t
gk_cache_get_size(void)
{
    return GK_MAX_CACHE_ENTRIES;
}

/**
 * @brief comparator function for comparing mac adress
 *
 * @params: _a: first MAC address to compare
 * @params: _b: second MAC address to compare
 *
 * @return 0 if identical, positive or negative value if different
 *         (implying the "order" between the entries)
 */
static int
gkc_mac_addr_cmp(const void *_a, const void *_b)
{
    const os_macaddr_t *a = _a;
    const os_macaddr_t *b = _b;

    return memcmp(a->addr, b->addr, sizeof(a->addr));
}

/**
 * @brief comparator function for attribute synthetic keys
 *
 * @param _a uint64_t representing a key
 * @param _b uint64_t representing a key
 *
 * @return 0 if identical, positive or negative value if different
 *         (implying the "order" between the entries)
 */
static int
gkc_uint64_cmp(const void *_a, const void *_b)
{
    const uint64_t *a = (const uint64_t *)_a;
    const uint64_t *b = (const uint64_t *)_b;

    if (*a < *b) return -1;
    if (*a > *b) return 1;
    return 0;
}

/* Fast hashing function. */
static uint64_t
MurmurOAAT64(uint8_t dir, uint8_t *data, size_t len)
{
    uint64_t h = 0x749E3E6989DF617;
    size_t i;

    h ^= dir;
    h *= 0x5bd1e9955bd1e995;
    h ^= h >> 47;

    for (i = 0; i < len; i++)
    {
        h ^= data[i];
        h *= 0x5bd1e9955bd1e995;
        h ^= h >> 47;
    }

    return h;
}

/*
 * Using 'direction' as part of the key for the cache entry
 * leads to some cache misses.
 * The 'direction' is now only considered for IPv4 and IPv6,
 * and set to GKC_FLOW_DIRECTION_INTERNAL_IGNORE for other
 * requests (FQDN, URL, SNI and APP)
 */
uint64_t
get_attr_key(struct gk_attr_cache_interface *req)
{
    struct sockaddr_in6 *in6;
    struct sockaddr_in *in4;
    size_t data_len;
    uint8_t *data;
    uint64_t ret;
    uint8_t dir;

    if (!req->attr_name && !req->ip_addr) return 0;

    data = (uint8_t *)req->attr_name;
    if (req->attr_name)
        data_len = strlen(req->attr_name);
    else
        data_len = 0;

    dir = GKC_FLOW_DIRECTION_INTERNAL_IGNORE;

    switch (req->attribute_type)
    {
        case GK_CACHE_REQ_TYPE_IPV4:
            if (req->ip_addr)
            {
                /* Make sure to point the IPv4 address itself */
                in4 = (struct sockaddr_in *)req->ip_addr;
                data = (uint8_t *)&in4->sin_addr;
                data_len = 4;
                dir = req->direction;
            }
            break;
        case GK_CACHE_REQ_TYPE_IPV6:
            if (req->ip_addr)
            {
                /* Make sure to point the IPv6 address itself */
                in6 = (struct sockaddr_in6 *)req->ip_addr;
                data = (uint8_t *)&in6->sin6_addr;
                data_len = 16;
                dir = req->direction;
            }
            break;
        case GK_CACHE_REQ_TYPE_INBOUND:
        case GK_CACHE_REQ_TYPE_OUTBOUND:
            dir = req->direction;
        default:
            ; /* Nothing to be done */
    }

    if (data_len == 0) return 0;

    ret = MurmurOAAT64(dir, data, data_len);

    return ret;
}

/**
 * @brief comparator function for 5-tuple
 *
 * @params: _a: first 5-tuple structure to compare
 * @params: _b: second 5-tuple structure to compare
 *
 * @return 0 if identical, positive or negative value if different
 *         (implying the "order" between the entries)
 */
int
gkc_flow_entry_cmp(const void *_a, const void *_b)
{
    const struct ip_flow_cache *key_a = _a;
    const struct ip_flow_cache *key_b = _b;
    int ipl;
    int cmp;

    /* Compare IP address length */
    cmp = (int)(key_a->ip_version) - (int)(key_b->ip_version);
    if (cmp != 0) return cmp;

    /* Get ip version comparison len. Default with the shortest. */
    ipl = (key_a->ip_version == 6 ? 16 : 4);

    /* Compare source IP addresses */
    cmp = memcmp(key_a->src_ip_addr, key_b->src_ip_addr, ipl);
    if (cmp != 0) return cmp;

    /* Compare destination IP addresses */
    cmp = memcmp(key_a->dst_ip_addr, key_b->dst_ip_addr, ipl);
    if (cmp != 0) return cmp;

    /* Compare ip protocols */
    cmp = (int)(key_a->protocol) - (int)(key_b->protocol);
    if (cmp != 0) return cmp;

    /* Compare source ports */
    cmp = (int)(key_a->src_port) - (int)(key_b->src_port);
    if (cmp != 0) return cmp;

    /* Compare destination ports */
    cmp = (int)(key_a->dst_port) - (int)(key_b->dst_port);
    return cmp;
}

/**
 * @brief initialize per device structure.
 *        Initializes the attributes and flow trees.
 *
 * @params: device_mac: device mac address
 *
 * @return pointer to per_device_cache on success
 *         NULL on failure
 */
static struct per_device_cache *
gkc_init_per_dev(os_macaddr_t *device_mac)
{
    struct per_device_cache *pdevice_cache;

    if (!device_mac) return NULL;

    /* initialize per device structure */
    pdevice_cache = CALLOC(1, sizeof(*pdevice_cache));
    if (pdevice_cache == NULL) return NULL;

    pdevice_cache->device_mac = CALLOC(1, sizeof(*pdevice_cache->device_mac));
    if (pdevice_cache->device_mac == NULL) goto error;

    memcpy(pdevice_cache->device_mac, device_mac, sizeof(*pdevice_cache->device_mac));

    ds_tree_init(&pdevice_cache->hostname_tree, gkc_uint64_cmp, struct attr_cache, attr_tnode);
    ds_tree_init(&pdevice_cache->url_tree, gkc_uint64_cmp, struct attr_cache, attr_tnode);
    ds_tree_init(&pdevice_cache->ipv4_tree, gkc_uint64_cmp, struct attr_cache, attr_tnode);
    ds_tree_init(&pdevice_cache->ipv6_tree, gkc_uint64_cmp, struct attr_cache, attr_tnode);
    ds_tree_init(&pdevice_cache->app_tree, gkc_uint64_cmp, struct attr_cache, attr_tnode);
    ds_tree_init(&pdevice_cache->outbound_tree, gkc_flow_entry_cmp, struct ip_flow_cache, ipflow_tnode);
    ds_tree_init(&pdevice_cache->inbound_tree, gkc_flow_entry_cmp, struct ip_flow_cache, ipflow_tnode);

    return pdevice_cache;

error:
    FREE(pdevice_cache);
    return NULL;
}

/**
 * @brief initialize gk_cache manager.
 */
void
gk_cache_init_mgr(struct gk_cache_mgr *mgr)
{
    if (!mgr) return;
    if (mgr->initialized) return;

    /* initialize per device tree */
    ds_tree_init(&mgr->per_device_tree, gkc_mac_addr_cmp, struct per_device_cache, perdevice_tnode);

    mgr->initialized = true;
}

/**
 * @brief adds redirect entry details to cache
 *
 * @params: input: contains redirect entries to be added
 *
 * @params: new_entry pointer to cache entry
 */
void
gk_add_new_redirect_entry(struct gk_attr_cache_interface *input, struct attr_cache *new_entry)
{
    struct fqdn_redirect_s *new_redirect;
    struct fqdn_redirect_s *in_redirect;

    if (input->fqdn_redirect == NULL) return;
    in_redirect = input->fqdn_redirect;

    new_entry->fqdn_redirect = CALLOC(1, sizeof(*new_redirect));
    if (new_entry->fqdn_redirect == NULL) return;

    new_redirect = new_entry->fqdn_redirect;

    /* return if redirection is not required */
    if (in_redirect->redirect == false) return;

    new_redirect->redirect = in_redirect->redirect;
    new_redirect->redirect_ttl = in_redirect->redirect_ttl;

    if (in_redirect->redirect_cname != NULL)
    {
        new_redirect->redirect_cname = STRDUP(in_redirect->redirect_cname);
    }
    STRSCPY(new_redirect->redirect_ips[0], in_redirect->redirect_ips[0]);
    STRSCPY(new_redirect->redirect_ips[1], in_redirect->redirect_ips[1]);
}

/**
 * @brief create a new attribute entry fo the given attribute type.
 *        We have previously ensured the manager is initialized.
 *
 * @params: entry: specifing the attribute type
 *
 * @return return pointer to created attribute struct
 *         NULL on failure
 */
struct attr_cache *
gkc_new_attr_entry(struct gk_attr_cache_interface *entry)
{
    struct attr_cache *new_attr_cache;
    union attribute_type *attr;
    time_t now;

    new_attr_cache = CALLOC(1, sizeof(*new_attr_cache));
    if (new_attr_cache == NULL) return NULL;

    attr = &new_attr_cache->attr;
    now = time(NULL);

    switch (entry->attribute_type)
    {
        case GK_CACHE_REQ_TYPE_FQDN:
            attr->host_name = CALLOC(1, sizeof(*attr->host_name));
            if (attr->host_name == NULL) goto cleanup_new_attr;
            attr->host_name->name = STRDUP(entry->attr_name);
            attr->host_name->count_fqdn.total = 1;

            gk_add_new_redirect_entry(entry, new_attr_cache);
            break;

        case GK_CACHE_REQ_TYPE_HOST:
            attr->host_name = CALLOC(1, sizeof(*attr->host_name));
            if (attr->host_name == NULL) goto cleanup_new_attr;
            attr->host_name->name = STRDUP(entry->attr_name);
            attr->host_name->count_host.total = 1;
            break;

        case GK_CACHE_REQ_TYPE_SNI:
            attr->host_name = CALLOC(1, sizeof(*attr->host_name));
            if (attr->host_name == NULL) goto cleanup_new_attr;
            attr->host_name->name = STRDUP(entry->attr_name);
            attr->host_name->count_sni.total = 1;
            break;

        case GK_CACHE_REQ_TYPE_URL:
            attr->url = CALLOC(1, sizeof(*attr->url));
            if (attr->url == NULL) goto cleanup_new_attr;
            attr->url->name = STRDUP(entry->attr_name);
            attr->url->hit_count.total = 1;
            break;

        case GK_CACHE_REQ_TYPE_IPV4:
            attr->ipv4 = CALLOC(1, sizeof(*attr->ipv4));
            if (attr->ipv4 == NULL) goto cleanup_new_attr;
            if (entry->ip_addr)
                memcpy(&attr->ipv4->ip_addr, entry->ip_addr, sizeof(attr->ipv4->ip_addr));
            attr->ipv4->hit_count.total = 1;
            if (entry->action_by_name != FSM_ACTION_NONE)
                attr->ipv4->action_by_name = entry->action_by_name;
            break;

        case GK_CACHE_REQ_TYPE_IPV6:
            attr->ipv6 = CALLOC(1, sizeof(*attr->ipv6));
            if (attr->ipv6 == NULL) goto cleanup_new_attr;
            if (entry->ip_addr)
                memcpy(&attr->ipv6->ip_addr, entry->ip_addr, sizeof(attr->ipv6->ip_addr));
            attr->ipv6->hit_count.total = 1;
            if (entry->action_by_name != FSM_ACTION_NONE)
                attr->ipv6->action_by_name = entry->action_by_name;
            break;

        case GK_CACHE_REQ_TYPE_APP:
            attr->app_name = CALLOC(1, sizeof(*attr->app_name));
            if (attr->app_name == NULL) goto cleanup_new_attr;
            attr->app_name->name = STRDUP(entry->attr_name);
            attr->app_name->hit_count.total = 1;
            break;

        default:
            goto cleanup_new_attr;
    }

    /* add entry creation time and provided TTL value */
    new_attr_cache->cache_ts = now;
    new_attr_cache->original_ts = now;
    new_attr_cache->cache_ttl = entry->cache_ttl;

    /* add the direction and the key */
    new_attr_cache->direction = entry->direction;
    if (entry->cache_key == 0)
        entry->cache_key = get_attr_key(entry);
    new_attr_cache->key = entry->cache_key;

    /* set action value: allow or block */
    new_attr_cache->redirect_flag = entry->redirect_flag;
    new_attr_cache->action = entry->action;
    new_attr_cache->categorized = entry->categorized;
    new_attr_cache->category_id = entry->category_id;
    new_attr_cache->confidence_level = entry->confidence_level;
    new_attr_cache->is_private_ip = entry->is_private_ip;
    if (entry->gk_policy)
    {
        new_attr_cache->gk_policy = STRDUP(entry->gk_policy);
    }

    new_attr_cache->flow_marker = entry->flow_marker;

    if (entry->network_id)
    {
        new_attr_cache->network_id = STRDUP(entry->network_id);
    }

    return new_attr_cache;

cleanup_new_attr:
    FREE(new_attr_cache);
    return NULL;
}

/**
 * @brief effectively add the attribute to the per device 'host_name' tree.
 *        We have ensured that the manager is initialized.
 *
 * @params: cache: tree structure for the attribute type
 * @params: entry: interface structure with input values
 *
 * @return true if new_attr_entry was inserted for the first time,
 *         false otherwise (we updated the cache)
 */
static bool
gkc_insert_host_name(ds_tree_t *cache, struct gk_attr_cache_interface *entry)
{
    struct attr_cache *cached_attr_entry;
    struct attr_cache *new_attr_cache;
    struct attr_hostname_s *attr;
    time_t now;
    bool rc;

    /* Perform the lookup before right before the actual insert.
     * In the present case, we can have more than one 'add' for each
     * entry (e.g., FQDN, then HOST): we need to update the matching
     * hit count.
     */

    cached_attr_entry = gkc_fetch_attribute_entry(entry);
    if (cached_attr_entry)
    {
        rc = cached_attr_entry->is_private_ip;
        if (rc)
        {
            now = time(NULL);
            cached_attr_entry->cache_ts = now;
            entry->is_private_ip = cached_attr_entry->is_private_ip;
            return false;
        }

        /* we don't need to test for validity as we just looked it up */
        attr = cached_attr_entry->attr.host_name;

        /* Since we found the entry in the cache, update what's needed
         * in that entry
         */
        switch (entry->attribute_type)
        {
            case GK_CACHE_REQ_TYPE_FQDN:
                attr->count_fqdn.total++;
                break;

            case GK_CACHE_REQ_TYPE_HOST:
                attr->count_host.total++;
                break;

            case GK_CACHE_REQ_TYPE_SNI:
                attr->count_sni.total++;
                break;

            default:
                /* Never reached by construction */
                LOGD("%s(): Unexpected attribute type: %d", __func__, entry->attribute_type);
                return false;
        }

        now = time(NULL);
        cached_attr_entry->cache_ts = now;

        return false;
    }

    /* We didn't have this entry, so we insert it now. */
    new_attr_cache = gkc_new_attr_entry(entry);
    if (new_attr_cache == NULL) return false;

    ds_tree_insert(cache, new_attr_cache, &new_attr_cache->key);

    return true;
}

/**
 * @brief effectively add the attribute to a per device 'cache' tree.
 *
 * @params: cache: tree structure for the attribute type
 * @params: entry: interface structure with input values
 *
 * @return true if new_attr_entry was inserted for the first time,
 *         false otherwise (we updated the cache)
 */
static bool
gkc_insert_generic(ds_tree_t *cache, struct gk_attr_cache_interface *entry)
{
    struct attr_cache *new_attr_cache;
    bool was_inserted;

    /* Perform the lookup just before the insert. Here, we don't need to update
     * anything as there should never be 2 inserts for 'generic' entries.
     */
    was_inserted = gkc_lookup_attribute_entry(entry, false);
    if (was_inserted)
    {
        LOGT("%s(): attribute entry " PRI_os_macaddr_lower_t " already present",
            __func__, FMT_os_macaddr_pt(entry->device_mac));
        return false;
    }

    new_attr_cache = gkc_new_attr_entry(entry);
    if (new_attr_cache == NULL) return false;

    ds_tree_insert(cache, new_attr_cache, &new_attr_cache->key);

    return true;
}

/**
 * @brief add the attribute to per device tree.
 *
 * @params: pdevice_cache: device tree structure
 * @params: entry: interface structure with input values
 *
 * @return true if the entry was properly inserted/updated in the cache
 */
static bool
gkc_add_attr_tree(struct per_device_cache *pdevice_cache, struct gk_attr_cache_interface *entry)
{
    bool was_inserted = false;

    switch (entry->attribute_type)
    {
        case GK_CACHE_REQ_TYPE_FQDN:
        case GK_CACHE_REQ_TYPE_HOST:
        case GK_CACHE_REQ_TYPE_SNI:
            was_inserted = gkc_insert_host_name(&pdevice_cache->hostname_tree, entry);
            break;

        case GK_CACHE_REQ_TYPE_URL:
            was_inserted = gkc_insert_generic(&pdevice_cache->url_tree, entry);
            break;

        case GK_CACHE_REQ_TYPE_IPV4:
            was_inserted = gkc_insert_generic(&pdevice_cache->ipv4_tree, entry);
            break;

        case GK_CACHE_REQ_TYPE_IPV6:
            was_inserted = gkc_insert_generic(&pdevice_cache->ipv6_tree, entry);
            break;

        case GK_CACHE_REQ_TYPE_APP:
            was_inserted = gkc_insert_generic(&pdevice_cache->app_tree, entry);
            break;

        default:
            LOGD("%s(): Not inserted on type = %d", __func__, entry->attribute_type);
            break;
    }
    return was_inserted;
}

/**
 * @brief initializes the per device tree if not initialized and then
 *        adds the attribute to it.
 *
 * @params: entry: interface structure with input values
 * @return: true or success false on failure
 */
bool
gkc_add_attribute_entry(struct gk_attr_cache_interface *entry)
{
    struct per_device_cache *pdevice_cache;
    struct gk_cache_mgr *mgr;
    int ret;

    mgr = gk_cache_get_mgr();
    if (!mgr->initialized) return false;

    if (mgr->total_entry_count >= GK_MAX_CACHE_ENTRIES)
    {
        LOGD("%s(): max cache entries %" PRIu64 " reached, cannot add entry to GK cache",
             __func__, mgr->total_entry_count);
        return false;
    }

    /* return if attribute type is not valid */
    if (entry->attribute_type < GK_CACHE_REQ_TYPE_FQDN  || entry->attribute_type > GK_CACHE_REQ_TYPE_APP) return false;

    pdevice_cache = ds_tree_find(&mgr->per_device_tree, entry->device_mac);
    if (pdevice_cache == NULL)
    {
        /* create a new per device tree */
        pdevice_cache = gkc_init_per_dev(entry->device_mac);
        if (pdevice_cache == NULL) return false;

        ds_tree_insert(&mgr->per_device_tree, pdevice_cache, pdevice_cache->device_mac);
    }

    /* Pre-compute the key */
    if (entry->cache_key == 0)
        entry->cache_key = get_attr_key(entry);

    /* Delay lookup until later, as we need different accounting.
     * See respective add functions.
     */

    ret = gkc_add_attr_tree(pdevice_cache, entry);
    if (ret == false) return false;

    /* increment cache entries counter */
    mgr->total_entry_count++;

    if (entry->action == FSM_ALLOW)
    {
        pdevice_cache->allowed[entry->attribute_type]++;
    }
    else
    {
        pdevice_cache->blocked[entry->attribute_type]++;
    }

    return true;
}

/**
 * @brief initializes the per device tree if not initialized and then
 *        adds the IP flow entry to it.
 *
 * @params: entry: IP flow interface structure with input values
 * @return: true or success false on failure
 */
bool
gkc_add_flow_entry(struct gkc_ip_flow_interface *entry)
{
    enum gk_cache_request_type attr_type;
    struct per_device_cache *pdevice;
    struct gk_cache_mgr *mgr;
    int ret;

    mgr = gk_cache_get_mgr();
    if (!mgr->initialized) return false;

    if (!entry->device_mac) return false;

    /* For the flows, we can lookup early as there are no corner cases */
    ret = gkc_lookup_flow(entry, false);
    if (ret)
    {
        LOGT("%s(): entry " PRI_os_macaddr_lower_t " already present",
             __func__, FMT_os_macaddr_pt(entry->device_mac));
        return false;
    }

    if (mgr->total_entry_count >= GK_MAX_CACHE_ENTRIES)
    {
        LOGD("%s(): max cache entries of %" PRIu64 " reached, cannot add entry to GK cache",
             __func__, mgr->total_entry_count);
        return false;
    }

    pdevice = ds_tree_find(&mgr->per_device_tree, entry->device_mac);
    if (pdevice == NULL)
    {
        /* create a new per device tree */
        pdevice = gkc_init_per_dev(entry->device_mac);
        if (pdevice == NULL) return false;

        ds_tree_insert(&mgr->per_device_tree, pdevice, pdevice->device_mac);
    }

    ret = gkc_add_flow_tree(pdevice, entry);
    if (ret == false) return false;

    /* increment cache entries counter */
    mgr->total_entry_count++;

    /* set the attribute type */
    attr_type =
        (entry->direction == GKC_FLOW_DIRECTION_INBOUND ? GK_CACHE_REQ_TYPE_INBOUND : GK_CACHE_REQ_TYPE_OUTBOUND);

    if (entry->action == FSM_ALLOW)
    {
        pdevice->allowed[attr_type]++;
    }
    else
    {
        pdevice->blocked[attr_type]--;
    }

    return true;
}

/**
 * @brief look up the device tree to the find the given
 *        device.
 *
 * @params: device_mac: mac address of the device
 * @return: pointer to per_device_cache if found else NULL
 */
struct per_device_cache *
gkc_lookup_device_tree(os_macaddr_t *device_mac)
{
    struct per_device_cache *pdevice_cache;
    struct gk_cache_mgr *mgr;

    if (!device_mac) return NULL;

    mgr = gk_cache_get_mgr();
    if (!mgr->initialized) return NULL;

    pdevice_cache = ds_tree_find(&mgr->per_device_tree, device_mac);
    return pdevice_cache;
}

/**
 * @brief check if the given flow is present in the cache
 *
 * @params: req: IP flow interface structure with the flow
 *          tuple to find
 * @return: true if found false if not present
 */
bool
gkc_lookup_flow(struct gkc_ip_flow_interface *req, bool update_count)
{
    struct per_device_cache *pdevice;
    int ret;

    if (!req) return false;
    ret = gkc_is_flow_valid(req);
    if (ret == false) return false;

    /* look up the per device tree first */
    pdevice = gkc_lookup_device_tree(req->device_mac);
    if (pdevice == NULL) return false;

    /* lookup flows tree */
    ret = gkc_lookup_flows_for_device(pdevice, req, update_count);

    return ret;
}

/**
 * @brief remove the give flow from the cache
 *
 * @params: req: IP flow interface structure with the flow
 *          tuple to delete
 * @return: true if success false is failed
 */
bool
gkc_del_flow(struct gkc_ip_flow_interface *req)
{
    struct per_device_cache *pdevice;
    struct gk_cache_mgr *mgr;
    int ret;

    mgr = gk_cache_get_mgr();
    if (!mgr->initialized) return false;

    ret = gkc_is_flow_valid(req);
    if (ret == false) return false;

    /* first check if the device is present */
    pdevice = gkc_lookup_device_tree(req->device_mac);
    if (pdevice == NULL) return false;

    ret = gkc_del_flow_from_dev(pdevice, req);
    if (ret == false) return false;

    mgr->total_entry_count--;
    return ret;
}

/**
 * @brief initialize gk_cache.
 *
 * receive none
 *
 * @return true for success and false for failure.
 */
bool
gk_cache_init(void)
{
    struct gk_cache_mgr *mgr;

    mgr = gk_cache_get_mgr();
    gk_cache_init_mgr(mgr);

    return true;
}

/**
 * @brief cleanup allocated memory.
 *
 * receive none
 *
 * @return void.
 */
void
gkc_cleanup_mgr(void)
{
    struct gk_cache_mgr *mgr = gk_cache_get_mgr();

    if (!mgr->initialized) return;
    gk_cache_cleanup();
    mgr->initialized = false;
    mgr->total_entry_count = 0;
}

void
gkc_lookup_redirect_entry(struct gk_attr_cache_interface *req, struct attr_cache *attr_entry)
{
    if (req->attribute_type != GK_CACHE_REQ_TYPE_FQDN) return;

    if (req->fqdn_redirect == NULL || attr_entry->fqdn_redirect == NULL) return;

    if (attr_entry->fqdn_redirect->redirect_cname)
    {
        req->fqdn_redirect->redirect_cname = STRDUP(attr_entry->fqdn_redirect->redirect_cname);
    }
    req->fqdn_redirect->redirect = attr_entry->fqdn_redirect->redirect;
    req->fqdn_redirect->redirect_ttl = attr_entry->fqdn_redirect->redirect_ttl;
    STRSCPY(req->fqdn_redirect->redirect_ips[0], attr_entry->fqdn_redirect->redirect_ips[0]);
    STRSCPY(req->fqdn_redirect->redirect_ips[1], attr_entry->fqdn_redirect->redirect_ips[1]);
}

bool
gkc_update_entry_action(struct gk_attr_cache_interface *req, struct attr_cache *attr_entry)
{
    struct attr_ip_addr_s *generic;
    if (req->attribute_type == GK_CACHE_REQ_TYPE_IPV4)
    {
        generic = attr_entry->attr.ipv4;
    }
    else if (req->attribute_type == GK_CACHE_REQ_TYPE_IPV6)
    {
        generic = attr_entry->attr.ipv6;
    }
    else return true;

    if ((generic->action_by_name == FSM_ACTION_NONE) && (attr_entry->action != FSM_ACTION_NONE))
    {
        /* entry added by IP threat. first request */
        req->action = attr_entry->action;
    }
    else if ((generic->action_by_name == FSM_ALLOW) && (attr_entry->action == FSM_ACTION_NONE))
    {
        /* entry added by dns. first request  */
        req->action = generic->action_by_name;
    }
    else if ((generic->action_by_name == FSM_ALLOW) && (attr_entry->action != FSM_ACTION_NONE))
    {
        req->action = attr_entry->action;
    }
    else if ((generic->action_by_name == FSM_BLOCK) && (attr_entry->action == FSM_ACTION_NONE))
    {
        /* entry added during dns response ips. action is block enforcing IP check */
        LOGT("%s: %s dns action is block, enforcing gatekeeper for IP check", __func__, req->attr_name);
        return false;
    }
    else if ((generic->action_by_name == FSM_BLOCK) && (attr_entry->action != FSM_ACTION_NONE))
    {
        req->action = attr_entry->action;
    }

    return true;
}

/**
 * @brief check if the attribute is present in the attribute
 *        tree
 *
 * @params: req: attribute interface structure with the
 *          attribute value to find
 * @return: true if found false if not present
 */
static bool
gkc_lookup_attr_tree(ds_tree_t *tree, struct gk_attr_cache_interface *req, bool update_count)
{
    struct attr_cache *attr_entry;
    union attribute_type *attr;
    int hit_count;
    uint64_t key;
    bool rc;
    int ret;

    if (!req->attr_name && !req->ip_addr) return false;

    if (req->cache_key == 0)
        req->cache_key = get_attr_key(req);
    key = req->cache_key;

    attr_entry = ds_tree_find(tree, &key);
    if (attr_entry == NULL) return false;
    attr = &attr_entry->attr;
    rc = attr_entry->is_private_ip;

    hit_count = req->hit_counter;

    /* increment the hit counter for this attribute */
    if (update_count && !rc)
    {
        switch (req->attribute_type)
        {
            case GK_CACHE_REQ_TYPE_FQDN:
                attr->host_name->count_fqdn.total++;
                hit_count = attr->host_name->count_fqdn.total;
                break;

            case GK_CACHE_REQ_TYPE_URL:
                attr->url->hit_count.total++;
                hit_count = attr->url->hit_count.total;
                break;

            case GK_CACHE_REQ_TYPE_HOST:
                attr->host_name->count_host.total++;
                hit_count = attr->host_name->count_host.total;
                break;

            case GK_CACHE_REQ_TYPE_SNI:
                attr->host_name->count_sni.total++;
                hit_count = attr->host_name->count_sni.total;
                break;

            case GK_CACHE_REQ_TYPE_IPV4:
                attr->ipv4->hit_count.total++;
                hit_count = attr->ipv4->hit_count.total;
                break;

            case GK_CACHE_REQ_TYPE_IPV6:
                attr->ipv6->hit_count.total++;
                hit_count = attr->ipv6->hit_count.total;
                break;

            case GK_CACHE_REQ_TYPE_APP:
                attr->app_name->hit_count.total++;
                hit_count = attr->app_name->hit_count.total;
                break;

            default:
                LOGD("%s(): unknown attr_type=%d", __func__, req->attribute_type);
        }
    }

    /* update the request with hit counter */
    req->hit_counter = hit_count;

    /* for new entry update count is false */
    if (update_count)
    {
        rc = gkc_update_entry_action(req, attr_entry);
        if (!rc) return false;
    }

    if ((attr_entry->action == FSM_ACTION_NONE) && (req->action != FSM_ACTION_NONE))
    {
        attr_entry->action = req->action;
    }
    else
        req->action = attr_entry->action;

    req->categorized = attr_entry->categorized;
    req->category_id = attr_entry->category_id;
    req->confidence_level = attr_entry->confidence_level;
    req->is_private_ip = attr_entry->is_private_ip;
    req->redirect_flag = attr_entry->redirect_flag;
    req->flow_marker = attr_entry->flow_marker;
    req->network_id = attr_entry->network_id;

    if ((req->attribute_type == GK_CACHE_REQ_TYPE_SNI) && (req->action == FSM_REDIRECT))
    {
        req->action = FSM_BLOCK;
        req->redirect_flag = false;
    }

    gkc_lookup_redirect_entry(req, attr_entry);

    if (attr_entry->gk_policy != NULL)
    {
        if (req->gk_policy == NULL)
        {
            /* update req gk_policy from cache entry */
            req->gk_policy = STRDUP(attr_entry->gk_policy);
        }
        else
        {
            /* update gk_policy if req gk_policy is different */
            ret = strcmp_len(attr_entry->gk_policy, strlen(attr_entry->gk_policy),
                             req->gk_policy, strlen(req->gk_policy));
            if (ret)
            {
                FREE(attr_entry->gk_policy);
                attr_entry->gk_policy = STRDUP(req->gk_policy);
            }
        }
    }
    else
    {
        /* update cache policy if it is not present */
        if (req->gk_policy != NULL)
        {
            attr_entry->gk_policy = STRDUP(req->gk_policy);
        }
    }

    return true;
}

/**
 * @brief check if the attribute is present in the device
 *        tree
 *
 * @params: req: attribute interface structure with the
 *          attribute value to find
 * @return: true if found false if not present
 */
static bool
gkc_lookup_attributes_tree(struct per_device_cache *pdevice, struct gk_attr_cache_interface *req, bool update_count)
{
    int ret = false;

    switch (req->attribute_type)
    {
        case GK_CACHE_REQ_TYPE_FQDN:
        case GK_CACHE_REQ_TYPE_HOST:
        case GK_CACHE_REQ_TYPE_SNI:
            ret = gkc_lookup_attr_tree(&pdevice->hostname_tree, req, update_count);
            break;

        case GK_CACHE_REQ_TYPE_URL:
            ret = gkc_lookup_attr_tree(&pdevice->url_tree, req, update_count);
            break;

        case GK_CACHE_REQ_TYPE_IPV4:
            ret = gkc_lookup_attr_tree(&pdevice->ipv4_tree, req, update_count);
            break;

        case GK_CACHE_REQ_TYPE_IPV6:
            ret = gkc_lookup_attr_tree(&pdevice->ipv6_tree, req, update_count);
            break;

        case GK_CACHE_REQ_TYPE_APP:
            ret = gkc_lookup_attr_tree(&pdevice->app_tree, req, update_count);
            break;

        default:
            break;
    }

    return ret;
}

/**
 * @brief Lookup cached action for given attribute
 *
 * receive ipaddress and mac of device.
 *
 * output action.
 *
 * @return true for success and false for failure.
 */
bool
gkc_lookup_attribute_entry(struct gk_attr_cache_interface *req, bool update_count)
{
    struct per_device_cache *pdevice;
    bool ret;

    if (!req || !req->device_mac) return false;

    if (req->attribute_type < GK_CACHE_REQ_TYPE_FQDN || req->attribute_type >= GK_CACHE_MAX_REQ_TYPES) return false;

    /* look up the per device tree first */
    pdevice = gkc_lookup_device_tree(req->device_mac);
    if (pdevice == NULL) return false;

    /* lookup the attributes tree */
    ret = gkc_lookup_attributes_tree(pdevice, req, update_count);
    if (ret == false) return ret;

    /* update the time statmp */
    pdevice->req_counter[req->attribute_type] += 1;

    return ret;
}

struct attr_cache *
gkc_fetch_attribute_entry(struct gk_attr_cache_interface *req)
{
    struct per_device_cache *pdevice;
    struct attr_cache *cache_entry;
    uint64_t key;

    if (!req || !req->device_mac) return NULL;

    if (req->attribute_type < GK_CACHE_REQ_TYPE_FQDN || req->attribute_type >= GK_CACHE_MAX_REQ_TYPES)
        return NULL;

    /* look up the per device tree first */
    pdevice = gkc_lookup_device_tree(req->device_mac);
    if (pdevice == NULL) return NULL;

    /* Build the key to look for */
    if (req->cache_key == 0)
        req->cache_key = get_attr_key(req);
    key = req->cache_key;

    /* lookup the attributes tree */
    switch (req->attribute_type)
    {
        case GK_CACHE_REQ_TYPE_FQDN:
        case GK_CACHE_REQ_TYPE_HOST:
        case GK_CACHE_REQ_TYPE_SNI:
            cache_entry = ds_tree_find(&pdevice->hostname_tree, &key);
            break;

        case GK_CACHE_REQ_TYPE_URL:
            cache_entry = ds_tree_find(&pdevice->url_tree, &key);
            break;

        case GK_CACHE_REQ_TYPE_IPV4:
            cache_entry = ds_tree_find(&pdevice->ipv4_tree, &key);
            break;

        case GK_CACHE_REQ_TYPE_IPV6:
            cache_entry = ds_tree_find(&pdevice->ipv6_tree, &key);
            break;

        case GK_CACHE_REQ_TYPE_APP:
            cache_entry = ds_tree_find(&pdevice->app_tree, &key);
            break;

        default:
            cache_entry = NULL;
            break;
    }

    return cache_entry;
}


/**
 * @brief upate or add the given attribute to the cache.
 *
 * @params: req: interface structure specifing the attribute request
 *
 * @return true for success and false for failure.
 */
bool
gkc_upsert_attribute_entry(struct gk_attr_cache_interface *entry)
{
    enum gk_cache_request_type attribute_type;
    char  ipstr[INET6_ADDRSTRLEN] = { 0 };
    struct sockaddr_in6 *addr_v6;
    struct sockaddr_in *addr_v4;
    struct attr_cache *attr_entry;
    time_t now;
    bool rc;

    attribute_type = entry->attribute_type;
    if (entry->attr_name == NULL)
    {
        if (attribute_type == GK_CACHE_REQ_TYPE_IPV4)
        {
            addr_v4 = (struct sockaddr_in *)entry->ip_addr;
            inet_ntop(AF_INET, &addr_v4->sin_addr, ipstr, sizeof(ipstr));
        }
        else if (attribute_type == GK_CACHE_REQ_TYPE_IPV6)
        {
            addr_v6 = (struct sockaddr_in6 *)entry->ip_addr;
            inet_ntop(AF_INET6, &addr_v6->sin6_addr, ipstr, sizeof(ipstr));
        }
    }

    /* Fetch the cache entry */
    attr_entry = gkc_fetch_attribute_entry(entry);
    if (attr_entry == NULL) /* Add the entry if not found */
    {
        rc = gkc_add_attribute_entry(entry);
        if (!rc)
        {
            LOGD("%s: Couldn't add ip entry to gatekeeper cache.", __func__);
        }
        LOGT("%s(): adding %s (attr type %d) ttl (%" PRIu64 ") to cache %s ",
             __func__,
             ((entry->attr_name != NULL) ? entry->attr_name : ipstr),
             attribute_type,
             entry->cache_ttl,
             (rc == true) ? "success" : "failed");
        return rc;
    }

    /* Update the entry */
    if (entry->action_by_name != FSM_ACTION_NONE)
    {
        if (attribute_type == GK_CACHE_REQ_TYPE_IPV4)
        {
            attr_entry->attr.ipv4->action_by_name = entry->action_by_name;
        }
        else if (attribute_type == GK_CACHE_REQ_TYPE_IPV6)
        {
            attr_entry->attr.ipv6->action_by_name = entry->action_by_name;
        }
    }

    if (entry->action != FSM_ACTION_NONE) attr_entry->action = entry->action;
    attr_entry->categorized = entry->categorized;
    attr_entry->category_id = entry->category_id;
    attr_entry->confidence_level = entry->confidence_level;
    attr_entry->is_private_ip = entry->is_private_ip;
    attr_entry->redirect_flag = entry->redirect_flag;
    now = time(NULL);
    attr_entry->cache_ts = now;

    if (entry->gk_policy != NULL)
    {
        if (attr_entry->gk_policy != NULL)
        {
            int ret;

            ret = strcmp_len(attr_entry->gk_policy, strlen(attr_entry->gk_policy),
                             entry->gk_policy, strlen(entry->gk_policy));
            if (ret)
            {
                FREE(attr_entry->gk_policy);
                attr_entry->gk_policy = STRDUP(entry->gk_policy);
            }
        }
        else
        {
            attr_entry->gk_policy = STRDUP(entry->gk_policy);
        }
    }
    /* Leaving the redirecting fields alone for now */

    LOGT("%s(): updating %s (attr type %d) ttl (%" PRIu64 ") (elapsed time %.1f) to cache %s ",
         __func__,
         ((entry->attr_name != NULL) ? entry->attr_name : ipstr),
         attribute_type,
         entry->cache_ttl,
         difftime(now, attr_entry->original_ts),
         "success");
    return true;
}



/**
 * @brief Delete fqdn entry.
 *
 * receive gk_cache_entry.
 *
 * @return true for success and false for failure.
 */
bool
gkc_del_attribute(struct gk_attr_cache_interface *req)
{
    struct per_device_cache *pdevice;
    struct gk_cache_mgr *mgr;
    int ret;

    mgr = gk_cache_get_mgr();
    if (!mgr->initialized) return false;

    if (!req || !req->device_mac) return false;

    /* first check if the device is present */
    pdevice = gkc_lookup_device_tree(req->device_mac);
    if (pdevice == NULL) return false;

    ret = gkc_del_attr_from_dev(pdevice, req);
    if (ret == false) return false;

    mgr->total_entry_count--;

    return ret;
}

/**
 * @brief remove old cache entres.
 *
 * @param ttl the cache entry time to live
 */
void
gkc_ttl_cleanup(void)
{
    struct gk_cache_mgr *mgr;
    ds_tree_t *tree;

    mgr = gk_cache_get_mgr();
    if (!mgr->initialized) return;

    tree = &mgr->per_device_tree;
    gk_cache_check_ttl_device_tree(tree);
}

/**
 * @brief returns the number of entries present in the cache
 *
 * @return number of entries present in the cache
 */
unsigned long
gk_get_cache_count(void)
{
    struct gk_cache_mgr *mgr;

    mgr = gk_cache_get_mgr();
    if (!mgr->initialized) return 0;

    return mgr->total_entry_count;
}

/**
 * @brief get the count of the devices stored in cache
 *
 * @return returns the device count value
 */
int
gk_get_device_count(void)
{
    struct per_device_cache *pdevice;
    struct gk_cache_mgr *mgr;
    ds_tree_t *tree;
    int count = 0;

    mgr = gk_cache_get_mgr();
    tree = &mgr->per_device_tree;

    if (!mgr->initialized) return count;

    ds_tree_foreach(tree, pdevice)
    {
        count++;
    }

    return count;
}

/**
 * @brief get the count of devices having allowed action
 *
 * @params: device_mac mac address of the device
 * @params: attr_type attribute type
 * @return counter value of the device.
 */
uint64_t
gkc_get_allowed_counter(os_macaddr_t *device_mac, enum gk_cache_request_type attr_type)
{
    struct per_device_cache *pdevice;

    if (!device_mac) return 0;

    if (attr_type < GK_CACHE_REQ_TYPE_FQDN || attr_type >= GK_CACHE_MAX_REQ_TYPES) return 0;

    /* look up the per device tree first */
    pdevice = gkc_lookup_device_tree(device_mac);
    if (pdevice == NULL) return 0;

    return pdevice->allowed[attr_type];
}

/**
 * @brief check ttl value for the given attribue
 *        or flow tree
 *
 * @params: attribute or flow tree
 *
 * @return void.
 */
uint64_t
gkc_get_blocked_counter(os_macaddr_t *device_mac, enum gk_cache_request_type attr_type)
{
    struct per_device_cache *pdevice;

    if (!device_mac) return 0;

    if (attr_type < GK_CACHE_REQ_TYPE_FQDN || attr_type >= GK_CACHE_MAX_REQ_TYPES) return 0;

    /* look up the per device tree first */
    pdevice = gkc_lookup_device_tree(device_mac);
    if (pdevice == NULL) return 0;

    return pdevice->blocked[attr_type];
}

/**
 * @brief pretty print the direction
 *
 * @param direction as presented in the enum
 *
 * @return matching string description
 */
static const char *
dir2str(uint8_t direction)
{
    switch (direction)
    {
        case GKC_FLOW_DIRECTION_INBOUND     : return "inbound";
        case GKC_FLOW_DIRECTION_OUTBOUND    : return "outbound";
        case GKC_FLOW_DIRECTION_LAN2LAN     : return "lan2lan";
        case GKC_FLOW_DIRECTION_UNSPECIFIED :
        default:                              return "unset";
    }
    /* never reached */
}

static void
dump_attr_tree(ds_tree_t *tree, enum gk_cache_request_type req_type)
{
    char ip_str[INET6_ADDRSTRLEN];
    union attribute_type *attr;
    struct attr_cache *entry;
    struct sockaddr_in6 *in6;
    struct sockaddr_in *in4;

    if (tree == NULL) return;

    ds_tree_foreach(tree, entry)
    {
        attr = &entry->attr;
        switch (req_type)
        {
            case GK_CACHE_INTERNAL_TYPE_HOSTNAME:
                LOGT("\t\t\t %s, %s, %s, %" PRId64 " , %" PRId64 " , %" PRId64 " network_id %s",
                     attr->host_name->name,
                     dir2str(entry->direction),
                     fsm_policy_get_action_str(entry->action),
                     attr->host_name->count_fqdn.total,
                     attr->host_name->count_host.total,
                     attr->host_name->count_sni.total,
                     entry->network_id);
                break;

            case GK_CACHE_REQ_TYPE_URL:
                LOGT("\t\t\t %s, %s, %s, %" PRId64 " network_id: %s",
                     attr->url->name,
                     dir2str(entry->direction),
                     fsm_policy_get_action_str(entry->action),
                     attr->url->hit_count.total,
                     entry->network_id);
                break;

            case GK_CACHE_REQ_TYPE_IPV4:
                in4 = (struct sockaddr_in *)&(attr->ipv4->ip_addr);
                inet_ntop(AF_INET, &in4->sin_addr, ip_str, INET_ADDRSTRLEN);
                LOGT("\t\t\t %s, %s, %s, %" PRId64 " network_id: %s",
                     ip_str,
                     dir2str(entry->direction),
                     fsm_policy_get_action_str(entry->action),
                     attr->ipv4->hit_count.total,
                     entry->network_id);
                break;

            case GK_CACHE_REQ_TYPE_IPV6:
                in6 = (struct sockaddr_in6 *)&(attr->ipv6->ip_addr);
                inet_ntop(AF_INET6, &in6->sin6_addr, ip_str, INET6_ADDRSTRLEN);
                LOGT("\t\t\t %s, %s, %s, %" PRId64 " network_id: %s",
                     ip_str,
                     dir2str(entry->direction),
                     fsm_policy_get_action_str(entry->action),
                     attr->ipv6->hit_count.total,
                     entry->network_id);
                break;

            case GK_CACHE_REQ_TYPE_APP:
                LOGT("\t\t\t %s, %s, %s, %" PRId64 " network_id: %s",
                     attr->app_name->name,
                     dir2str(entry->direction),
                     fsm_policy_get_action_str(entry->action),
                     attr->app_name->hit_count.total,
                     entry->network_id);
                break;

            default:
                break;
        }
    }
}

static void
dump_flow_tree(ds_tree_t *tree)
{
    char src_ip_str[INET6_ADDRSTRLEN];
    char dst_ip_str[INET6_ADDRSTRLEN];
    int domain;

    struct ip_flow_cache *entry;

    if (tree == NULL) return;

    ds_tree_foreach(tree, entry)
    {
        domain = (entry->ip_version == 4 ? AF_INET : AF_INET6);
        inet_ntop(domain, entry->src_ip_addr, src_ip_str, sizeof(src_ip_str));
        inet_ntop(domain, entry->dst_ip_addr, dst_ip_str, sizeof(dst_ip_str));
        LOGT("src ip %s, dst ip: %s sport: %d, dport: %d proto: %d action: %d, private ip: %s, hitcount: %" PRIu64 " network_id: %s",
             src_ip_str,
             dst_ip_str,
             entry->src_port,
             entry->dst_port,
             entry->protocol,
             entry->action,
             (entry->is_private_ip ? "true" : "false"),
             entry->hit_count.total,
             entry->network_id);
    }
}

/**
 * @brief print cache'd entres.
 *
 */
void
gkc_print_cache_entries(void)
{
    if (LOG_SEVERITY_ENABLED(LOG_SEVERITY_TRACE))
    {
        gkc_print_cache_parts(GK_CACHE_MAX_REQ_TYPES);
    }
}

#define PRINT_ONE_CACHE(type, field, name, dump) \
{\
    if (cache_type == type || cache_type == GK_CACHE_MAX_REQ_TYPES)\
    {\
        subtree = &entry->field;\
        if (!ds_tree_is_empty(subtree))\
        {\
            LOGT("\t %s Entries :", name);\
            dump;\
        }\
    }\
}

#define PRINT_ATTR_CACHE(type, field, name) \
    PRINT_ONE_CACHE(type, field, name, dump_attr_tree(subtree, type));

#define PRINT_FLOW_CACHE(type, field, name) \
    PRINT_ONE_CACHE(type, field, name, dump_flow_tree(subtree));


void
gkc_print_cache_parts(enum gk_cache_request_type cache_type)
{
    struct per_device_cache *entry;
    struct gk_cache_mgr *mgr;
    ds_tree_t *subtree;
    ds_tree_t *tree;

    if (!LOG_SEVERITY_ENABLED(LOG_SEVERITY_TRACE)) return;

    mgr = gk_cache_get_mgr();
    if (!mgr->initialized) return;

    tree = &mgr->per_device_tree;

    LOGT("%s: gatekeeper_cache dump", __func__);
    LOGT("=====START=====");

    ds_tree_foreach(tree, entry)
    {
        LOGT("--------------------------------------------------------------------------------------------------");
        LOGT("\t \t Printing cache entries for device " PRI_os_macaddr_lower_t
             " ",
             FMT_os_macaddr_pt(entry->device_mac));
        LOGT("--------------------------------------------------------------------------------------------------");

        PRINT_ATTR_CACHE(GK_CACHE_INTERNAL_TYPE_HOSTNAME, hostname_tree, "COMBINED");
        PRINT_ATTR_CACHE(GK_CACHE_REQ_TYPE_URL, url_tree, "URL");
        PRINT_ATTR_CACHE(GK_CACHE_REQ_TYPE_IPV4, ipv4_tree, "IPv4");
        PRINT_ATTR_CACHE(GK_CACHE_REQ_TYPE_IPV6, ipv6_tree, "IPv6");
        PRINT_ATTR_CACHE(GK_CACHE_REQ_TYPE_APP, app_tree, "APP Name");

        PRINT_FLOW_CACHE(GK_CACHE_REQ_TYPE_INBOUND, inbound_tree, "Inbound Entries");
        PRINT_FLOW_CACHE(GK_CACHE_REQ_TYPE_OUTBOUND, outbound_tree, "Outbound Entries");
    }
    LOGT("=====END=====");
}

#undef PRINT_FLOW_CACHE
#undef PRINT_ATTR_CACHE
#undef PRINT_ONE_CACHE

void
clear_gatekeeper_cache(void)
{
    LOGD("%s(): clearing gate keeper cache", __func__);
    gk_cache_cleanup();
}
