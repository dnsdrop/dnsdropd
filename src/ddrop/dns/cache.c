#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>

#include <event2/event.h>
#include <ldns/ldns.h>


struct ddrop_dnscache_entry {
    ldns_rbnode_t                 node;
    ldns_rdf                    * name;
    ldns_rr_type                  type;
    ldns_rr_class                 class;
    ldns_pkt                    * answer;
    time_t                        insert_time;
    uint16_t                      ttl;
    struct ddrop_dnscache_entry * next;
};

struct ddrop_dnscache {
    ldns_rbtree_t * root;
};

static int
dnscache_cmpfn(const void * a, const void * b)
{
    struct ddrop_dnscache_entry * x;
    struct ddrop_dnscache_entry * y;

    x = (struct ddrop_dnscache_entry *)a;
    y = (struct ddrop_dnscache_entry *)b;

    if (x->class != y->class) {
        if (x->class < y->class) {
            return -1;
        }

        return 1;
    }

    if (x->type != y->type) {
        if (x->type < y->type) {
            return -1;
        }

        return 1;
    }

    return ldns_rdf_compare(x->name, y->name);
}

#define IS_EXPIRED(E) (E->insert_time + E->ttl > time(NULL)) ? 1 : 0

static struct ddrop_dnscache_entry *
dnscache_find(struct ddrop_dnscache * cache, ldns_rdf * name, ldns_rr_type type, ldns_rr_class class)
{
    struct ddrop_dnscache_entry ent;

    ent.node.key = &ent;
    ent.name     = name;
    ent.class    = class;
    ent.type     = type;

    return (struct ddrop_dnscache_entry *)ldns_rbtree_search(cache->root, &ent);
}

static struct ddrop_dnscache_entry *
dnscache_insert(struct ddrop_dnscache * cache, ldns_rdf * name,
                ldns_rr_type type, ldns_rr_class class,
                uint16_t ttl, ldns_pkt * answer)
{
    struct ddrop_dnscache_entry * ent = NULL;

    if ((ent = dnscache_find(cache, name, type, class))) {
        if (!IS_EXPIRED(ent)) {
            return ent;
        }

        ldns_rbtree_delete(cache->root, ent);
    }

    if (!ent && !(ent = calloc(1, sizeof(*ent)))) {
        return NULL;
    }

    ent->node.key    = ent;
    ent->name        = name;
    ent->type        = type;
    ent->class       = class;
    ent->answer      = answer;
    ent->ttl         = ttl;
    ent->insert_time = time(NULL);

    ldns_rbtree_insert(cache->root, &ent->node);

    return ent;
}

struct ddrop_dnscache *
ddrop_dnscache_new(void)
{
    struct ddrop_dnscache * cache;

    if (!(cache = calloc(1, sizeof(*cache)))) {
        return NULL;
    }

    if (!(cache->root = ldns_rbtree_create(dnscache_cmpfn))) {
        free(cache);
        return NULL;
    }

    return cache;
}
