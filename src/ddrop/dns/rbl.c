#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <ldns/ldns.h>

#include "rbl.h"

struct ddrop_dns_rbl_ent {
    ldns_rbnode_t              node;
    ldns_rdf                 * name;
    char                     * str;
    uint16_t                   class;
    struct ddrop_dns_rbl_ent * next;
};

#define RBL_MKFN(type, name)                                          \
    type ddrop_dns_rbl_ent_ ## name(struct ddrop_dns_rbl_ent * ent) { \
        return (type)ent->name;                                       \
    }

RBL_MKFN(ldns_rdf *, name);
RBL_MKFN(char *, str);
RBL_MKFN(uint16_t, class);

struct ddrop_dns_rbl {
    ldns_rbtree_t * tree;
};

static int
dns_rbl_rr_cmp_(const void * a, const void * b)
{
    struct ddrop_dns_rbl_ent * x = (struct ddrop_dns_rbl_ent *)a;
    struct ddrop_dns_rbl_ent * y = (struct ddrop_dns_rbl_ent *)b;

    if (x->class != y->class) {
        if (x->class < y->class) {
            return -1;
        }

        return 1;
    }

    return ldns_rdf_compare(x->name, y->name);
}

struct ddrop_dns_rbl *
ddrop_dns_rbl_new(void)
{
    struct ddrop_dns_rbl * rbl;

    if (!(rbl = calloc(1, sizeof(*rbl)))) {
        return NULL;
    }

    rbl->tree = ldns_rbtree_create(dns_rbl_rr_cmp_);

    if (rbl->tree == NULL) {
        free(rbl);
        return NULL;
    }

    return rbl;
}

struct ddrop_dns_rbl_ent *
ddrop_dns_rbl_find_rdf(struct ddrop_dns_rbl * rbl, ldns_rdf * name, uint16_t class)
{
    struct ddrop_dns_rbl_ent z;
    ldns_rbnode_t          * found;

    z.node.key = &z;
    z.name     = name;
    z.class    = class;

    found      = ldns_rbtree_search(rbl->tree, &z);

    return (struct ddrop_dns_rbl_ent *)found;
}

struct ddrop_dns_rbl_ent *
ddrop_dns_rbl_find(struct ddrop_dns_rbl * rbl, const char * name, uint16_t class)
{
    struct ddrop_dns_rbl_ent * found = NULL;
    ldns_rdf                 * rd    = ldns_dname_new_frm_str(name);

    found = ddrop_dns_rbl_find_rdf(rbl, rd, class);
    ldns_rdf_deep_free(rd);

    return found;
}

struct ddrop_dns_rbl_ent *
ddrop_dns_rbl_insert(struct ddrop_dns_rbl * rbl, const char * name, uint16_t class)
{
    struct ddrop_dns_rbl_ent * ent;

    if ((ent = ddrop_dns_rbl_find(rbl, name, class))) {
        return ent;
    }

    if (!(ent = (struct ddrop_dns_rbl_ent *)calloc(1, sizeof(*ent)))) {
        return NULL;
    }

    ent->node.key = ent;
    ent->str      = strdup(name);
    ent->class    = class;
    ent->name     = ldns_dname_new_frm_str(name);

    ldns_rbtree_insert(rbl->tree, &ent->node);

    return ent;
}

int
ddrop_dns_rbl_foreach(struct ddrop_dns_rbl * rbl, int (*cb)(struct ddrop_dns_rbl_ent *, void *), void * arg)
{
    ldns_rbnode_t * node;

    node = ldns_rbtree_first(rbl->tree);

    while (node != LDNS_RBTREE_NULL) {
        struct ddrop_dns_rbl_ent * ent;
        int                        ret;

        ent = (struct ddrop_dns_rbl_ent *)node->key;

        if ((cb) && (ret = (cb)(ent, arg)) != 0) {
            return ret;
        }

        node = ldns_rbtree_next(node);
    }

    return 0;
}
