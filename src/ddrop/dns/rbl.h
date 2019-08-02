#ifndef __RBL_H__
#define __RBL_H__

#include <ldns/ldns.h>

struct ddrop_dns_rbl;
struct ddrop_dns_rbl_ent;

struct ddrop_dns_rbl     * ddrop_dns_rbl_new(void);
struct ddrop_dns_rbl_ent * ddrop_dns_rbl_find(struct ddrop_dns_rbl *, const char *, uint16_t);
struct ddrop_dns_rbl_ent * ddrop_dns_rbl_find_rdf(struct ddrop_dns_rbl *, ldns_rdf *, uint16_t);
struct ddrop_dns_rbl_ent * ddrop_dns_rbl_insert(struct ddrop_dns_rbl *, const char *, uint16_t);

#endif

