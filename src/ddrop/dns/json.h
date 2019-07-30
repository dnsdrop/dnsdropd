#pragma once

#include <ldns/ldns.h>
#include <liblz.h>
#include <liblz/lz_json.h>

CS__EXPORT lz_json * ddrop_dns_to_json(ldns_pkt * packet);
CS__EXPORT lz_json * ddrop_dns_rr_to_json(ldns_rr * rr);
CS__EXPORT lz_json * ddrop_dns_rdf_to_json(ldns_rdf * rdf);
CS__EXPORT lz_json * ddrop_dns_rr_list_to_json(ldns_rr_list * rrlist);

CS__EXPORT ldns_rdf * ddrop_dns_json_to_rdf(lz_json * json);
CS__EXPORT ldns_rr  * ddrop_dns_json_to_rr(lz_json * json);
CS__EXPORT ldns_pkt * ddrop_json_to_dns(lz_json * json);
