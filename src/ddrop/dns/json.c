#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>

#include <ldns/ldns.h>

#include "ddrop/common.h"
#include "ddrop/core/log.h"
#include "ddrop/dns/json.h"

static ldns_rr_type
json__to_rr_type_(lz_json * type_j)
{
    if (type_j == NULL) {
        return 1;
    }

    switch (lz_json_get_type(type_j)) {
        case lz_json_vtype_string:
            return ldns_get_rr_type_by_name(lz_json_get_string(type_j));
        case lz_json_vtype_number:
            return lz_json_get_number(type_j);
        default:
            return 0;
    }

    return 0;
}

static ldns_rdf_type
json__to_rdf_type_(lz_json * type_j)
{
    return lz_json_get_number(type_j);
}

static ldns_rr_class
json__to_rr_class_(lz_json * class_j)
{
    switch (lz_json_get_type(class_j)) {
        case lz_json_vtype_string:
            printf("hi %s\n", lz_json_get_string(class_j));
            return ldns_get_rr_class_by_name(lz_json_get_string(class_j));
        case lz_json_vtype_number:
        default:
            return lz_json_get_number(class_j);
    }
}

static int
json__to_rdf_(ldns_rdf ** out, lz_json * json)
{
    ldns_rdf * rdf;
    lz_json  * _type;
    lz_json  * _data;

    *out  = NULL;

    _type = lz_json_get_path(json, "_type");

    if ((_data = lz_json_get_path(json, "_data")) == NULL) {
        log_error("get_data");
        return -1;
    }

    rdf = ldns_rdf_new_frm_str(
            json__to_rdf_type_(_type),
            lz_json_get_string(_data));

    if (rdf == NULL) {
        return -1;
    }

    *out = rdf;

    return 0;
}

static int
rdf__to_json_(lz_json ** out, ldns_rdf * rdf)
{
    lz_json     * rdf_json;
    char        * rdf_str;
    ldns_rdf_type rdf_type;
    int           type;

    if (out == NULL || rdf == NULL) {
        return -1;
    }

    *out = NULL;

    if ((rdf_json = lz_json_object_new()) == NULL) {
        return -1;
    }

    rdf_type = ldns_rdf_get_type(rdf);
    rdf_str  = ldns_rdf2str(rdf);

    lz_json_object_add(rdf_json, "_type",
                       lz_json_number_new(rdf_type));

    lz_json_object_add(rdf_json, "_data",
                       lz_json_string_new(rdf_str));

    *out = rdf_json;

    free(rdf_str);

    return 0;
}

static int
json__to_rr_(ldns_rr ** out, lz_json * json)
{
    lz_json  * _owner;
    lz_json  * _ttl;
    lz_json  * _rd_count;
    lz_json  * _rr_type;
    lz_json  * _rr_class;
    lz_json  * _rdata_fields;
    lz_json  * _rr_question;

    size_t     i;
    ldns_rdf * owner_rdf;
    ldns_rr  * rr;

    _owner        = lz_json_get_path(json, "_owner");
    _ttl          = lz_json_get_path(json, "_ttl");
    _rd_count     = lz_json_get_path(json, "_rd_count");
    _rr_type      = lz_json_get_path(json, "_rr_type");
    _rr_class     = lz_json_get_path(json, "_rr_class");
    _rdata_fields = lz_json_get_path(json, "_rdata_fields");
    _rr_question  = lz_json_get_path(json, "_rr_question");

    if (json__to_rdf_(&owner_rdf, _owner) == -1) {
        log_error("owner json__to_rdf_");
        return -1;
    }

    if ((rr = ldns_rr_new_frm_type(
             json__to_rr_type_(_rr_type))) == NULL) {
        log_error("ldns_rr_new_frm_type");
        return -1;
    }

    ldns_rr_set_owner(rr, owner_rdf);
    ldns_rr_set_ttl(rr, lz_json_get_number(_ttl));
    ldns_rr_set_rd_count(rr, 0);
    ldns_rr_set_class(rr, json__to_rr_class_(_rr_class));
    ldns_rr_set_question(rr, lz_json_get_boolean(_rr_question));

    uint16_t count = lz_json_get_number(_rd_count);

    for (i = 0; i < count; i++) {
        ldns_rdf * rd_rdf;
        lz_json  * rd_rdf_json = lz_json_get_array_index(_rdata_fields, i);

        if (json__to_rdf_(&rd_rdf, rd_rdf_json) == -1) {
            log_error("json__to_rdf_");
            continue;
        }

        ldns_rr_push_rdf(rr, rd_rdf);
    }

    *out = rr;

    return 0;
} /* json__to_rr_ */

static int
rr__to_json_(lz_json ** out, ldns_rr * rr)
{
    lz_json  * rr_json;
    lz_json  * owner_rdf_json;
    lz_json  * rdata_fields_json;
    ldns_rdf * owner_rdf;
    size_t     rd_count;
    size_t     i;

    /*
     *
     * ----------------[ ldns_RR ]---------------------------------------------
     *  strcpy.net.    600     IN      MX             10       mail.strcpy.net.
     *   \              \       \       \              \                     /
     *    owner          ttl     class   type           \        rdf[]      /
     *    (rdf)     (uint32_t) (rr_class) (rr_type)
     */

    rr_json = lz_json_object_new();

    lz_json_object_add(rr_json, "_owner",
                       ddrop_dns_rdf_to_json(ldns_rr_owner(rr)));

    lz_json_object_add(rr_json, "_ttl",
                       lz_json_number_new(ldns_rr_ttl(rr)));

    rd_count = ldns_rr_rd_count(rr);

    lz_json_object_add(rr_json, "_rd_count",
                       lz_json_number_new(rd_count));

    lz_json_object_add(rr_json, "_rr_type",
                       lz_json_number_new(ldns_rr_get_type(rr)));

    lz_json_object_add(rr_json, "_rr_class",
                       lz_json_number_new(ldns_rr_get_class(rr)));

    rdata_fields_json = lz_json_array_new();

    for (i = 0; i < rd_count; i++) {
        ldns_rdf * rdf;

        lz_json_array_add(rdata_fields_json,
                          ddrop_dns_rdf_to_json(ldns_rr_rdf(rr, i)));
    }

    lz_json_object_add(rr_json, "_rdata_fields",
                       rdata_fields_json);

    lz_json_object_add(rr_json, "_rr_question",
                       lz_json_boolean_new(ldns_rr_is_question(rr)));

    *out = rr_json;

    return 0;
} /* rr__to_json_ */

static int
json__to_rr_list_(ldns_rr_list ** out, lz_json * json)
{
    ldns_rr_list * rr_list;
    size_t         rr_count;
    size_t         i;

    return 0;
}

static int
rr_list__to_json_(lz_json ** out, ldns_rr_list * rrlist)
{
    lz_json * rrlist_json;
    size_t    rr_count;
    size_t    i;

    if ((rrlist_json = lz_json_array_new()) == NULL) {
        return -1;
    }

    rr_count = ldns_rr_list_rr_count(rrlist);

    for (i = 0; i < rr_count; i++) {
        ldns_rr * rr;

        lz_json_array_add(rrlist_json,
                          ddrop_dns_rr_to_json(
                              ldns_rr_list_rr(rrlist, i)));
    }

    *out = rrlist_json;

    return 0;
}

ldns_rdf *
ddrop_dns_json_to_rdf(lz_json * json)
{
    ldns_rdf * rdf;

    if (json__to_rdf_(&rdf, json) == -1) {
        return NULL;
    }

    return rdf;
}

ldns_rr *
ddrop_dns_json_to_rr(lz_json * json)
{
    ldns_rr * rr;

    if (json__to_rr_(&rr, json) == -1) {
        return NULL;
    }

    return rr;
}

lz_json *
ddrop_dns_rdf_to_json(ldns_rdf * rdf)
{
    lz_json * rdf_j;

    if (rdf__to_json_(&rdf_j, rdf) == -1) {
        return NULL;
    }

    return rdf_j;
}

lz_json *
ddrop_dns_rr_list_to_json(ldns_rr_list * rrlist)
{
    lz_json * rr_json_array;

    if (rr_list__to_json_(&rr_json_array, rrlist) == -1) {
        return NULL;
    }

    return rr_json_array;
}

lz_json *
ddrop_dns_rr_to_json(ldns_rr * rr)
{
    char       * rr_type  = NULL;
    char       * rr_class = NULL;
    const char * errstr   = NULL;
    lz_json    * rr_json  = NULL;

    if (rr == NULL) {
        return NULL;
    }

    if (rr__to_json_(&rr_json, rr) == -1) {
        return NULL;
    }

    return rr_json;
} /* ddrop_dns_rr_to_json */

ldns_pkt *
ddrop_json_to_dns(lz_json * json)
{
    ldns_pkt * pkt;
    int        i;

    pkt = ldns_pkt_new();

    struct {
        const char * key;
        void         (* ldnsfn)(ldns_pkt *, bool);
    } hdr_[] = {
        { "_qr", ldns_pkt_set_qr },
        { "_aa", ldns_pkt_set_aa },
        { "_tc", ldns_pkt_set_tc },
        { "_rd", ldns_pkt_set_rd },
        { "_cd", ldns_pkt_set_cd },
        { "_ra", ldns_pkt_set_ra },
        { "_ad", ldns_pkt_set_ad },
        { NULL,  NULL            }
    };

    for (i = 0; hdr_[i].key != NULL; i++) {
        lz_json * flag_j;
        bool      flag = false;

        flag_j = lz_json_get_path(json, hdr_[i].key);

        if (flag_j != NULL) {
            flag = lz_json_get_boolean(flag_j);
        }

        hdr_[i].ldnsfn(pkt, flag);
    }

    {
        lz_json    * id_j;
        unsigned int id = 0;

        id_j = lz_json_get_path(json, "_id");

        if (id_j != NULL) {
            id = lz_json_get_number(id_j);
        }
    }

    {
        lz_json    * opcode_j;
        unsigned int opcode = 0;

        opcode_j = lz_json_get_path(json, "_opcode");

        if (opcode_j != NULL) {
            opcode = lz_json_get_number(opcode_j);
        }
    }

    {
        lz_json    * rcode_j;
        unsigned int rcode = 0;

        rcode_j = lz_json_get_path(json, "_rcode");

        if (rcode_j != NULL) {
            rcode = lz_json_get_number(rcode_j);
        }
    }

    struct {
        const char     * key;
        const char     * count;
        ldns_pkt_section sect;
    } rr_[] = {
        { "_question",   "_qdcount", LDNS_SECTION_QUESTION   },
        { "_answer",     "_ancount", LDNS_SECTION_ANSWER     },
        { "_authority",  "_nscount", LDNS_SECTION_AUTHORITY  },
        { "_additional", "_arcount", LDNS_SECTION_ADDITIONAL },
        { NULL,          NULL,       -1                      }
    };


    for (i = 0; rr_[i].key != NULL; i++) {
        lz_json * rr_list;
        size_t    rr_iter;
        size_t    rr_count;

        rr_list  = lz_json_get_path(json, rr_[i].key);
        rr_count = lz_json_get_number(lz_json_get_path(json, rr_[i].count));

        for (rr_iter = 0; rr_iter < rr_count; rr_iter++) {
            ldns_rr * rr;
            lz_json * rr_json;

            rr_json = lz_json_get_array_index(rr_list, rr_iter);

            json__to_rr_(&rr, rr_json);
            ldns_pkt_safe_push_rr(pkt, rr_[i].sect, rr);
        }
    }

    return pkt;
} /* ddrop_json_to_dns */

lz_json *
ddrop_dns_to_json(ldns_pkt * packet)
{
    char    * errstr;
    char    * opcode_s;
    char    * rcode_s;
    int       i;
    lz_json * packet_j;

    if (packet == NULL) {
        return NULL;
    }

    if ((packet_j = lz_json_object_new()) == NULL) {
        return NULL;
    }

    enum type__ {
        type__bool_,
        type__u16_,
        type__rrlist_,
        type__rr_,
        type__rdf_
    };

    /* this is a quick pre-initialized structure that we can use
     * to easily encode parts of the ldns_pkt into the matching
     * lz_json type.
     */
    struct {
        const char * k; /**< key to use in the json */
        enum type__  t; /**< the type that is returned from the ldns_pkt_X func */

        union {
            bool           (* bool_)(const ldns_pkt *);
            uint16_t       (* u16_)(const ldns_pkt *);
            ldns_rr_list * (* rrlist_)(const ldns_pkt *);
            ldns_rr      * (* rr_)(const ldns_pkt *);
            ldns_rdf     * (* rdf_)(const ldns_pkt *);
        };
    } fn_list[] = {
        { "_qr",         type__bool_,   .bool_   = ldns_pkt_qr         },
        { "_aa",         type__bool_,   .bool_   = ldns_pkt_aa         },
        { "_tc",         type__bool_,   .bool_   = ldns_pkt_tc         },
        { "_rd",         type__bool_,   .bool_   = ldns_pkt_rd         },
        { "_cd",         type__bool_,   .bool_   = ldns_pkt_cd         },
        { "_ra",         type__bool_,   .bool_   = ldns_pkt_ra         },
        { "_ad",         type__bool_,   .bool_   = ldns_pkt_ad         },
        { "_id",         type__u16_,    .u16_    = ldns_pkt_id         },
        { "_qdcount",    type__u16_,    .u16_    = ldns_pkt_qdcount    },
        { "_ancount",    type__u16_,    .u16_    = ldns_pkt_ancount    },
        { "_nscount",    type__u16_,    .u16_    = ldns_pkt_nscount    },
        { "_arcount",    type__u16_,    .u16_    = ldns_pkt_arcount    },
        { "_question",   type__rrlist_, .rrlist_ = ldns_pkt_question   },
        { "_answer",     type__rrlist_, .rrlist_ = ldns_pkt_answer     },
        { "_authority",  type__rrlist_, .rrlist_ = ldns_pkt_authority  },
        { "_additional", type__rrlist_, .rrlist_ = ldns_pkt_additional },
        { "_tsig_rr",    type__rr_,     .rr_     = ldns_pkt_tsig       },
        { "_answerfrom", type__rdf_,    .rdf_    = ldns_pkt_answerfrom },
        { "_edns_data",  type__rdf_,    .rdf_    = ldns_pkt_edns_data  },
        { NULL,          -1,            NULL }
    };

    /* iterate over the above data, call the function associated with the
     * `type`, and convert it to its native JSON type.
     */
    for (i = 0; fn_list[i].k != NULL; i++) {
        lz_json * j_ent;

        log_debug("key=%s", fn_list[i].k);

        switch (fn_list[i].t) {
            case type__bool_:
                j_ent = lz_json_boolean_new((fn_list[i].bool_)(packet));
                break;
            case type__u16_:
                j_ent = lz_json_number_new((fn_list[i].u16_)(packet));
                break;
            case type__rrlist_:
                j_ent = ddrop_dns_rr_list_to_json((fn_list[i].rrlist_)(packet));
                break;
            case type__rr_:
                j_ent = ddrop_dns_rr_to_json((fn_list[i].rr_)(packet));
                break;
            case type__rdf_:
                j_ent = ddrop_dns_rdf_to_json((fn_list[i].rdf_)(packet));
                break;
            default:
                log_error("unknown type");

                j_ent = NULL;
                break;
        } /* switch */

        if (j_ent != NULL) {
            lz_json_object_add(packet_j, fn_list[i].k, j_ent);
        } else {
            log_debug("j_ent == NULL");
        }
    }

    ldns_pkt_opcode opcode;
    ldns_pkt_rcode  rcode;

    opcode = ldns_pkt_get_opcode(packet);
    rcode  = ldns_pkt_get_rcode(packet);

    lz_json_object_add(packet_j, "_opcode",
                       lz_json_number_new(opcode));


    lz_json_object_add(packet_j, "_rcode",
                       lz_json_number_new(rcode));


    return packet_j;
}     /* ddrop_dnspkt_to_json */
