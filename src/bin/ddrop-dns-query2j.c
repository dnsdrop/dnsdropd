#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <getopt.h>

#include <ldns/ldns.h>

#include "ddrop/common.h"
#include "ddrop/core/log.h"
#include "ddrop/dns/json.h"

static const char * help =
    "Usage %s [opts] <rr_name>\n"
    "  -class 'class' : Class of the query  (default: IN)  \n"
    "  -type  'type'  : Type of query       (default: A )  \n"
    "  -rd            : Recursion Desired   (default: ON)  \n"
    "  -qr            : Query response      (default: OFF) \n"
    "  -aa            : Auth Answer         (default: OFF) \n"
    "  -tc            : Truncated           (default: OFF) \n"
    "  -ra            : Recursion Available (default: OFF) \n"
    "  -ad            : Authenticated Data  (default: OFF) \n";

struct csos_dns_query2j {
    char        * rr_name;
    ldns_rr_type  rr_type;
    ldns_rr_class rr_class;
    uint16_t      rr_flags;
};

static struct csos_dns_query2j *
parse__arguments_(int argc, char ** argv)
{
    int                     opt        = 0;
    int                     long_index = 0;
    struct csos_dns_query2j q          = {
        .rr_name  = NULL,
        .rr_type  = LDNS_RR_TYPE_A,
        .rr_class = LDNS_RR_CLASS_IN,
        .rr_flags = 0
    };

    static struct option    long_options[] = {
        { "type",  required_argument, 0, 't' },
        { "class", required_argument, 0, 'c' },
        { "rd",    no_argument,       0, 'r' },
        { "qr",    no_argument,       0, 'q' },
        { "aa",    no_argument,       0, 'a' },
        { "tc",    no_argument,       0, 'T' },
        { "ra",    no_argument,       0, 'R' },
        { "ad",    no_argument,       0, 'A' },
        { "help",  no_argument,       0, 'h' },
        { NULL,    0,                 0, 0   }
    };

    while ((opt = getopt_long_only(argc, argv, "t:c:rqatRATh",
                                   long_options, &long_index)) != -1) {
        switch (opt) {
            case 't':
                q.rr_type   = ldns_get_rr_type_by_name(optarg);
                break;
            case 'c':
                q.rr_class  = ldns_get_rr_class_by_name(optarg);
                break;
            case 'r':
                q.rr_flags |= LDNS_RD;
                break;
            case 'q':
                q.rr_flags |= LDNS_QR;
                break;
            case 'a':
                q.rr_flags |= LDNS_AA;
                break;
            case 'T':
                q.rr_flags |= LDNS_TC;
                break;
            case 'R':
                q.rr_flags |= LDNS_RA;
                break;
            case 'A':
                q.rr_flags |= LDNS_AD;
                break;
            case 'h':
            default:
                printf(help, argv[0]);
                exit(EXIT_SUCCESS);
        } /* switch */
    }

    argc -= optind;
    argv += optind;

    if (argc == 0) {
        log_error("no rr_name");
        exit(EXIT_FAILURE);
    }

    /* make sure at least LDNS_RA is enabled */
    if (q.rr_flags == 0) {
        q.rr_flags = LDNS_RD;
    }

    return mm__alloc_(struct csos_dns_query2j, {
        .rr_type  = q.rr_type,
        .rr_class = q.rr_class,
        .rr_flags = q.rr_flags,
        .rr_name  = strdup(argv[0])
    });
} /* parse_arguments_ */

int
main(int argc, char ** argv)
{
    struct csos_dns_query2j * query;
    ldns_pkt                * packet;

    if (!(query = parse__arguments_(argc, argv))) {
        exit(EXIT_FAILURE);
    }

    if (ldns_pkt_query_new_frm_str(
            &packet,
            query->rr_name,
            query->rr_type,
            query->rr_class,
            query->rr_flags) != LDNS_STATUS_OK) {
        log_error("pkt_query_frm_str");
        exit(EXIT_FAILURE);
    }

    ldns_pkt_print(stderr, packet);

    {
        lz_json * packet_j;

        if (!(packet_j = ddrop_dns_to_json(packet))) {
            log_error("dns_to_json");
            exit(EXIT_FAILURE);
        }

        lz_json_fprintf(stdout, packet_j);

        lz_json_free(packet_j);
    }

    ddrop_safe_free(packet, ldns_pkt_free);
    ddrop_safe_free(query->rr_name, free);
    ddrop_safe_free(query, free);

    return 0;
} /* main */
