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

struct test_dns_config {
    char        * nameserver;
    char        * resolvconf;
    ldns_rr_type  type;
    ldns_rr_class class;
    char        * name;
};

static const char * help =
    "Usage %s [opts] <name>\n"
    "  -nameserver   <host>  : use a specific nameserver\n"
    "  -resolv-conf  <file>  : use a specific resolv.conf\n"
    "  -type         <type>  : DNS type to use\n"
    "  -class        <class> : DNS class to use\n";


static struct test_dns_config *
parse_arguments_(int argc, char ** argv)
{
    int                      opt        = 0;
    int                      long_index = 0;
    struct test_dns_config   cfg        = {
        .nameserver = NULL,
        .resolvconf = NULL,
        .type       = LDNS_RR_TYPE_A,
        .class      = LDNS_RR_CLASS_IN,
        .name       = "criticalstack.com."
    };
    struct test_dns_config * ret;


    static struct option     long_options[] = {
        { "nameserver",  required_argument, 0, 'n' },
        { "resolv-conf", required_argument, 0, 'r' },
        { "type",        required_argument, 0, 't' },
        { "class",       required_argument, 0, 'c' },
        { "help",        no_argument,       0, 'h' },
        { NULL,          0,                 0, 0   }
    };

    while ((opt = getopt_long_only(argc, argv, "n:r:t:c:h",
                                   long_options, &long_index)) != -1) {
        switch (opt) {
            case 'n':
                cfg.nameserver = strdup(optarg);
                break;
            case 'r':
                cfg.resolvconf = strdup(optarg);
                break;
            case 't':
                cfg.type       = ldns_get_rr_type_by_name(optarg);
                break;
            case 'c':
                cfg.class      = ldns_get_rr_class_by_name(optarg);
                break;
            case 'h':
                printf(help, argv[0]);
                exit(EXIT_SUCCESS);
            default:
                log_error("Unknown option %c", opt);
                exit(EXIT_FAILURE);
        } /* switch */
    }

    argc -= optind;
    argv += optind;

    if (argc == 0) {
        log_error("no name set (see -h)");
        exit(EXIT_FAILURE);
    }

    cfg.name = strdup(argv[0]);

    log_info("ns    = %s", cfg.nameserver);
    log_info("class = %d", cfg.class);
    log_info("type  = %d", cfg.type);
    log_info("name  = %s", cfg.name);

    ret = malloc(sizeof(cfg));
    memcpy(ret, &cfg, sizeof(cfg));

    return ret;
} /* parse_arguments_ */

static ldns_rdf *
rdf_addr_from_str_(char * str)
{
    ldns_rdf * a;

    if ((a = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, str)) == NULL) {
        if ((a = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, str)) == NULL) {
            log_error("new_frm_str AAAA");
            return NULL;
        }
    }

    return a;
}

int
main(int argc, char ** argv)
{
    struct test_dns_config * config;
    ldns_resolver          * resolver;
    ldns_rdf               * domain;
    ldns_pkt               * packet;
    ldns_status              res;
    lz_json                * packet_json = NULL;

    if ((config = parse_arguments_(argc, argv)) == NULL) {
        exit(EXIT_FAILURE);
    }

    if (config->nameserver) {
        ldns_rdf * ns_rdf;

        if ((resolver = ldns_resolver_new()) == NULL) {
            log_error("resolver_new()");
            exit(EXIT_FAILURE);
        }

        if ((ns_rdf = rdf_addr_from_str_(config->nameserver)) == NULL) {
            log_error("rdf_frm_str");
            exit(EXIT_FAILURE);
        }

        if (ldns_resolver_push_nameserver(resolver, ns_rdf) != LDNS_STATUS_OK) {
            log_error("push_nameserver");
            exit(EXIT_FAILURE);
        }
    } else {
        if (ldns_resolver_new_frm_file(&resolver, config->resolvconf) != LDNS_STATUS_OK) {
            log_error("res_new_frm_file");
            exit(EXIT_FAILURE);
        }
    }

    if ((domain = ldns_dname_new_frm_str(config->name)) == NULL) {
        log_error("dname_from_str");
        exit(EXIT_FAILURE);
    }

    if ((packet = ldns_resolver_search(resolver,
                                       domain,
                                       config->type,
                                       config->class,
                                       LDNS_RD)) == NULL) {
        log_error("resolver_search");
        exit(EXIT_FAILURE);
    }


    log_info("{{{{{{ DECODED RAW DNS PACKET RESPONSE }}}}}}");
    ldns_pkt_print(stderr, packet);

    {
        char    outbuf[4098];
        ssize_t outlen;

        if ((packet_json = ddrop_dns_to_json(packet)) == NULL) {
            log_error("dns_to_json");
            exit(EXIT_FAILURE);
        }


        log_info("{{{{{{ RAW DNS RESPONSE TO JSON OUTPUT }}}}}}");
        outlen = lz_json_to_buffer(packet_json, outbuf, sizeof(outbuf));

        fprintf(stdout, "%.*s\n", (int)outlen, outbuf);
    }

    ldns_pkt_free(packet);

    if ((packet = ddrop_json_to_dns(packet_json)) == NULL) {
        log_error("json_to_dns");
        exit(EXIT_FAILURE);
    }

    log_info("{{{{{{ JSON OUTPUT TO RAW DNS RESPONSE }}}}}}");
    ldns_pkt_print(stderr, packet);


    ldns_pkt_free(packet);
    lz_json_free(packet_json);

    return 0;
} /* main */
