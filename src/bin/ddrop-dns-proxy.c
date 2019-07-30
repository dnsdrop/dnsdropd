#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <getopt.h>

#include <event2/event.h>
#include <event2/thread.h>
#include <evhtp/thread.h>
#include <ldns/ldns.h>

#include "ddrop/common.h"
#include "ddrop/core/log.h"
#include "ddrop/dns/dnsd.h"
#include "ddrop/dns/json.h"
#include "ddrop/dns/resolver.h"


static char              * g_listen_addr       = "127.0.0.6";
static char              * g_listen_iface      = "lo";
static int                 g_listen_port       = 53;

static char              * g_https_host        = "127.0.0.1";
static int                 g_https_port        = 4453;
static char              * g_https_client_cert = NULL;
static char              * g_https_client_key  = NULL;

static evhtp_ssl_ctx_t   * g_ssl_ctx           = NULL;
static struct event_base * g_event_base        = NULL;

enum {
    OPTARG_CERT = 1000,
    OPTARG_KEY,
    OPTARG_ADDR,
    OPTARG_PORT,
    OPTARG_SNI
};

static int
process_request_(struct ddrop_dnsd_request * req, void * arg)
{
    ldns_pkt * question;
    ldns_pkt * answer;
    lz_json  * question_j;
    lz_json  * answer_j;

    question   = ddrop_dnsd_request_get_query(req);
    ddrop_assert(question != NULL);

    question_j = ddrop_dns_to_json(question);
    ddrop_assert(question_j != NULL);
}

int
main(int argc, char ** argv)
{
    struct ddrop_dnsd_listener * dnsd;
    struct ddrop_resolver_ctx  * resolver;
    int                          res;
    int                          opt;
    int                          long_index;

    static struct option         long_options[] = {
        { "cert", required_argument, 0, OPTARG_CERT },
        { "key",  required_argument, 0, OPTARG_KEY  },
        { "addr", required_argument, 0, OPTARG_ADDR },
        { "port", required_argument, 0, OPTARG_PORT },
        { "help", no_argument,       0, 'h'         },
        { NULL,   0,                 0, 0           }
    };

    while ((opt = getopt_long_only(argc, argv, "", long_options, &long_index)) != -1) {
        switch (opt) {
            case 'h':
                return 0;
            case OPTARG_CERT:
                g_https_client_cert = strdup(optarg);
                break;
            case OPTARG_KEY:
                g_https_client_key  = strdup(optarg);
                break;
            case OPTARG_ADDR:
                g_https_host        = strdup(optarg);
                break;
            case OPTARG_PORT:
                g_https_port        = atoi(optarg);
                break;
        }
    }

    g_event_base = event_base_new();
    ddrop_assert(g_event_base != NULL);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    g_ssl_ctx = SSL_CTX_new(SSLv23_client_method());
#else
    g_ssl_ctx = SSL_CTX_new(TLS_client_method());
#endif
    ddrop_assert(g_ssl_ctx != NULL);

    SSL_CTX_use_PrivateKey_file(g_ssl_ctx, g_https_client_key, SSL_FILETYPE_PEM);
    SSL_CTX_use_certificate_file(g_ssl_ctx, g_https_client_cert, SSL_FILETYPE_PEM);

    dnsd = ddrop_dnsd_listener_new(g_event_base, g_listen_addr, g_listen_port, g_listen_iface);
    ddrop_assert(dnsd != NULL);

    res  = ddrop_dnsd_listener_set_callback(dnsd, process_request_, NULL);
    ddrop_assert(res == 0);

    res  = ddrop_dnsd_listener_start(dnsd);
    ddrop_assert(res == 0);

    event_base_loop(g_event_base, 0);

    return 0;
} /* main */
