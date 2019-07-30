/*
 * example usage of the libddrop_dnsResolver API.
 *
 * 1. create a resolver context
 * 2. enable notifications on the event_base
 * 3. make a dns request for IN A criticalstack.com.
 * 4. read the response in `resolver_callback_`
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <getopt.h>

#include <event2/event.h>
#include <event2/thread.h>
#include <evhtp/evhtp.h>
#include <ldns/ldns.h>

#include "ddrop/common.h"
#include "ddrop/dns/json.h"
#include "ddrop/core/log.h"

static int
print_header_(evhtp_header_t * header, void * arg)
{
    fprintf(stderr, "%s: %s\n", header->key, header->val);
    return 0;
}

static void
https_resp_(evhtp_request_t * req, void * arg)
{
    evhtp_headers_for_each(req->headers_in, print_header_, NULL);
    fprintf(stderr, "%d\n", req->status);

    if (evbuffer_get_length(req->buffer_in)) {
        fprintf(stderr, "got: %.*s\n",
                (int)evbuffer_get_length(req->buffer_in),
                evbuffer_pullup(req->buffer_in, -1));
    }

    /* since we only made one request, we break the event loop */
    event_base_loopbreak((struct event_base *)arg);
}

enum {
    OPTARG_CERT = 1000,
    OPTARG_KEY,
    OPTARG_ADDR,
    OPTARG_PORT,
    OPTARG_SNI
};

int
main(int argc, char ** argv)
{
    struct event_base  * evbase;
    evhtp_connection_t * conn;
    evhtp_request_t    * req;
    evhtp_ssl_ctx_t    * ctx;
    char               * addr           = NULL;
    uint16_t             port           = 4443;
    char               * key            = NULL;
    char               * crt            = NULL;
    int                  opt            = 0;
    int                  long_index     = 0;
    int                  res;

    static struct option long_options[] = {
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
                printf("Usage: %s\n"
                       " -key <private key>\n"
                       " -cert <cert>\n"
                       " -addr <x.x.x.x>\n"
                       " -port <port>\n", argv[0]);
                return 0;
            case OPTARG_CERT:
                crt  = strdup(optarg);
                break;
            case OPTARG_KEY:
                key  = strdup(optarg);
                break;
            case OPTARG_ADDR:
                addr = strdup(optarg);
                break;
            case OPTARG_PORT:
                port = atoi(optarg);
                break;
        } /* switch */
    }

    evbase = event_base_new();

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    ctx    = SSL_CTX_new(SSLv23_client_method());
#else
    ctx    = SSL_CTX_new(TLS_client_method());
#endif


    if (key) {
        /* client private key file defined, so use it */
        res = SSL_CTX_use_PrivateKey_file(
            ctx,
            key,
            SSL_FILETYPE_PEM);

        if (res == 0) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
    }

    if (crt) {
        /* client cert key file defined, use it */
        res = SSL_CTX_use_certificate_file(
            ctx,
            crt,
            SSL_FILETYPE_PEM);

        if (res == 0) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
    }

    /* create a new connection to the server */
    conn = evhtp_connection_ssl_new(evbase,
                                    addr ? : "127.0.0.1",
                                    port, ctx);

    /* when the request has been completed, call https_resp_ */
    req = evhtp_request_new(https_resp_, evbase);

    {
        /* make a dns packet */
        ldns_pkt * packet;
        lz_json  * packet_json;
        char       outbuf[1024] = { 0 };

        ldns_pkt_query_new_frm_str(
                &packet,
                "strcpy.net.",
                LDNS_RR_TYPE_A,
                LDNS_RR_CLASS_IN, 0);

        ldns_pkt_print(stderr, packet);

        /* convert dns packet to JSON layout */

        packet_json = ddrop_dns_to_json(packet);

        lz_json_to_buffer(packet_json, outbuf, sizeof(outbuf));
        fprintf(stderr, "%s\n", outbuf);

        evbuffer_add(req->buffer_out, outbuf, strlen(outbuf));
        ddrop_safe_free(packet_json, lz_json_free);

        printf("%s\n", evbuffer_pullup(req->buffer_out, -1));
    }



    /* make a request context, 'GET / HTTP/1.1' */
    res = evhtp_make_request(conn, req, htp_method_POST, "/_dns/");

    /* the loop will make the request and call https_resp_
     * when complete.
     */
    event_base_loop(evbase, 0);





    return 0;
} /* main */
