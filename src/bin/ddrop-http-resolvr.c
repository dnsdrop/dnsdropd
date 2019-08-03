#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <getopt.h>
#include <pthread.h>

#include <event2/event.h>
#include <event2/thread.h>
#include <evhtp/evhtp.h>
#include <evhtp/thread.h>
#include <evhtp/sslutils.h>
#include <ldns/ldns.h>

#include "ddrop/common.h"
#include "ddrop/core/log.h"
#include "ddrop/dns/json.h"
#include "ddrop/dns/resolver.h"

enum {
    OPTARG_CERT = 1000,
    OPTARG_KEY,
    OPTARG_CA,
    OPTARG_VERIFY_PEER,
    OPTARG_VERIFY_DEPTH,
    OPTARG_RESOLV_CONF,
    OPTARG_BIND_ADDR,
    OPTARG_BIND_PORT,
    OPTARG_USE_HTTP,
    OPTARG_CONN_CLOSE,
};

struct http_resolvr_cfg {
    char   * _pub_crt;
    char   * _prv_key;
    char   * _ca_file;
    int      _verify_client;
    int      _verify_depth;
    char   * _listen_addr;
    uint16_t _listen_port;
    char   * _resolv_conf;
    int      _use_http;
    int      _conn_closed;
};


struct query_stats {
    uint64_t total_queries;
    uint64_t total_answers;
    uint64_t total_errors;
    time_t   first_query;
    time_t   last_query;
    uint64_t response[LDNS_RCODE_NOTZONE + 1];
};

struct resolver {
    struct event_base         * evbase;
    struct evhtp              * htp;
    struct http_resolvr_cfg   * config;
    struct ddrop_resolver_ctx * rctx;
    struct query_stats        * stats;
    pthread_mutex_t             m;
};

struct query {
    struct resolver * resolvr;
    evhtp_request_t * http_req;
};

static struct query_stats *
query_stats_new(void)
{
    struct query_stats * s = calloc(1, sizeof(struct query_stats));

    if (s == NULL) {
        return NULL;
    }

    return s;
}

static const char * help =
    "  -ssl-cert <file>\n"
    "      Specifies  a  `file` with the certificate in the PEM\n"
    "      format for the http-resolvr  daemon. If intermediate\n"
    "      certificates  should  be  specified in addition to a\n"
    "      primary certificate, they should be specified in the\n"
    "      same file in the following order:\n"
    "        1. primary certificate\n"
    "        2. intermediate certificate\n\n"
    "      A  secret key in the PEM format may be placed in the\n"
    "      same file.\n\n"
    "  -ssl-cert-key <file>\n"
    "      Specifies  a  `file`  with the secret key in the PEM\n"
    "      format\n\n"

    "  -ssl-trusted-certificate <file>\n"
    "      Specifies  a `file` with trusted CA certs in the PEM\n"
    "      format used to verify client certificates.        \n\n"

    "  -ssl-verify-client (on | off | optional)                \n"
    "      Enables verification of client certificates.        \n"
    "        on       : the client has to present a valid cert \n"
    "        off      : no client cert is required at all      \n"
    "        optional : the client may present a valid cert  \n\n"

    "  -ssl-verify-depth <number>                              \n"
    "      Set verification depth in the client cert chain   \n\n"

    "  -listen-addr (ipv6:[::] | ipv4:X.X.X.X | unix:spath   \n\n"
    "  -listen-port port                                       \n"
    "      Port to listen on (ignored if type is `unix:`     \n\n"

    "  -resolv-conf <file>                                     \n"
    "      Alternative resolv.conf (default /etc/resolv.conf)\n\n"
    "  -use-http                                             \n\n";


static int
validate_config_(struct http_resolvr_cfg * cfg, const char ** errstr)
{
    struct stat estat;

    if (cfg == NULL) {
        *errstr = "config is null";
        return -1;
    }

    if (cfg->_use_http == 0) {
        if (!cfg->_pub_crt && !cfg->_prv_key) {
            *errstr = "cert and key are null";
            return -1;
        }

        if (cfg->_verify_client == -1) {
            *errstr = "invalid ssl-verify-client value";
            return -1;
        }

        if (cfg->_verify_client && !cfg->_verify_depth) {
            *errstr = "ssl-verify-depth must be > 0";
            return -1;
        }

        if (cfg->_pub_crt && stat(cfg->_pub_crt, &estat) == -1) {
            *errstr = "_pub_crt";
            return -1;
        }

        if (cfg->_prv_key && stat(cfg->_prv_key, &estat) == -1) {
            *errstr = "_prv_key";
            return -1;
        }

        if (cfg->_ca_file && stat(cfg->_ca_file, &estat) == -1) {
            *errstr = "_ca_file";
            return -1;
        }
    }

    return 0;
} /* validate_config_ */

static evhtp_ssl_cfg_t *
resolver_cfg2ssl_cfg_(struct http_resolvr_cfg * r_cfg)
{
    return mm__alloc_(evhtp_ssl_cfg_t, {
        .pemfile      = r_cfg->_pub_crt,
        .privfile     = r_cfg->_prv_key,
        .cafile       = r_cfg->_ca_file,
        .verify_peer  = r_cfg->_verify_client,
        .verify_depth = r_cfg->_verify_depth
    });
}

static struct http_resolvr_cfg *
parse_arguments_(int argc, char ** argv)
{
    struct http_resolvr_cfg * config;
    char                    * resolv_conf    = NULL;
    char                    * cert           = NULL;
    char                    * cert_key       = NULL;
    char                    * ca_file        = NULL;
    char                    * verify_client  = NULL;
    int                       verify_depth   = 0;
    char                    * bind_addr      = NULL;
    uint16_t                  bind_port      = 0;
    int                       long_index     = 0;
    int                       opt            = 0;
    const char              * errstr         = NULL;
    int                       use_http       = 0;
    int                       conn_closed    = 0;

    static struct option      long_options[] = {
        { "ssl-cert",                required_argument, 0, OPTARG_CERT         },
        { "ssl-cert-key",            required_argument, 0, OPTARG_KEY          },
        { "ssl-trusted-certificate", required_argument, 0, OPTARG_CA           },
        { "ssl-verify-client",       required_argument, 0, OPTARG_VERIFY_PEER  },
        { "ssl-verify-depth",        required_argument, 0, OPTARG_VERIFY_DEPTH },
        { "listen-addr",             required_argument, 0, OPTARG_BIND_ADDR    },
        { "listen-port",             required_argument, 0, OPTARG_BIND_PORT    },
        { "resolv-conf",             required_argument, 0, OPTARG_RESOLV_CONF  },
        { "use-http",                no_argument,       0, OPTARG_USE_HTTP     },
        { "conn-close",              no_argument,       0, OPTARG_CONN_CLOSE   },
        { "help",                    no_argument,       0, 'h'                 },
        { NULL,                      0,                 0, 0                   },
    };

    while ((opt = getopt_long_only(argc, argv, "", long_options, &long_index)) != -1) {
        switch (opt) {
            case OPTARG_RESOLV_CONF:
                resolv_conf   = strdup(optarg);
                break;
            case OPTARG_CERT:
                cert          = strdup(optarg);
                break;
            case OPTARG_KEY:
                cert_key      = strdup(optarg);
                break;
            case OPTARG_CA:
                ca_file       = strdup(optarg);
                break;
            case OPTARG_VERIFY_PEER:
                verify_client = strdup(optarg);
                break;
            case OPTARG_VERIFY_DEPTH:
                verify_depth  = atoi(optarg);
                break;
            case OPTARG_BIND_ADDR:
                bind_addr     = strdup(optarg);
                break;
            case OPTARG_BIND_PORT:
                bind_port     = atoi(optarg);
                break;
            case OPTARG_CONN_CLOSE:
                conn_closed   = 1;
                break;
            case OPTARG_USE_HTTP:
                use_http      = 1;
                break;
            case 'h':
            default:
                fprintf(stdout, "Usage: %s [opts]\n%s", argv[0], help);
                exit(EXIT_SUCCESS);
        } /* switch */
    }

    config = mm__alloc_(struct http_resolvr_cfg, {
        ._pub_crt       = cert,
        ._prv_key       = cert_key,
        ._ca_file       = ca_file,
        ._verify_client = htp_sslutil_verify2opts(verify_client),
        ._verify_depth  = verify_depth ? : 1,
        ._listen_addr   = bind_addr ? : strdup("127.0.0.1"),
        ._listen_port   = bind_port ? : 44353,
        ._resolv_conf   = resolv_conf,
        ._use_http      = use_http,
        ._conn_closed   = conn_closed,
    });

    if (validate_config_(config, &errstr) == -1) {
        log_error("Error validating configuration: %s (%s)",
            errstr, strerror(errno));

        ddrop_safe_free(config->_pub_crt, free);
        ddrop_safe_free(config->_prv_key, free);
        ddrop_safe_free(config->_ca_file, free);
        ddrop_safe_free(config->_listen_addr, free);
        ddrop_safe_free(config->_resolv_conf, free);
        ddrop_safe_free(config, free);
    }

    return config;
} /* parse_arguments_ */

#include <zlib.h>

static int
resolver_callback_(struct ddrop_resolver_request * req, void * args)
{
    struct query    * query;
    struct resolver * resolvr;
    evhtp_request_t * request;
    ldns_pkt        * answer_pkt;
    evhtp_res         res;

    query   = (struct query *)args;
    ddrop_assert(query != NULL);

    resolvr = query->resolvr;
    ddrop_assert(resolvr != NULL);

    request = (evhtp_request_t *)query->http_req;
    ddrop_assert(request != NULL);

    if (!(answer_pkt = ddrop_resolver_request_get_a_packet(req))) {
        evbuffer_add_printf(request->buffer_out,
            "{\"error\":\"%s\"}",
            ldns_get_errorstr_by_id(
                ddrop_resolver_request_get_status(req)));

        res = EVHTP_RES_PRECONDFAIL;
    } else {
        lz_json * answer_json;
        char      outbuf[65535] = { 0 };
        size_t    outlen;

        answer_json = ddrop_dns_to_json(answer_pkt);
        ddrop_assert(answer_json != NULL);

        outlen      = lz_json_to_buffer(answer_json,
            outbuf, sizeof(outbuf));

        fprintf(stdout, "%.*s\n", (int)outlen, outbuf);
        fflush(stdout);

        do {
            const char * encoding = evhtp_header_find(request->headers_in, "accept-encoding");

            if (encoding == NULL) {
                break;
            }

            if (strstr(encoding, "gzip") == NULL) {
                break;
            }

            z_stream ctx = { 0 };
            char     gzipbuf[outlen];

            ctx.zalloc = Z_NULL;
            ctx.zfree  = Z_NULL;
            ctx.opaque = Z_NULL;

            if (deflateInit2(&ctx, Z_BEST_COMPRESSION, Z_DEFLATED, (15 + 16), MAX_MEM_LEVEL,
                    Z_DEFAULT_STRATEGY) != Z_OK) {
                log_warn("deflateInit2 error: %s", strerror(errno));
                break;
            }

            ctx.next_in   = (unsigned char *)outbuf;
            ctx.avail_in  = outlen;
            ctx.next_out  = (unsigned char *)gzipbuf;
            ctx.avail_out = outlen;

            int ret;

            ret = deflate(&ctx, Z_FINISH);

            if (ret != Z_STREAM_END) {
                log_warn("deflate != stream_end %d", ret);
                (void)deflateEnd(&ctx);
                break;
            }

            outlen = outlen - ctx.avail_out;
            memcpy(outbuf, gzipbuf, outlen);

            (void)deflateEnd(&ctx);

            evhtp_headers_add_header(request->headers_out,
                evhtp_header_new("Content-Encoding", "gzip", 0, 0));
        } while (0);


        evhtp_headers_add_header(request->headers_out,
                evhtp_header_new("Content-Type", "application/dnsdrop-json", 0, 0));
        evbuffer_add(request->buffer_out, outbuf, outlen);

        ddrop_safe_free(answer_json, lz_json_free);

        res = EVHTP_RES_OK;
    }

    pthread_mutex_lock(&resolvr->m);
    {
        resolvr->stats->total_answers += 1;

        if (answer_pkt) {
            ldns_pkt_rcode rcode;

            rcode = ldns_pkt_get_rcode(answer_pkt);

            if (rcode != LDNS_RCODE_NOERROR) {
                resolvr->stats->total_errors += 1;
            }

            if (rcode <= LDNS_RCODE_NOTZONE) {
                resolvr->stats->response[rcode] += 1;
            }
        } else {
            resolvr->stats->total_errors += 1;
        }
    }
    pthread_mutex_unlock(&resolvr->m);


    ddrop_safe_free(req, ddrop_resolver_request_free);
    ddrop_safe_free(query, free);

    evhtp_request_resume(request);
    evhtp_send_reply(request, res);

    return 0;
} /* resolver_callback_ */

static void
http_stats_handler_(evhtp_request_t * request, void * arg)
{
    struct resolver * resolvr;

    resolvr = (struct resolver *)arg;
    ddrop_assert(resolvr != NULL);

    pthread_mutex_lock(&resolvr->m);
    {
        evbuffer_add_printf(request->buffer_out,
                "{\"queries\":%zu,"
                "\"answers\":%zu,"
                "\"errors\":{\"total\":%zu,"
                "\"formmerr\":%zu,"
                "\"servfail\":%zu,"
                "\"nxdomain\":%zu,"
                "\"notimpl\":%zu,"
                "\"refused\":%zu,"
                "\"yxdomain\":%zu,"
                "\"yxrrset\":%zu,"
                "\"nxrrset\":%zu,"
                "\"notauth\":%zu,"
                "\"notzone\":%zu},"
                "\"first_query\":%lu,"
                "\"last_query\":%lu}",
                resolvr->stats->total_queries,
                resolvr->stats->total_answers,
                resolvr->stats->total_errors,
                resolvr->stats->response[LDNS_RCODE_FORMERR],
                resolvr->stats->response[LDNS_RCODE_SERVFAIL],
                resolvr->stats->response[LDNS_RCODE_NXDOMAIN],
                resolvr->stats->response[LDNS_RCODE_NOTIMPL],
                resolvr->stats->response[LDNS_RCODE_REFUSED],
                resolvr->stats->response[LDNS_RCODE_YXDOMAIN],
                resolvr->stats->response[LDNS_RCODE_YXRRSET],
                resolvr->stats->response[LDNS_RCODE_NXRRSET],
                resolvr->stats->response[LDNS_RCODE_NOTAUTH],
                resolvr->stats->response[LDNS_RCODE_NOTZONE],
                resolvr->stats->first_query,
                resolvr->stats->last_query);
    }
    pthread_mutex_unlock(&resolvr->m);

    evhtp_send_reply(request, EVHTP_RES_OK);
} /* http_stats_handler_ */

static void
http_request_handler_(evhtp_request_t * request, void * arg)
{
    struct resolver           * resolvr;
    struct ddrop_resolver_ctx * resolver_ctx;
    size_t                      buffer_len;
    unsigned char             * buffer;
    size_t                      n_read;
    ldns_pkt                  * query_pkt;
    lz_json                   * query_json;
    struct timeval              tv;
    struct query              * query;

    resolvr      = (struct resolver *)arg;
    ddrop_assert(resolvr != NULL);

    resolver_ctx = resolvr->rctx;
    ddrop_assert(resolver_ctx != NULL);

    buffer_len   = evbuffer_get_length(request->buffer_in);
    buffer       = evbuffer_pullup(request->buffer_in, buffer_len);

    if (buffer_len == 0) {
        return evhtp_send_reply(request, 500);
    }

    if (!(query_json = lz_json_parse_buf((const char *)buffer, buffer_len, &n_read))) {
        return evhtp_send_reply(request, EVHTP_RES_SERVERR);
    }

    if (!(query_pkt = ddrop_json_to_dns(query_json))) {
        ddrop_safe_free(query_json, lz_json_free);

        return evhtp_send_reply(request, EVHTP_RES_SERVERR);
    }

    query           = malloc(sizeof(*query));
    ddrop_assert(query != NULL);

    query->resolvr  = resolvr;
    query->http_req = request;

    if (ddrop_resolver_send_pkt(resolver_ctx,
            query_pkt, resolver_callback_, query) == -1) {
        ddrop_safe_free(query_json, lz_json_free);
        ddrop_safe_free(query_pkt, ldns_pkt_free);
        ddrop_safe_free(query, free);

        return evhtp_send_reply(request, EVHTP_RES_SERVERR);
    }

    ddrop_safe_free(query_json, lz_json_free);

    event_base_gettimeofday_cached(resolvr->evbase, &tv);

    pthread_mutex_lock(&resolvr->m);
    {
        if (resolvr->stats->first_query == 0) {
            resolvr->stats->first_query = (time_t)tv.tv_sec;
        }

        resolvr->stats->last_query     = (time_t)tv.tv_sec;
        resolvr->stats->total_queries += 1;
    }
    pthread_mutex_unlock(&resolvr->m);

    return evhtp_request_pause(request);
} /* http_request_handler_ */

int
main(int argc, char ** argv)
{
    struct resolver * resolvr;
    evhtp_ssl_cfg_t * ssl_config;
    int               res;

    resolvr        = calloc(1, sizeof(*resolvr));
    ddrop_assert(resolvr != NULL);

    resolvr->stats = query_stats_new();
    ddrop_assert(resolvr->stats != NULL);

    pthread_mutex_init(&resolvr->m, NULL);

    resolvr->config = parse_arguments_(argc, argv);
    ddrop_assert(resolvr->config != NULL);

    ssl_config      = resolver_cfg2ssl_cfg_(resolvr->config);
    ddrop_assert(ssl_config != NULL);

    res = evthread_use_pthreads();
    ddrop_assert(res != -1);

    resolvr->evbase = event_base_new();
    ddrop_assert(resolvr->evbase != NULL);

    res           = evthread_make_base_notifiable(resolvr->evbase);
    ddrop_assert(res != -1);

    resolvr->rctx = ddrop_resolver_ctx_new(resolvr->evbase,
            resolvr->config->_resolv_conf);
    ddrop_assert(resolvr->rctx != NULL);

    resolvr->htp        = evhtp_new(resolvr->evbase, NULL);
    ddrop_assert(resolvr->htp != NULL);

    resolvr->htp->flags = EVHTP_FLAG_ENABLE_ALL;

    res = ddrop_resolver_ctx_start(resolvr->rctx);
    ddrop_assert(res != -1);

    if (resolvr->config->_use_http == 0) {
        res = evhtp_ssl_init(resolvr->htp, ssl_config);
        ddrop_assert(res != -1);
    }

    evhtp_set_cb(resolvr->htp, "/_stats/",
            http_stats_handler_, resolvr);

    evhtp_set_cb(resolvr->htp, "/_dns/",
             http_request_handler_, resolvr);

    res = evhtp_bind_socket(resolvr->htp,
            resolvr->config->_listen_addr,
            resolvr->config->_listen_port, SOMAXCONN);
    ddrop_assert(res != -1);

    return event_base_loop(resolvr->evbase, 0);
} /* main */
