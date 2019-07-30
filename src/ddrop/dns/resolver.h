#pragma once

struct ddrop_resolver_ctx;
struct ddrop_resolver_request;

typedef int (* ddrop_resolver_cb)(struct ddrop_resolver_request *, void *);


/**
 * @brief create a new resolver context. This is our main (non-blocking)
 *        loop for making async-requests.
 *
 * @param evbase an event_base with locking and notifications enabled
 * @param rconf  alternative resolv.conf
 *
 * @return NULL on error
 */
CS__EXPORT struct ddrop_resolver_ctx * ddrop_resolver_ctx_new(struct event_base * evbase, const char * rconf);


/**
 * @brief free up all the resources contained within the resolver context
 *
 * @param ctx
 *
 * @return
 */
CS__EXPORT void ddrop_resolver_ctx_free(struct ddrop_resolver_ctx * ctx);


/**
 * @brief starts up all the async workers and other misc events
 *
 * @param ctx
 *
 * @return 0 on success, -1 on error
 */
CS__EXPORT int ddrop_resolver_ctx_start(struct ddrop_resolver_ctx * ctx);


/**
 * @brief creates a raw request structure. Generally, this is not used
 *        instead the below functions are wrappers around this.
 *
 * @param ctx
 *
 * @return NULL on error
 */
CS__EXPORT struct ddrop_resolver_request * ddrop_resolver_request_new(struct ddrop_resolver_ctx * ctx);


/**
 * @brief free the request structure and all of its decendents.
 *
 * @param req
 *
 * @return
 */
CS__EXPORT void ddrop_resolver_request_free(struct ddrop_resolver_request * req);


/**
 * @brief when a dns_pkt has already been created, this is used to process
 *        that query in an async-like manner.
 *
 * @param ctx the resolver context
 * @param pkt the ldns packet
 * @param cb  function to call when the response has been processed
 * @param args arguments passed to the callback
 *
 * @return 0 on success, -1 on error
 */
CS__EXPORT int ddrop_resolver_send_pkt(struct ddrop_resolver_ctx * ctx,
                                       ldns_pkt * pkt, ddrop_resolver_cb cb, void * args);


/**
 * @brief do an async-lookup of a host -> ip[6] addr
 *
 * @param ctx the resolver context
 * @param name the hostname to lookup
 * @param type the type (AF_INET[6])
 * @param ddrop_resolver_cb function to call when the response has been proccessed
 * @param args arguments passed to the callback
 *
 * @return 0 on success, -1 on error
 */
CS__EXPORT int         ddrop_resolver_gethostbyname(struct ddrop_resolver_ctx *,
                                                    const char *, int type, ddrop_resolver_cb, void *);


CS__EXPORT ldns_pkt  * ddrop_resolver_request_get_q_packet(struct ddrop_resolver_request * req);
CS__EXPORT ldns_pkt  * ddrop_resolver_request_get_a_packet(struct ddrop_resolver_request * req);
CS__EXPORT ldns_status ddrop_resolver_request_get_status(struct ddrop_resolver_request * req);
