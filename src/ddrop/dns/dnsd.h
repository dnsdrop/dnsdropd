#pragma once
#include <ddrop/common.h>
#include <event2/event.h>
#include <ldns/ldns.h>

struct ddrop_dnsd_listener;
struct ddrop_dnsd_request;

typedef int (* ddrop_dnsd_requestcb)(struct ddrop_dnsd_request *, void *);

CS__EXPORT struct ddrop_dnsd_listener * ddrop_dnsd_listener_new(struct event_base *, char *, uint16_t, const char * dev);
CS__EXPORT int                       ddrop_dnsd_listener_set_callback(struct ddrop_dnsd_listener *, ddrop_dnsd_requestcb, void *);
CS__EXPORT int                       ddrop_dnsd_listener_start(struct ddrop_dnsd_listener *);
CS__EXPORT int                       ddrop_dnsd_request_queue(struct ddrop_dnsd_request *);
CS__EXPORT int                       ddrop_dnsd_response_queue(struct ddrop_dnsd_request *, ldns_pkt *);
CS__EXPORT ldns_pkt                * ddrop_dnsd_request_get_query(struct ddrop_dnsd_request *);
