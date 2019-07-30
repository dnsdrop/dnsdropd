#pragma once

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <event2/event.h>
#include <ldns/ldns.h>

struct ddrop_dns_shim;

struct ddrop_dns_shim_cfg {
    char   * bind_addr;
    uint16_t bind_port;
    int      sock_type;
};

typedef int (* ddrop_dns_shim_cb)(struct ddrop_dns_shim *, lz_json *, struct sockaddr_storage *, void *);

CS__EXPORT struct ddrop_dns_shim * ddrop_dns_shim_new(struct event_base *, struct ddrop_dns_shim_cfg *);
CS__EXPORT int                  ddrop_dns_shim_set_callback(struct ddrop_dns_shim *, ddrop_dns_shim_cb, void *);
CS__EXPORT int                  ddrop_dns_shim_start(struct ddrop_dns_shim *);
CS__EXPORT void                 ddrop_dns_shim_free(struct ddrop_dns_shim *);

CS__EXPORT struct event_base * ddrop_dns_shim_get_evbase(struct ddrop_dns_shim *);
CS__EXPORT struct event      * ddrop_dns_shim_get_event(struct ddrop_dns_shim *);
CS__EXPORT evutil_socket_t     ddrop_dns_shim_get_sock(struct ddrop_dns_shim *);
