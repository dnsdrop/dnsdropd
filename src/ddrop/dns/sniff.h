#pragma once

#include <event2/event.h>
#include <ldns/ldns.h>

struct ddrop_pcap_config {
    char * _iface;
    char * _filter;
    int    _bufferlen;
    int    _snaplen;
};


struct ddrop_pcap * ddrop_pcap_new(struct event_base * base, struct ddrop_pcap_config * cfg);
int                 ddrop_pcap_start(struct ddrop_pcap * cap);
int                 ddrop_pcap_setcb(struct ddrop_pcap *, int (*)(struct ddrop_pcap *, ldns_pkt *), void *);
