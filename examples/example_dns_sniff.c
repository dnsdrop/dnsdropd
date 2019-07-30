#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>

#include <ldns/ldns.h>
#include <event2/event.h>

#include "ddrop/common.h"
#include "ddrop/core/log.h"
#include "ddrop/dns/json.h"
#include "ddrop/dns/sniff.h"

static int
print_dns_packet(struct ddrop_pcap * cap, ldns_pkt * dns_packet)
{
    ldns_pkt_print(stderr, dns_packet);

    return 0;
}

int
main(int argc, char ** argv)
{
    struct event_base * evbase;
    struct ddrop_pcap * cap;

    evbase = event_base_new();
    cap    = ddrop_pcap_new(evbase, NULL);
    ddrop_assert(cap != NULL);

    ddrop_pcap_setcb(cap, print_dns_packet, NULL);
    ddrop_pcap_start(cap);

    event_base_loop(evbase, 0);

    return 0;
}
