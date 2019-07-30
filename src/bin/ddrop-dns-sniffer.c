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
print_dns_packet(struct ddrop_pcap * cap, ldns_pkt * dns_packet) {
    lz_json * packet_j;


    if ((packet_j = ddrop_dns_to_json(dns_packet)) == NULL) {
        log_error("ddrop_dns_to_json failure");
        return 0;
    }

    ldns_pkt_print(stderr, dns_packet);
    lz_json_print(stderr, packet_j);

    ddrop_safe_free(packet_j, lz_json_free);

    return 0;
}

int
main(int argc, char ** argv)
{
    struct event_base * evbase;
    struct ddrop_pcap    * cap;

    evbase = event_base_new();
    cap    = ddrop_pcap_new(evbase, NULL);
    ddrop_assert(cap != NULL);

    ddrop_pcap_setcb(cap, print_dns_packet, NULL);
    ddrop_pcap_start(cap);

    event_base_loop(evbase, 0);
    /* stuff */

    return 0;
}
