#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>


#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define __FAVOR_BSD
#include <netinet/if_ether.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>
#include <unistd.h>

#include <event2/event.h>
#include <ldns/ldns.h>
#include <pcap/pcap.h>
#include <pcap/sll.h>


#include "ddrop/common.h"
#include "ddrop/core/log.h"
#include "ddrop/dns/sniff.h"

struct ddrop_pcap_packet {
    const struct pcap_pkthdr * _pkthdr;
    const u_char             * _full_packet;
    const u_char             * _payload;
    size_t                     _payload_len;

    uint8_t _l1_type;
    uint8_t _l2_type;
    uint8_t _l3_type;
    size_t  _l1_len;
    size_t  _l2_len;
    size_t  _l3_len;

    union {
        const struct sll_header   * _sll;
        const struct ether_header * _eth;
    } _l1;

    union {
        const struct ip      * _ip;
        const struct ip6_hdr * _ip6;
    } _l2;

    union {
        const struct udphdr * _udp;
        const struct tcphdr * _tcp;
    } _l3;

    const u_char * _l1_payload;
    const u_char * _l2_payload;
    const u_char * _l3_payload;
};

struct ddrop_pcap_dns {
    struct ddrop_pcap_packet * _packet;
    ldns_pkt                 * _dns_packet;
};



struct ddrop_pcap {
    struct ddrop_pcap_config _config;
    struct event_base      * _evbase;
    struct event           * _pcap_ev;
    int                      _pcap_fd;
    pcap_t                 * _pcap;
    int                      (* _callback)(struct ddrop_pcap * cap, ldns_pkt * pkt);
};

static void
pcap__config_free_(struct ddrop_pcap_config * config)
{
    if (config == NULL) {
        return;
    }

    ddrop_safe_free(config->_filter, free);
    ddrop_safe_free(config->_iface, free);
    ddrop_safe_free(config, free);
}

static void
pcap__free_(struct ddrop_pcap * cap)
{
    if (cap == NULL) {
        return;
    }

    ddrop_safe_free(cap->_pcap, pcap_close);
    ddrop_safe_free(cap->_pcap_ev, event_free);
}

static int
pcap__init_(struct ddrop_pcap ** out, struct ddrop_pcap_config * config)
{
    struct ddrop_pcap * cap;

    if (out == NULL) {
        return -1;
    }

    cap = (struct ddrop_pcap *)calloc(1, sizeof(*cap));

    if (config == NULL) {
        cap->_config._bufferlen = 2 * 1024;
        cap->_config._filter    = strdup("udp src port 53");
        cap->_config._iface     = strdup("any");
        cap->_config._snaplen   = 512;
    } else {
        cap->_config._bufferlen = config->_bufferlen;
        cap->_config._filter    = strdup(config->_filter);
        cap->_config._iface     = strdup(config->_iface);
        cap->_config._snaplen   = config->_snaplen;
    }


    *out = cap;

    return 0;
}

void
pcap__decode_dns_(struct ddrop_pcap * cap, struct ddrop_pcap_packet * packet)
{
    ldns_status status;
    ldns_pkt  * dns_packet;

    status = ldns_wire2pkt(&dns_packet, packet->_payload, packet->_payload_len);

    if (status != LDNS_STATUS_OK) {
        return;
    }

    if (cap->_callback != NULL) {
        (cap->_callback)(cap, dns_packet);
    }

    ldns_pkt_free(dns_packet);
}

void
pcap__pkt_handler_(u_char                   * arg,
                   const struct pcap_pkthdr * pkthdr,
                   const u_char             * packet)
{
    struct ddrop_pcap         * cap;
    bpf_u_int32                 length;
    bpf_u_int32                 caplen;
    u_int16_t                   ether_type;
    const u_char              * orig_packet;
    const struct ip           * ip_p;
    const struct ether_header * eth_p;
    const struct sll_header   * sll_p;
    const struct udphdr       * udp;
    const struct tcphdr       * tcp;
    uint16_t                    toff;
    uint32_t                    ip_hl;
    int                         datalink;
    struct ddrop_pcap_packet    ddrop_packet;

    cap = (struct ddrop_pcap *)arg;
    ddrop_assert(cap != NULL);


    orig_packet               = packet;
    caplen                    = pkthdr->caplen;
    length                    = pkthdr->len;
    datalink                  = pcap_datalink(cap->_pcap);

    ddrop_packet._pkthdr      = pkthdr;
    ddrop_packet._full_packet = packet;
    ddrop_packet._l1_type     = datalink;

    switch (datalink) {
        case DLT_LINUX_SLL:
            if (caplen < SLL_HDR_LEN || length < SLL_HDR_LEN) {
                return;
            }

            sll_p                    = (const struct sll_header *)packet;
            ether_type               = ntohs(sll_p->sll_protocol);

            length                  -= SLL_HDR_LEN;
            caplen                  -= SLL_HDR_LEN;
            packet                  += SLL_HDR_LEN;

            ddrop_packet._l1_len     = SLL_HDR_LEN;
            ddrop_packet._l1._sll    = sll_p;
            ddrop_packet._l1_payload = packet;

            break;
        case DLT_EN10MB:
            if (caplen < ETHER_HDR_LEN || length < ETHER_HDR_LEN) {
                return;
            }

            eth_p                    = (const struct ether_header *)packet;
            ether_type               = ntohs(eth_p->ether_type);

            length                  -= ETHER_HDR_LEN;
            caplen                  -= ETHER_HDR_LEN;
            packet                  += ETHER_HDR_LEN;

            ddrop_packet._l1_len     = ETHER_HDR_LEN;
            ddrop_packet._l1._eth    = eth_p;
            ddrop_packet._l1_payload = packet;

            break;
        default:
            return;
    } /* switch */

    while (ether_type == ETHERTYPE_VLAN) {
        if (caplen < 4 || length < 4) {
            return;
        }

        ether_type               = ntohs(*(unsigned short *)(packet + 2));

        length                  -= 4;
        caplen                  -= 4;
        packet                  += 4;

        ddrop_packet._l1_len    += 4;
        ddrop_packet._l1_payload = packet;
    }

    if (caplen < sizeof(struct ip) || length < sizeof(struct ip)) {
        return;
    }

    ddrop_packet._l2_type = ether_type;
    ip_p = (const struct ip *)packet;

    if (ip_p->ip_v != 4) {
        return;
    }

    ip_hl   = ip_p->ip_hl * 4;

    length -= ip_hl;
    caplen -= ip_hl;
    packet += ip_hl;

    ddrop_packet._l2._ip      = ip_p;
    ddrop_packet._l2_len      = ip_hl;
    ddrop_packet._l2_payload  = packet;
    ddrop_packet._payload     = packet;
    ddrop_packet._payload_len = length;
    ddrop_packet._l3_type     = ip_p->ip_p;

    switch (ip_p->ip_p) {
        case IPPROTO_TCP:
            tcp     = (struct tcphdr *)packet;
            toff    = tcp->th_off * 4;

            length -= toff;
            caplen -= toff;
            packet += toff;

            ddrop_packet._payload     = packet;
            ddrop_packet._payload_len = length;
            ddrop_packet._l3._tcp     = tcp;
            ddrop_packet._l3_payload  = packet;
            ddrop_packet._l3_len      = toff;

            break;
        case IPPROTO_UDP:
            udp     = (struct udphdr *)packet;

            length -= sizeof(struct udphdr);
            caplen -= sizeof(struct udphdr);
            packet += sizeof(struct udphdr);


            ddrop_packet._payload     = packet;
            ddrop_packet._payload_len = length;
            ddrop_packet._l3._udp     = udp;
            ddrop_packet._l3_payload  = packet;
            ddrop_packet._l3_len      = sizeof(struct udphdr);

            break;
    } /* switch */

    pcap__decode_dns_(cap, &ddrop_packet);
}     /* pcap__pkt_handler_ */

static void
pcap__decodecb_(int sock, short which, void * arg)
{
    struct ddrop_pcap * cap = (struct ddrop_pcap *)arg;

    (void)sock;
    (void)which;

    ddrop_assert(cap != NULL);

    pcap_dispatch(cap->_pcap, -1, (pcap_handler)pcap__pkt_handler_, (u_char *)arg);
}

static int
pcap__new_(struct ddrop_pcap ** out, struct event_base * base, struct ddrop_pcap_config * config)
{
    pcap_t            * pcap;
    struct ddrop_pcap * cap;
    char                errbuf[PCAP_ERRBUF_SIZE];
    char                error = 1;

    if (out == NULL || base == NULL) {
        return -1;
    }

    *out = NULL;

    if (pcap__init_(&cap, config) == -1) {
        return -1;
    }

    cap->_evbase = base;
    cap->_pcap   = pcap_open_live(cap->_config._iface, 128, 1, 1024, errbuf);
    /*cap->_pcap   = pcap_create(cap->_config._iface, errbuf); */

    if (cap->_pcap == NULL) {
        return -1;
    }

#if 0
    if (pcap_set_snaplen(cap->_pcap, cap->_config._snaplen)) {
        return -1;
    }

    if (pcap_set_promisc(cap->_pcap, 1)) {
        return -1;
    }

    if (pcap_set_timeout(cap->_pcap, -1)) {
        return -1;
    }

    if (pcap_set_buffer_size(cap->_pcap, cap->_config._bufferlen)) {
        return -1;
    }

#endif


    if (pcap_setnonblock(cap->_pcap, 1, errbuf) == -1) {
        return -1;
    }

    if (cap->_config._filter != NULL) {
        struct bpf_program filterp;

        if (pcap_compile(cap->_pcap, &filterp, cap->_config._filter, 1, PCAP_NETMASK_UNKNOWN) < 0) {
            return -1;
        }

        if (pcap_setfilter(cap->_pcap, &filterp)) {
            return -1;
        }
    }

    cap->_pcap_fd = pcap_get_selectable_fd(cap->_pcap);
    cap->_pcap_ev = event_new(base, cap->_pcap_fd, EV_READ | EV_PERSIST, pcap__decodecb_, cap);

    *out          = cap;

    return 0;
} /* pcap__init_ */

static int
pcap__start_(struct ddrop_pcap * cap)
{
    if (cap == NULL) {
        return -1;
    }

#if 0
    if (pcap_activate(cap->_pcap) < 0) {
        return -1;
    }

#endif

    return event_add(cap->_pcap_ev, NULL);
}

struct ddrop_pcap *
ddrop_pcap_new(struct event_base * base, struct ddrop_pcap_config * config)
{
    struct ddrop_pcap * ret = NULL;

    if (pcap__new_(&ret, base, config) == -1) {
        return NULL;
    }

    return ret;
}

int
ddrop_pcap_setcb(struct ddrop_pcap * cap, int (*cb)(struct ddrop_pcap *, ldns_pkt *), void * args)
{
    if (cap == NULL) {
        return -1;
    }

    cap->_callback = cb;

    return 0;
}

int
ddrop_pcap_start(struct ddrop_pcap * cap)
{
    return pcap__start_(cap);
}
