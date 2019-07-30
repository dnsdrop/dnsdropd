#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>

#include <sys/queue.h>
#include <event2/event.h>
#include <ldns/ldns.h>

struct ddrop_dnscache_ent {
    uint32_t hash;            /* hash of rr */
    void   * key;             /* pkt->rrlist[0]->_owner->_data */

    struct event_base * evbase;
    struct event      * timeout_ev;
    ldns_pkt          * answer;

    TAILQ_ENTRY(ddrop_dnscache_ent) next;
};

