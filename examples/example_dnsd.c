#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <getopt.h>

#include <evhtp.h>
#include <ldns/ldns.h>
#include <event2/event.h>

#include "ddrop/common.h"
#include "ddrop/core/log.h"
#include "ddrop/dns/dnsd.h"

int
main(int argc, char ** argv) {
    struct event_base       * evbase;
    struct ddrop_dnsd_listener * dnsd;
    int                       res;

    evbase = event_base_new();
    ddrop_assert(evbase != NULL);

    dnsd   = ddrop_dnsd_listener_new(evbase, "127.0.0.5", 53, "lo");
    ddrop_assert(dnsd != NULL);

    res    = ddrop_dnsd_listener_start(dnsd);
    ddrop_assert(res == 0);

    event_base_loop(evbase, 0);

    return 0;
}
