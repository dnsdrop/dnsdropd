#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>

#include <ldns/ldns.h>
#include <ldns/rr.h>

struct ddrop_dns_stat_entry {
    time_t         first_seen;
    time_t         last_seen;
    ldns_rr_list * records;
};
