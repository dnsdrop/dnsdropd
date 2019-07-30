#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>

#include <ldns/ldns.h>

#include "ddrop/common.h"
#include "ddrop/core/log.h"
#include "ddrop/dns/json.h"

int
main(int argc, char ** argv)
{
    lz_json  * json_dns;
    ldns_pkt * packet;
    size_t     bytes_read;

    if (argc < 2) {
        log_error("usage: %s <file.json>", argv[0]);
        exit(EXIT_FAILURE);
    }

    if ((json_dns = lz_json_parse_file(argv[1], &bytes_read)) == NULL) {
        log_error("parse_file");
        exit(EXIT_FAILURE);
    }

    if ((packet = ddrop_json_to_dns(json_dns)) == NULL) {
        log_error("json_to_dns");
        exit(EXIT_FAILURE);
    }

    ldns_pkt_print(stdout, packet);
    ldns_pkt_free(packet);
    lz_json_free(json_dns);

    return 0;
}
