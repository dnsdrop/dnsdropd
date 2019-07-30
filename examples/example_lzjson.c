#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <stdbool.h>

#include <liblz.h>
#include <liblz/lz_json.h>

#include "ddrop/core/log.h"

static int
json__example_object_(void)
{
    lz_json * json_obj;
    lz_json * json_arr;
    char      outbuf[1024];
    ssize_t   outlen;

    if ((json_obj = lz_json_object_new()) == NULL) {
        return -1;
    }

    if ((json_arr = lz_json_array_new()) == NULL) {
        return -1;
    }


    lz_json_array_add(json_arr, lz_json_number_new(1));
    lz_json_array_add(json_arr, lz_json_number_new(2));
    lz_json_array_add(json_arr, lz_json_number_new(3));
    lz_json_array_add(json_arr, lz_json_boolean_new(true));

    if (lz_json_object_add(json_obj, "foo",
                           lz_json_string_new("bar")) == -1) {
        return -1;
    }

    if (lz_json_object_add(json_obj, "array", json_arr) == -1) {
        return -1;
    }

    outlen = lz_json_to_buffer(json_obj, outbuf, sizeof(outbuf));

    log_info("%.*s", (int)outlen, outbuf);

    return 0;
}

int
main(int argc, char ** argv)
{
    if (json__example_object_() == -1) {
        log_error("json__example_object_");

        exit(EXIT_FAILURE);
    }

    return 0;
}
