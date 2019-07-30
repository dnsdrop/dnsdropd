#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <time.h>

#include <event2/event.h>

#include "ddrop/common.h"
#include "ddrop/core/log.h"
#include "ddrop/template/template.h"

struct ddrop_template {
    struct event_base * evbase;
    struct event      * timer_ev;
    struct timeval      tv;
};


static void
template__timercb_(int sock, short which, void * arg)
{
    struct ddrop_template * tmpl;

    if ((tmpl = (struct ddrop_template *)arg) == NULL) {
        log_error("uhhh bad juju");
        return;
    }

    log_info("template ping");

    evtimer_add(tmpl->timer_ev, &tmpl->tv);
}

static int
template__init_(struct ddrop_template * tmpl)
{
    if (tmpl == NULL) {
        return -1;
    }

    return 0;
}

static int
template__start_(struct ddrop_template * tmpl)
{
    if (tmpl == NULL) {
        return -1;
    }

    return evtimer_add(tmpl->timer_ev, &tmpl->tv);
}

static int
template__new_(struct ddrop_template ** out, struct event_base * evbase, int seconds)
{
    struct ddrop_template * tmpl;

    if (evbase == NULL | out == NULL) {
        return -1;
    }

    *out = NULL;

    if ((tmpl = calloc(1, sizeof(*tmpl))) == NULL) {
        return -1;
    }

    tmpl->timer_ev   = evtimer_new(evbase, template__timercb_, tmpl);
    tmpl->evbase     = evbase;

    tmpl->tv.tv_sec  = seconds;
    tmpl->tv.tv_usec = 0;

    *out = tmpl;

    return 0;
}

struct ddrop_template *
ddrop_template_new(struct event_base * evbase, int seconds)
{
    struct ddrop_template * template;

    if (evbase == NULL) {
        return NULL;
    }

    if (seconds <= 0) {
        /* default to 10 */
        seconds = 10;
    }

    if (template__new_(&template, evbase, seconds) == -1) {
        return NULL;
    }

    return template;
}

int
ddrop_template_init(struct ddrop_template * tmpl)
{
    return template__init_(tmpl);
}

int
ddrop_template_start(struct ddrop_template * tmpl)
{
    return template__start_(tmpl);
}
