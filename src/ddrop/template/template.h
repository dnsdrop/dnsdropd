#pragma once

struct cs_template;


CS__EXPORT struct cs_template * cs_template_new(struct event_base *, int seconds);
CS__EXPORT int                  cs_template_init(struct cs_template *);
CS__EXPORT int                  cs_template_start(struct cs_template *);

