#pragma once

#include <stdlib.h>

struct hmap_key {
    void * data;
    size_t len;
};

struct hmap_entry {
    struct hmap_entry * prev;
    struct hmap_entry * next;
    struct hmap_key   * key;
    char                val[];
};

struct hmap {
    struct hmap_entry ** entries;
    struct hmap_entry  * head;
    struct hmap_entry  * tail;
    size_t               cap;
    size_t               size;
};


static int
hmap_resize(struct hmap * m, size_t cap) {
    struct hmap_entry ** entries;
    struct hmap_entry * entry;

    entries = (struct hmap_entry **)calloc(cap, sizeof(**entries));

    if (entries == NULL) {
        return -1;
    }

    entry = m->head;

    while (entry != NULL) {
        uint32_t hash;
        size_t bucket;

static struct hmap * 
hmap_create(void) {
    struct hmap * m = (struct hmap *)calloc(1, sizeof(struct hmap));

    if (m == NULL) {
        return NULL;
    }
}

