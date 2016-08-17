
#include <assert.h>

#include "lib/generic/lru.h"
#include "contrib/ucw/lib.h"
#include "contrib/murmurhash3/murmurhash3.h"

struct lru_item {
	uint8_t key_len, val_len; /**< Single byte should be enough for our purposes. */
	char data[];              /**< Place for both key and value. */
};

/** @internal Compute offset of value in struct lru_item. */
static uint val_offset(uint key_len) {
	uint key_end = sizeof(struct lru_item) + key_len;
	// align it to the closest multiple of four
	return ((key_end - 1) & 0x3) + 4;
}

// TODO: put into a better place?
void * mm_malloc(void *ctx, size_t n)
{
	(void) ctx;
	return malloc(n);
}
//mm_ctx_init unavailable; hand-writing instead
const knot_mm_t MM_DEFAULT = (knot_mm_t) { NULL, mm_malloc, free };

/** @internal Free each item. */
void lru_free_items_impl(struct lru *lru)
{
	assert(lru);
	for (int i = 0; i < (1 << lru->log_groups); ++i) {
		lru_group_t *g = get_group(lru, i);
		for (int j = 0; j < lru->assoc; ++j)
			mm_free(&lru->mm, g->items[j].item);
	}
}

/** @internal See lru_create. */
struct lru * lru_create_impl(uint max_slots, uint assoc, knot_mm_t *mm)
{
	assert(max_slots);
	if (!mm)
		mm = /*const-cast*/(knot_mm_t *) &MM_DEFAULT;

	// let lru->log_groups = ceil(log2(max_slots / (float) assoc))
	//   without trying for efficiency
	uint group_count = (max_slots - 1) / assoc + 1;
	uint log_groups = 0;
	for (uint s = group_count - 1; s; s /= 2)
		++log_groups;
	group_count = 1 << log_groups;

	size_t size = sizeof(struct lru) + group_count * sizeof_group(assoc);
	struct lru *lru = mm_alloc(mm, size);
	if (unlikely(lru == NULL))
		return NULL;
	*lru = (struct lru) {
		.mm = *mm,
		.log_groups = log_groups,
		.assoc = assoc
	};
	// zeros are a good init
	memset(lru->group_data, 0, group_count * sizeof_group(assoc));
	return lru;
}

/** @internal Implementation of both getting and insertion. */
void * lru_get_impl(struct lru *lru, char *key, uint key_len, uint val_len, bool do_insert)
{
	assert(lru && key && key_len >=0 && key_len < 256);
	// find the right group
	uint32_t khash = hash(key, key_len);
	uint32_t id = khash & ((1 << lru->log_groups) - 1);
	lru_group_t *g = get_group(lru, id);
	struct lru_item *it;
	int i;
	// scan the group
	for (i = 0; i < lru->assoc; ++i)
		if (g->items[i].hash == khash) {
			it = g->items[i].item;
			if (it && it->key_len == key_len && memcmp(it->data, key, key_len) == 0)
				goto found; // to reduce huge nesting depth
		}
	if (!do_insert)
		return NULL;
	// key not found -> find a place to insert
	uint best_i = -1;
	uint32_t best_stamp = -1;
	for (i = 0; i < lru->assoc; ++i) {
		if (g->items[i].item == NULL)
			goto insert;
		if (g->items[i].stamp < best_stamp) {
			best_i = i;
			best_stamp = g->items[i].stamp;
		}
	}
	i = best_i;
insert: // insert into position i
	g->items[i].hash = khash;
	it = g->items[i].item;
	uint new_size = val_offset(key_len) + val_len;
	if (it == NULL || new_size != val_offset(it->key_len) + it->val_len) {
		// (re)allocate
		mm_free(&lru->mm, it);
		it = g->items[i].item = mm_alloc(&lru->mm, new_size);
	}
	it->key_len = key_len;
	it->val_len = val_len;
	memcpy(it->data, key, key_len);
found: // key and hash OK on g->items[i]; now update stamps
	if (g->items[i].stamp < g->stamp) {
		g->items[i].stamp = ++g->stamp;
		// halve all stamps if they've got too big
		if (unlikely(g->stamp & (1<<31))) {
			g->stamp /= 2;
			for (int i = 0; i < lru->assoc; ++i)
				g->items[i].stamp /= 2;
		}
	}
	return it->data + val_offset(key_len);
}

