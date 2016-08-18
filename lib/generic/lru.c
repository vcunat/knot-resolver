/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <assert.h>

#include "lib/generic/lru.h"
#include "contrib/ucw/lib.h"
#include "contrib/murmurhash3/murmurhash3.h"

struct lru_item {
	uint8_t key_len, val_len; /**< Single byte should be enough for our purposes. */
	char data[];              /**< Place for both key and value. */
};

/** @internal Compute offset of value in struct lru_item. */
static uint val_offset(uint key_len)
{
	uint key_end = offsetof(struct lru_item, data) + key_len;
	// align it to the closest multiple of four
	return round_power(key_end, 2);
}

/** @internal Return pointer to value in an item. */
static void * item_val(struct lru_item *it)
{
	return it->data + val_offset(it->key_len) - offsetof(struct lru_item, data);
}

/** @internal Compute the size of an item. ATM we don't align/pad the end of it. */
static uint item_size(uint key_len, uint val_len)
{
	return val_offset(key_len) + val_len;
}

/** @internal Free each item. */
KR_EXPORT void lru_free_items_impl(struct lru *lru)
{
	assert(lru);
	for (int i = 0; i < (1 << lru->log_groups); ++i) {
		lru_group_t *g = get_group(lru, i);
		for (int j = 0; j < lru->assoc; ++j)
			mm_free(lru->mm, g->items[j].item);
	}
}

/** @internal Bump a stamp in an LRU group, index `i` within the group. */
static void move_to_front(struct lru *lru, lru_group_t *g, uint i) {
	if (g->items[i].stamp < g->stamp || g->stamp == 0) {
		g->items[i].stamp = ++g->stamp;
		// halve all stamps within group if they've got too big
		if (unlikely(g->stamp & (1<<31))) {
			g->stamp /= 2;
			for (int i = 0; i < lru->assoc; ++i)
				g->items[i].stamp /= 2;
		}
	}
}

/** @internal See lru_apply. */
KR_EXPORT void lru_apply_impl(struct lru *lru, lru_apply_fun f, void *baton)
{
	assert(lru);
	for (int i = 0; i < (1 << lru->log_groups); ++i) {
		lru_group_t *g = get_group(lru, i);
		for (int j = 0; j < lru->assoc; ++j) {
			struct lru_item *it = g->items[j].item;
			if (!it)
				continue;
			int ret = f(it->data, it->key_len, item_val(it), baton);
			assert(-1 <= ret && ret <= 1);
			if (ret < 0) { // evict
				mm_free(lru->mm, it);
				g->items[j].item = NULL;
			}
			if (ret > 0)
				move_to_front(lru, g, j);
		}
	}
}

/** @internal See lru_create. */
KR_EXPORT struct lru * lru_create_impl(uint max_slots, uint assoc, knot_mm_t *mm)
{
	assert(max_slots);
	// let lru->log_groups = ceil(log2(max_slots / (float) assoc))
	//   without trying for efficiency
	uint group_count = (max_slots - 1) / assoc + 1;
	uint log_groups = 0;
	for (uint s = group_count - 1; s; s /= 2)
		++log_groups;
	group_count = 1 << log_groups;
	assert(max_slots <= group_count * assoc && group_count * assoc < 2 * max_slots);

	size_t size = offsetof(struct lru, group_data) + group_count * sizeof_group(assoc);
	struct lru *lru = mm_alloc(mm, size);
	if (unlikely(lru == NULL))
		return NULL;
	*lru = (struct lru){
		.mm = mm,
		.log_groups = log_groups,
		.assoc = assoc
	};
	// zeros are a good init
	memset(lru->group_data, 0, group_count * sizeof_group(assoc));
	return lru;
}

/** @internal Implementation of both getting and insertion. */
KR_EXPORT void * lru_get_impl(struct lru *lru, const char *key, uint key_len,
				uint val_len, bool do_insert)
{
	assert(lru && key && key_len < 256);
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
insert: // insert into position i (incl. key)
	assert(i >= 0 && i < lru->assoc);
	g->items[i].hash = khash;
	g->items[i].stamp = 0; // trigger stamp update
	it = g->items[i].item;
	uint new_size = item_size(key_len, val_len);
	if (it == NULL || new_size != item_size(it->key_len, it->val_len)) {
		// (re)allocate
		mm_free(lru->mm, it);
		it = g->items[i].item = mm_alloc(lru->mm, new_size);
		if (it == NULL)
			return NULL;
	}
	it->key_len = key_len;
	it->val_len = val_len;
	memcpy(it->data, key, key_len);
found: // key and hash OK on g->items[i]; now update stamps
	move_to_front(lru, g, i);
	return item_val(g->items[i].item);
}

