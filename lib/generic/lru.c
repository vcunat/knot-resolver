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

#include "lib/generic/lru.h"
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
KR_EXPORT void lru_free_items_impl(struct lru *lru) // TODO: re-read
{
	assert(lru);
	for (int i = 0; i < (1 << lru->log_groups); ++i) {
		lru_group_t *g = get_group(lru, i);
		for (int j = 0; j < LRU_ASSOC; ++j)
			mm_free(lru->mm, g->items[j]);
	}
}


/** @internal See lru_apply. */
KR_EXPORT void lru_apply_impl(struct lru *lru, lru_apply_fun f, void *baton) // TODO: re-read
{
	assert(lru);
	for (int i = 0; i < (1 << lru->log_groups); ++i) {
		lru_group_t *g = get_group(lru, i);
		for (int j = 0; j < LRU_ASSOC; ++j) {
			struct lru_item *it = g->items[j];
			if (!it)
				continue;
			int ret = f(it->data, it->key_len, item_val(it), baton);
			assert(-1 <= ret && ret <= 1);
			if (ret < 0) { // evict
				mm_free(lru->mm, it);
				g->items[j] = NULL;
			}
		}
	}
}

/** @internal See lru_create. */
KR_EXPORT struct lru * lru_create_impl(uint max_slots, knot_mm_t *mm)
{
	assert(max_slots);
	// let lru->log_groups = ceil(log2(max_slots / (float) assoc))
	//   without trying for efficiency
	uint group_count = (max_slots - 1) / LRU_ASSOC + 1;
	uint log_groups = 0;
	for (uint s = group_count - 1; s; s /= 2)
		++log_groups;
	group_count = 1 << log_groups;
	assert(max_slots <= group_count * LRU_ASSOC && group_count * LRU_ASSOC < 2 * max_slots);

	size_t size = offsetof(struct lru, group_data) + group_count * sizeof_group();
	struct lru *lru = mm_alloc(mm, size);
	if (unlikely(lru == NULL))
		return NULL;
	*lru = (struct lru){
		.mm = mm,
		.log_groups = log_groups,
	};
	// zeros are a good init
	memset(lru->group_data, 0, group_count * sizeof_group());
	return lru;
}

/** @internal Implementation of both getting and insertion. */
KR_EXPORT void * lru_get_impl(struct lru *lru, const char *key, uint key_len,
				uint val_len, bool do_insert)
{
	assert(lru && (key || !key_len) && key_len < 256);
	// find the right group
	uint32_t khash = hash(key, key_len);
	uint16_t khash_top = khash >> 16;
	uint32_t id = khash & ((1 << lru->log_groups) - 1);
	lru_group_t *g = get_group(lru, id);
	struct lru_item *it;
	int i;
	// scan the group
	for (i = 0; i < LRU_ASSOC; ++i)
		if (g->hashes[i] == khash_top) {
			it = g->items[i];
			if (likely(it && it->key_len == key_len
					&& memcmp(it->data, key, key_len) == 0))
				goto found; // to reduce huge nesting depth
		}
	// key not found -> find a place to insert
	if (do_insert)
		for (i = 0; i < LRU_ASSOC; ++i)
			if (g->counts[i] == 0)
				goto insert;
	//// fail to get/insert: we'll return NULL but first update counts
	// first, check if we track key's count at least
	for (i = LRU_ASSOC; i < LRU_TRACKED; ++i)
		if (g->hashes[i] == khash_top) {
			++g->counts[i];
			return NULL;
		}
	// decrement all counts but only on every LRU_TRACKED occasion
	if (g->counts[LRU_TRACKED]) {
		--g->counts[LRU_TRACKED];
	} else {
		g->counts[LRU_TRACKED] = LRU_TRACKED - 1;
		for (i = 0; i < LRU_TRACKED; ++i)
			--g->counts[i];
	}
	return NULL;
insert: // insert into position i (incl. key)
	assert(i >= 0 && i < LRU_ASSOC);
	g->hashes[i] = khash_top;
	assert(g->counts[i] == 0); // incremented below
	it = g->items[i];
	uint new_size = item_size(key_len, val_len);
	if (it == NULL || new_size != item_size(it->key_len, it->val_len)) {
		// (re)allocate
		mm_free(lru->mm, it);
		it = g->items[i] = mm_alloc(lru->mm, new_size);
		if (it == NULL)
			return NULL;
	}
	it->key_len = key_len;
	it->val_len = val_len;
	memcpy(it->data, key, key_len);
	memset(item_val(it), 0, val_len); // clear the value
found: // key and hash OK on g->items[i]; now update stamps
	assert(i >= 0 && i < LRU_ASSOC);
	++g->counts[i];
	return item_val(g->items[i]);
}

