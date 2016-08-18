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
/**
 * @file lru.h
 * @brief LRU-like cache.
 *
 *
 * @note The implementation is a pseudo-LRU similar to what CPU caches do:
 *     hashing is used to split keys into small groups pseudo-randomly,
 *     and almost-perfect LRU is done within each group.
 *
 * # Example usage: FIXME
 *
 * @code{.c}
 * 	// Define new LRU type
 * 	typedef lru_t(int) lru_int_t;
 *
 * 	// Create LRU on stack
 * 	size_t lru_size = lru_size(lru_int_t, 10);
 * 	lru_int_t lru[lru_size];
 * 	lru_init(&lru, 5);
 *
 * 	// Insert some values
 * 	*lru_set(&lru, "luke", strlen("luke")) = 42;
 * 	*lru_set(&lru, "leia", strlen("leia")) = 24;
 *
 * 	// Retrieve values
 * 	int *ret = lru_get(&lru, "luke", strlen("luke");
 * 	if (ret) printf("luke dropped out!\n");
 * 	else     printf("luke's number is %d\n", *ret);
 *
 * 	// Set up eviction function, this is going to get called
 * 	// on entry eviction (baton refers to baton in 'lru' structure)
 * 	void on_evict(void *baton, void *data_) {
 * 		int *data = (int *) data;
 * 		printf("number %d dropped out!\n", *data);
 * 	}
 * 	char *enemies[] = {"goro", "raiden", "subzero", "scorpion"};
 * 	for (int i = 0; i < 4; ++i) {
 * 		int *val = lru_set(&lru, enemies[i], strlen(enemies[i]));
 * 		if (val)
 * 			*val = i;
 * 	}
 *
 * 	// We're done
 * 	lru_deinit(&lru);
 * @endcode
 *
 * \addtogroup generics
 * @{
 */

#pragma once

#include <stdint.h>
#include <stddef.h>

#include "lib/utils.h"
#include "libknot/mm_ctx.h"

/* ================================ Interface ================================ */

/** @brief The type for LRU, parametrized by value type. */
#define lru_t(type) \
	union { \
		type* pdata_t; \
		struct lru lru; \
	}

/**
 * @brief Allocate and initialize an LRU with default associativity.
 *
 * The real limit on the number of slots can be a bit larger but less than double.
 *
 * @param ptable pointer to a pointer to the LRU
 * @param max_slots number of slots
 * @param mm_ctx memory context to use for LRU and its keys, NULL for default
 */
#define lru_create(ptable, max_slots, mm_ctx) \
	*((struct lru **)(ptable)) = \
		lru_create_impl((max_slots), LRU_ASSOC_DEFAULT, (mm_ctx))

/** @brief Free an LRU created by lru_create (it can be NULL). */
#define lru_free(table) \
	lru_free_impl(&(table)->lru)

/** @brief Reset an LRU to the empty state (but preserve any settings). */
#define lru_reset(table) \
	lru_reset_impl(&(table)->lru)

/**
 * @brief Find key in the LRU and return pointer to the corresponding value.
 *
 * @param table pointer to LRU
 * @param key_ lookup key
 * @param len_ key length
 * @return pointer to data or NULL if not found
 */
#define lru_get_try(table, key_, len_) \
	(__typeof__((table)->pdata_t)) \
		lru_get_impl(&(table)->lru, (key_), (len_), -1, false)

/**
 * @brief Return pointer to value, inserting if needed (uninitialized).
 *
 * @param table pointer to LRU
 * @param key_ lookup key
 * @param len_ key length
 * @return pointer to data or NULL if out-of-memory
 */
#define lru_get_new(table, key_, len_) \
	(__typeof__((table)->pdata_t)) \
		lru_get_impl(&(table)->lru, (key_), (len_), sizeof(*(table)->pdata_t), true)



/* ======================== Inlined part of implementation ======================== */

typedef unsigned int uint;

// FIXME: detect availability
#define CACHE_ALIGNED __attribute__((aligned(64)))

struct lru {
	struct knot_mm mm; /**< Memory context to use for keys and lru itself. */
	uint log_groups, /**< Logarithm of the number of LRU groups. */
		assoc; /**< The maximal number of items per group. */
	char group_data[] CACHE_ALIGNED;
};

struct lru_item;

struct lru_group {
	uint32_t stamp;
	struct {
		uint32_t stamp, hash;
		struct lru_item *item;
	} items[];
} CACHE_ALIGNED;
typedef struct lru_group lru_group_t;

/** @internal Default associativity for LRU.
 * ATM it's chosen so lru_group fits into one or two x86 cache lines
 * (64 and 128 bytes on 32 and 64-bit). */
static const int LRU_ASSOC_DEFAULT = sizeof(size_t) == 8 ? 7 : 5;

static inline uint round_power(uint size, uint power)
{
	uint res = ((size - 1) & ~((1 << power) - 1)) + (1 << power);
	assert(__builtin_ctz(res) >= power);
	assert(size <= res && res < size + (1 << power));
	return res;
}

/** @internal Compute the size of a lru_group_t of given associativity. */
static inline uint sizeof_group(uint assoc)
{
	uint byte_size = offsetof(lru_group_t, items)
		+ sizeof(((lru_group_t *)0)->items[0]) * assoc;
	return round_power(byte_size, 6); // CACHE_ALIGNED
}

/** @internal Return pointer to the group on position group_index. */
static inline lru_group_t * get_group(struct lru *lru, uint group_index)
{
	assert(group_index < (1 << lru->log_groups));
	uint stride = sizeof_group(lru->assoc);
	return (lru_group_t *)(lru->group_data + stride * group_index);
}


void lru_free_items_impl(struct lru *lru);
struct lru * lru_create_impl(uint max_slots, uint assoc, knot_mm_t *mm);
void * lru_get_impl(struct lru *lru, const char *key, uint key_len,
			uint val_len, bool do_insert);

/** @internal See lru_free. */
static inline void lru_free_impl(struct lru *lru)
{
	if (!lru)
		return;
	lru_free_items_impl(lru);
	mm_free(&lru->mm, lru);
}

/** @internal See lru_reset. */
static inline void lru_reset_impl(struct lru *lru)
{
	lru_free_items_impl(lru);
	memset(lru->group_data, 0, (1 << lru->log_groups) * sizeof_group(lru->assoc));
}

