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
 * # Example usage:
 *
 * @code{.c}
 * 	// Define new LRU type
 * 	typedef lru_t(int) lru_int_t;
 *
 * 	// Create LRU
 * 	lru_int_t *lru;
 * 	lru_create(&lru, 5, NULL);
 *
 * 	// Insert some values
 * 	*lru_get_new(lru, "luke", strlen("luke")) = 42;
 * 	*lru_get_new(lru, "leia", strlen("leia")) = 24;
 *
 * 	// Retrieve values
 * 	int *ret = lru_get_try(lru, "luke", strlen("luke"));
 * 	if (!ret) printf("luke dropped out!\n");
 * 	    else  printf("luke's number is %d\n", *ret);
 *
 * 	char *enemies[] = {"goro", "raiden", "subzero", "scorpion"};
 * 	for (int i = 0; i < 4; ++i) {
 * 		int *val = lru_get_new(lru, enemies[i], strlen(enemies[i]));
 * 		if (val)
 * 			*val = i;
 * 	}
 *
 * 	// We're done
 * 	lru_free(lru);
 * @endcode
 *
 * \addtogroup generics
 * @{
 */

#pragma once

#include <assert.h>
#include <stdint.h>
#include <stddef.h>

#include "contrib/ucw/lib.h"
#include "lib/utils.h"
#include "libknot/mm_ctx.h"

/* ================================ Interface ================================ */

/** @brief The type for LRU, parametrized by value type. */
#define lru_t(type) \
	union { \
		type *pdata_t; /* only the *type* information is used */ \
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
#define lru_create(ptable, max_slots, mm_ctx) do { \
	(void)(((__typeof__((*(ptable))->pdata_t))0) == (void *)0); /* typecheck lru_t */ \
	*((struct lru **)(ptable)) = \
		lru_create_impl((max_slots), (mm_ctx)); \
	} while (false)

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
 * @brief Return pointer to value, inserting if needed (zeroed).
 *
 * @param table pointer to LRU
 * @param key_ lookup key
 * @param len_ key length
 * @return pointer to data or NULL if out-of-memory
 */
#define lru_get_new(table, key_, len_) \
	(__typeof__((table)->pdata_t)) \
		lru_get_impl(&(table)->lru, (key_), (len_), sizeof(*(table)->pdata_t), true)


/**
 * @brief Apply a function to every item in LRU.
 *
 * @param table pointer to LRU
 * @param function int (*function)(const char *key, uint len, val_type *val, void *baton)
 *        return value meanings: 0 do nothing, -1 evict the item, 1 move to front.
 * @param baton extra pointer passed to each function invocation
 */
#define lru_apply(table, function, baton) do { \
	lru_apply_fun_g(fun_dummy, __typeof__(*(table)->pdata_t)) = 0; \
	(void)(fun_dummy == (function)); /* produce a warning with incompatible function type */ \
	lru_apply_impl(&(table)->lru, (lru_apply_fun)(function), (baton)); \
	} while (false)


/* ======================== Inlined part of implementation ======================== */

#define lru_apply_fun_g(name, val_type) \
	int (*(name))(const char *key, uint len, val_type *val, void *baton)
typedef lru_apply_fun_g(lru_apply_fun, void);

#if __GNUC__ >= 4
	#define CACHE_ALIGNED __attribute__((aligned(64)))
#else
	#define CACHE_ALIGNED
#endif

struct lru_item;

#if SIZE_MAX > (1 << 32)
	/** @internal The number of keys stored within each group. */
	#define LRU_ASSOC 2
#else
	#define LRU_ASSOC 3
#endif
/** @internal The number of hashes tracked within each group: 12-1 or 13-1. */
#define LRU_TRACKED ((64 - sizeof(size_t) * LRU_ASSOC) / 4 - 1)

struct lru_group {
	uint16_t counts[LRU_TRACKED+1]; /*!< Occurence counters; the last one is special. */
	uint16_t hashes[LRU_TRACKED+1]; /*!< Top halves of hashes; the last one is unused. */
	struct lru_item *items[LRU_ASSOC]; /*!< The full items. */
} CACHE_ALIGNED;
typedef struct lru_group lru_group_t;

/* The sizes are chosen so lru_group just fits into a single x86 cache line. */
_Static_assert(64 == sizeof(lru_group_t)
		&& 64 == LRU_ASSOC * sizeof(void*) + (LRU_TRACKED+1) * 4,
		"bad sizing for you sizeof(void*)");

struct lru {
	struct knot_mm *mm; /**< Memory context to use for keys and lru itself. */
	uint log_groups; /**< Logarithm of the number of LRU groups. */
	lru_group_t groups[] CACHE_ALIGNED; /**< The groups of items. */
};

/** @brief Round the value up to a multiple of (1 << power). */
static inline uint round_power(uint size, uint power)
{
	uint res = ((size - 1) & ~((1 << power) - 1)) + (1 << power);
	assert(__builtin_ctz(res) >= power);
	assert(size <= res && res < size + (1 << power));
	return res;
}

void lru_free_items_impl(struct lru *lru);
struct lru * lru_create_impl(uint max_slots, knot_mm_t *mm);
void * lru_get_impl(struct lru *lru, const char *key, uint key_len,
			uint val_len, bool do_insert);
void lru_apply_impl(struct lru *lru, lru_apply_fun f, void *baton);

/** @internal See lru_free. */
static inline void lru_free_impl(struct lru *lru)
{
	if (!lru)
		return;
	lru_free_items_impl(lru);
	mm_free(lru->mm, lru);
}

/** @internal See lru_reset. */
static inline void lru_reset_impl(struct lru *lru)
{
	lru_free_items_impl(lru);
	memset(lru->groups, 0, offsetof(struct lru, groups[1 << lru->log_groups]));
}

