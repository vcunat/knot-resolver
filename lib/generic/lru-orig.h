/*  Copyright (C) 2013 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * @note This is a naive LRU implementation with a simple slot stickiness counting.
 *       Each write access increases stickiness on success, and decreases on collision.
 *       A slot is freed if the stickiness decreases to zero. This makes it less likely,
 *       that often-updated entries are jousted out of cache.
 *
 * # Example usage:
 *
 * @code{.c}
 * 	// Define new LRU type
 * 	typedef lru_hash(int) lru_int_t;
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

#include <stdlib.h>
#include <stdint.h>
#include "contrib/murmurhash3/murmurhash3.h"

#define lru_slot_struct \
	char *key;    /**< Slot key */ \
	uint16_t len; /**< Slot length */ \
	uint16_t refs; /**< Slot importance (#writes - #collisions) */ \
/** @brief Slot header. */
struct lru_slot {
	lru_slot_struct
};

/** @brief Return boolean true if slot matches key/len pair. */
static inline int lru_slot_match(struct lru_slot *slot, const char *key, uint32_t len)
{
	return (slot->len == len) && (memcmp(slot->key, key, len) == 0);
}

#define lru_slot_offset(table) \
	(size_t)((void *)&((table)->slots[0].data) - (void *)&((table)->slots[0]))

/** @brief Callback definitions. */
typedef void (*lru_free_f)(void *baton, void *ptr);

/** @brief LRU structure base. */
#define lru_hash_struct \
	uint32_t size;      /**< Number of slots */ \
	uint32_t evictions; /**< Number of evictions. */ \
	uint32_t stride;    /**< Stride of the 'slots' array */ \
	lru_free_f evict;   /**< Eviction function */ \
	void *baton;        /**< Passed to eviction function */
/** @internal Object base of any other lru_hash type. */
struct lru_hash_base {
	lru_hash_struct
	char slots[];
};

/** @brief User-defined hashtable. */
#define lru_hash(type) \
struct { \
	lru_hash_struct \
	struct { \
		lru_slot_struct \
		type data; \
	} slots[]; \
}

/** Get slot at given index. */
static inline void *lru_slot_at(struct lru_hash_base *lru, uint32_t id)
{
	if (id >= lru->size) {
		return NULL;
	}
	return (struct lru_slot *)(lru->slots + (id * lru->stride));
}

/** Get pointer to slot value. */
static inline void *lru_slot_val(struct lru_slot *slot, size_t offset)
{
	return ((char *)slot) + offset;
}

/** @internal Slot data getter */
static inline void *lru_slot_get(struct lru_hash_base *lru, const char *key, uint16_t len, size_t offset)
{
	if (!lru || !key || len == 0) {
		return NULL;
	}
	uint32_t id = hash(key, len) % lru->size;
	struct lru_slot *slot = lru_slot_at(lru, id);
	if (lru_slot_match(slot, key, len)) {
		return lru_slot_val(slot, offset);
	}
	return NULL;
}

static inline int lru_slot_evict(struct lru_hash_base *lru, uint32_t id, size_t offset)
{
	struct lru_slot *slot = lru_slot_at(lru, id);
	if (!slot || !slot->key) {
		return -1;
	}
	lru->evictions += 1;
	free(slot->key);
	if (lru->evict) {
		lru->evict(lru->baton, lru_slot_val(slot, offset));
	}
	memset(slot, 0, lru->stride);
	return 0;
}

/** @internal Slot data setter */
static inline void *lru_slot_set(struct lru_hash_base *lru, const char *key, uint16_t len, size_t offset)
{
	if (!lru || !key || len == 0) {
		return NULL;
	}
	uint32_t id = hash(key, len) % lru->size;
	struct lru_slot *slot = lru_slot_at(lru, id);
	if (lru_slot_match(slot, key, len)) {
		slot->refs += 1; /* Increase slot significance */
	} else {
		if (slot->key) {
			slot->refs -= 1; /* Decrease slot significance */
			if (slot->refs > 0) {
				return NULL; /* Couldn't joust former key. */
			}
			if (lru_slot_evict(lru, id, offset) < 0) {
				return NULL;
			}
		}
		memset(slot, 0, lru->stride);
		slot->key = malloc(len);
		if (!slot->key) {
			return NULL;
		}
		memcpy(slot->key, key, len);
		slot->len = len;
		slot->refs = 1;
	}
	return lru_slot_val(slot, offset);
}

/**
 * @brief Return size of the LRU structure with given number of slots.
 * @param  type     type of LRU structure
 * @param  max_slots number of slots
 */
#define lru_size(type, max_slots) \
	(sizeof(type) + (max_slots) * sizeof(((type *)NULL)->slots[0]))

/**
 * @brief Initialize hash table.
 * @param table hash table
 * @param max_slots number of slots
 */
#define lru_init(table, max_slots) \
 (memset((table), 0, sizeof(*table) + (max_slots) * sizeof((table)->slots[0])), \
  (table)->stride = sizeof((table)->slots[0]), (table)->size = (max_slots))

/**
 * @brief Free all keys and evict all values.
 * @param table hash table
 */
#define lru_deinit(table) if (table) { \
	for (uint32_t i = 0; i < (table)->size; ++i) { \
		if ((table)->slots[i].key) { \
			if ((table)->evict) { \
				(table)->evict((table)->baton, &(table)->slots[i].data); \
			} \
			free((table)->slots[i].key); \
		} \
	} \
}

/**
 * @brief Find key in the hash table and return pointer to it's value.
 * @param table hash table
 * @param key_ lookup key
 * @param len_ key length
 * @return pointer to data or NULL
 */
#define lru_get(table, key_, len_) \
	(__typeof__(&(table)->slots[0].data)) \
		lru_slot_get((struct lru_hash_base *)(table), (key_), (len_), lru_slot_offset(table))

/**
 * @brief Return pointer to value (create/replace if needed)
 * @param table hash table
 * @param key_ lookup key
 * @param len_ key length
 * @return pointer to data or NULL
 */
#define lru_set(table, key_, len_) \
 	(__typeof__(&(table)->slots[0].data)) \
		lru_slot_set((struct lru_hash_base *)(table), (key_), (len_), lru_slot_offset(table))

/**
 * @brief Evict element at index.
 * @param table hash table
 * @param pos_ element position
 * @return 0 if successful, negative integer if failed
 */
#define lru_evict(table, pos_) \
 	lru_slot_evict((struct lru_hash_base *)(table), (pos_), lru_slot_offset(table))

/** @} */
