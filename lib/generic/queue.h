#pragma once

#include "contrib/ucw/lib.h"
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/** @brief The type for queue, parametrized by value type. */
#define queue_t(type) \
	union { \
		type *pdata_t; /* only the *type* information is used */ \
		struct queue queue; \
	}

/** @brief Initialize a queue.  You can malloc() it the usual way. */
#define queue_init(q) do { \
	(void)(((__typeof__(((q).pdata_t)))0) == (void *)0); /* typecheck queue_t */ \
	queue_init_impl(&(q).queue, sizeof(*(q).pdata_t)); \
	} while (false)

/** @brief De-initialize a queue: make it invalid and free any inner allocations. */
#define queue_deinit(q) \
	queue_deinit_impl(&(q).queue)

/** @brief Push data to queue's tail.  (Type-safe version; use _impl() otherwise.) */
#define queue_push(q, data) \
	*((__typeof__((q).pdata_t)) queue_push_impl(&(q).queue)) = data
		
/** @brief Push data to queue's head.  (Type-safe version; use _impl() otherwise.) */
#define queue_push_head(q, data) \
	*((__typeof__((q).pdata_t)) queue_push_head_impl(&(q).queue)) = data

/** @brief Remove the element at the head. */
#define queue_pop(q) \
	queue_pop_impl(&(q).queue)

/** @brief Return a "reference" to the element at the head (it's an l-value) . */
#define queue_head(q) \
	( *(__typeof__((q).pdata_t)) queue_head_impl(&(q).queue) )

/** @brief Return a "reference" to the element at the tail (it's an l-value) . */
#define queue_tail(q) \
	( *(__typeof__((q).pdata_t)) queue_tail_impl(&(q).queue) )

/** @brief Return the number of elements in the queue. */
#define queue_len(q) \
	((const size_t)(q).queue.len)



/* ======================== Inlined part of implementation ======================== */

struct queue_chunk;
struct queue {
	size_t len;
	uint16_t chunk_cap, item_size;
	struct queue_chunk *head, *tail;
};

void queue_init_impl(struct queue *q, size_t item_size);
void queue_deinit_impl(struct queue *q);
void * queue_push_impl(struct queue *q);
void * queue_push_head_impl(struct queue *q);

struct queue_chunk {
	struct queue_chunk *next; /* head -> ... -> tail */
	int16_t begin, end, cap, pad_; /* indices: zero is closest to head */
	uint8_t data[];
};

static inline void * queue_head_impl(const struct queue *q)
{
	assert(q);
	struct queue_chunk *h = q->head;
	if (unlikely(!h))
		return NULL;
	assert(h->end > h->begin);
	return h->data + h->begin * q->item_size;
}

static inline void * queue_tail_impl(const struct queue *q)
{
	assert(q);
	struct queue_chunk *t = q->tail;
	if (unlikely(!t))
		return NULL;
	assert(t->end > t->begin);
	return t->data + (t->end - 1) * q->item_size;
}

static inline void queue_pop_impl(struct queue *q)
{
	assert(q && q->head && q->head->end > q->head->begin);
	if (q->head->end - q->head->begin == 1) {
		struct queue_chunk *h = q->head;
		q->head = h->next;
		free(h);
	} else {
		++(q->head->begin);
	}
	--(q->len);
}





void test()
{
	queue_t(int*) q;
	queue_init(q);
	queue_push(q, NULL);
	queue_push_head(q, NULL);
	queue_pop(q);
	int *p = queue_head(q);
	queue_head(q) = queue_tail(q) = p;
	int l = queue_len(q);
	(void)l;
	queue_deinit(q);
}

