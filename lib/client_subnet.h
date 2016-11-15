#pragma once

#include <libknot/rrtype/opt.h>

#include "lib/rplan.h"

/*! The location identifier string; used by cache.
 *
 * It's "0" for explicit /0, and "" for no ECS with /0 scope (like TLD).
 * If the server doesn't support ECS, it's considered as /0 scope.
 * NULL pointer means ECS isn't attempted.
 * TODO: perhaps rename stuff.
 */
typedef struct kr_ecs {
	uint8_t loc_len; /*!< The length of loc. */
	char loc[2];
} kr_ecs_t;


/*! Context for client subnet handling.  Private to modules/client_subnet */
struct kr_ecs_ctx;



#define ECS_LOC_FMT(ecs) \
	((ecs)->loc_len == 2 ? "%c%c" : ((ecs)->loc_len == 0 ? "none" : "/0")) \
	, (ecs)->loc[0], (ecs)->loc[1]


static inline kr_ecs_t * kr_ecs_get(const struct kr_query *qry) {
#if 0
	assert(qry);
	if (!qry->ecs) /* first check the typical case */
		return NULL;
	if (qry->parent)
		return NULL;
	return qry->ecs;
#endif
	assert(false);
	return NULL;
}

