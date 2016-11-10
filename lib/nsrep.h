/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#pragma once

#include <netinet/in.h>
#include <sys/socket.h>
#include <libknot/dname.h>
#include <limits.h>

#include "lib/defines.h"
#include "lib/generic/map.h"
#include "lib/generic/lru.h"

struct kr_query;

/** 
  * NS RTT score (special values).
  * @note RTT is measured in milliseconds.
  */
enum kr_ns_score {
	KR_NS_MAX_SCORE = KR_CONN_RTT_MAX,
	KR_NS_TIMEOUT   = (95 * KR_NS_MAX_SCORE) / 100,
	KR_NS_LONG      = (3 * KR_NS_TIMEOUT) / 4,
	KR_NS_UNKNOWN   = KR_NS_TIMEOUT / 2,
	KR_NS_PENALTY   = 100,
	KR_NS_GLUED     = 10
};

/**
 * NS QoS flags.  All cleared by default.
 */
enum kr_ns_rep {
	KR_NS_NOIP4  = 1 << 0, /**< NS has no IPv4 */
	KR_NS_NOIP6  = 1 << 1, /**< NS has no IPv6 */
	//KR_NS_NOEDNS = 1 << 2, /**< NS has no EDNS support; unused so far */
	KR_NS_FLAG_COUNT = 2,  /**< The number/range of flags above */
};

/**
 * NS RTT update modes.
 */
enum kr_ns_umode {
	KR_NS_UPDATE = 0, /**< Update as smooth over last two measurements */
	KR_NS_RESET,      /**< Set to given value */
	KR_NS_ADD,        /**< Increment current value */
	KR_NS_MAX         /**< Set to maximum of current/proposed value. */
};

/** NS reputation tracking. */
typedef lru_t(struct kr_nsrep_rep) kr_nsrep_rep_lru_t;
/** NS RTT tracking. */
typedef lru_t(unsigned) kr_nsrep_lru_t;

/* Maximum count of addresses probed in one go (last is left empty) */
#define KR_NSREP_MAXADDR 4

/**
 * Name server representation.
 * Contains extra information about the name server, e.g. score
 * or other metadata.
 */
struct kr_nsrep
{
	unsigned score;                  /**< NS score */
	unsigned reputation;             /**< NS reputation */
	const knot_dname_t *name;        /**< NS name */
	struct kr_context *ctx;          /**< Resolution context */
	union {
		struct sockaddr ip;
		struct sockaddr_in ip4;
		struct sockaddr_in6 ip6;
	} addr[KR_NSREP_MAXADDR];        /**< NS address(es) */
};

/** @internal Address bytes for given family. */
#define kr_nsrep_inaddr(addr) \
	((addr).ip.sa_family == AF_INET ? (void *)&((addr).ip4.sin_addr) : (void *)&((addr).ip6.sin6_addr))
/** @internal Address length for given family. */
#define kr_nsrep_inaddr_len(addr) \
	((addr).ip.sa_family == AF_INET ? sizeof(struct in_addr) : sizeof(struct in6_addr))

/**
 * Set given NS address.
 * @param  qry      updated query
 * @param  index    index of the updated target
 * @param  addr     address bytes (struct in_addr or struct in6_addr)
 * @param  addr_len address bytes length (type will be derived from this)
 * @param  port     address port (if <= 0, 53 will be used)
 * @return          0 or an error code
 */
KR_EXPORT
int kr_nsrep_set(struct kr_query *qry, size_t index, uint8_t *addr, size_t addr_len, int port);

/**
 * Elect best nameserver/address pair from the nsset.
 * @param  qry          updated query
 * @param  ctx          resolution context
 * @return              0 or an error code
 */
KR_EXPORT
int kr_nsrep_elect(struct kr_query *qry, struct kr_context *ctx);

/**
 * Elect best nameserver/address pair from the nsset.
 * @param  qry          updated query
 * @param  ctx          resolution context
 * @return              0 or an error code
 */
KR_EXPORT
int kr_nsrep_elect_addr(struct kr_query *qry, struct kr_context *ctx);

/**
 * Update NS address RTT information.
 *
 * @brief In KR_NS_UPDATE mode reputation is smoothed over last N measurements.
 * 
 * @param  ns           updated NS representation
 * @param  addr         chosen address (NULL for first)
 * @param  score        new score (i.e. RTT), see enum kr_ns_score
 * @param  cache        LRU cache
 * @param  umode        update mode; see enum kr_ns_umode
 * @return              0 on success, error code on failure
 */
KR_EXPORT
int kr_nsrep_update_rtt(struct kr_nsrep *ns, const struct sockaddr *addr,
			unsigned score, kr_nsrep_lru_t *cache, enum kr_ns_umode umode);

/**
 * Set reputation flags for the current NS.
 *
 * @param  qry          query where to update .ns.reputation, use its timestamp and cache
 * @param  reputation   combined reputation flags to set, see enum kr_ns_rep
 *                      (flags not present are not touched)
 * @return              0 on success, error code when called badly
 */
KR_EXPORT
int kr_nsrep_flags_set(struct kr_query *qry, unsigned flags);


/**
 * Get cached NS reputation.
 *
 * @param  ctx          context for cache
 * @param  name         the name to probe
 * @param  timestamp    current time (in seconds); flags older than a day are cleared
 * @return              the reputation, defaulting to 0 when not found
 */
KR_EXPORT
unsigned kr_nsrep_flags_get(const struct kr_context *ctx, const knot_dname_t *name,
			    uint32_t timestamp);

