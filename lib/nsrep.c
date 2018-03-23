/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <arpa/inet.h>

#include "lib/nsrep.h"
#include "lib/rplan.h"
#include "lib/resolve.h"
#include "lib/defines.h"
#include "lib/generic/pack.h"
#include "contrib/ucw/lib.h"

/** Some built-in unfairness ... */
#ifndef FAVOUR_IPV6
#define FAVOUR_IPV6 20 /* 20ms bonus for v6 */
#endif

/** @internal Macro to set address structure. */
#define ADDR_SET(sa, family, addr, len, port) do {\
    	memcpy(&sa ## _addr, (addr), (len)); \
    	sa ## _family = (family); \
	sa ## _port = htons(port); \
} while (0)

/** Update nameserver representation with current name/address pair. */
static void update_nsrep(struct kr_nsrep *ns, size_t pos, uint8_t *addr, size_t addr_len, int port)
{
	if (addr == NULL) {
		ns->addr[pos].ip.sa_family = AF_UNSPEC;
		return;
	}

	/* Rotate previous addresses to the right. */
	memmove(ns->addr + pos + 1, ns->addr + pos, (KR_NSREP_MAXADDR - pos - 1) * sizeof(ns->addr[0]));

	switch(addr_len) {
	case sizeof(struct in_addr):
		ADDR_SET(ns->addr[pos].ip4.sin, AF_INET, addr, addr_len, port); break;
	case sizeof(struct in6_addr):
		ADDR_SET(ns->addr[pos].ip6.sin6, AF_INET6, addr, addr_len, port); break;
	default: assert(0); break;
	}
}

static void update_nsrep_set(struct kr_nsrep *ns, const knot_dname_t *name, uint8_t *addr[], unsigned score)
{
	/* NSLIST is not empty, empty NS cannot be a leader. */
	if (!addr[0] && ns->addr[0].ip.sa_family != AF_UNSPEC) {
		return;
	}
	/* Set new NS leader */
	ns->name = name;
	ns->score = score;
	for (size_t i = 0; i < KR_NSREP_MAXADDR; ++i) {
		if (addr[i]) {
			void *addr_val = pack_obj_val(addr[i]);
			size_t len = pack_obj_len(addr[i]);
			update_nsrep(ns, i, addr_val, len, KR_DNS_PORT);
		} else {
			break;
		}
	}
}

#undef ADDR_SET

/** Scan addr_set and choose the best KR_NSREP_MAXADDR (or fewer) addresses.
 * \param has_timeouted[out] optionally indicated if the list contains a timeouted IP
 * \return the best score (> KR_NS_MAX_SCORE if nothing suitable found) */
static unsigned eval_addr_set(pack_t *addr_set, struct kr_context *ctx, bool feeling_lucky,
				uint8_t *addr[], bool *retry_timeouted)
{
	kr_nsrep_rtt_lru_t *rtt_cache = ctx->cache_rtt;
	const struct kr_qflags opts = ctx->options;

	/* We first produce a list with more fields. */
	struct addr_info {
		uint8_t *addr;
		unsigned score;
		bool is_timeouted;
		kr_nsrep_rtt_lru_entry_t *cached;
	};
	struct addr_info ais[KR_NSREP_MAXADDR] =
		{ { .addr = NULL, .score = KR_NS_MAX_SCORE + 1, } };

	const uint64_t now = kr_now();

	for (uint8_t *it = pack_head(*addr_set); it != pack_tail(*addr_set);
						it = pack_obj_next(it)) {
		void *val = pack_obj_val(it);
		size_t len = pack_obj_len(it);
		unsigned penalty = 0;
		bool is_valid = false;
		/* Check if the address isn't disabled. */
		if (len == sizeof(struct in6_addr)) {
			is_valid = !(opts.NO_IPV6);
		} else {
			assert(len == sizeof(struct in_addr));
			is_valid = !(opts.NO_IPV4);
			penalty = FAVOUR_IPV6;
		}

		if (!is_valid) {
			continue;
		}

		/* Get all the information for the current address. */
		struct addr_info ai;
		memset(&ai, 0, sizeof(ai));
		ai.addr = it;
		ai.cached = rtt_cache ? lru_get_try(rtt_cache, val, len) : NULL;

		if (!ai.cached) {
			/* Unknown RTT? ...  */
			ai.score = feeling_lucky
				/* ... let's try that first while we're lucky. */
				? kr_rand_uint(6)
				/* ... I don't much feel like trying it. */
				: kr_rand_uint(KR_NS_UNKNOWN);

		} else {
			if (ai.cached->score >= KR_NS_TIMEOUT) {
				/* If NS once was marked as "timeouted",
				 * it won't participate in NS elections
				 * at least ctx->cache_rtt_tout_retry_interval milliseconds.
				 * Regular luck isn't enough to affect this case. */
				uint64_t elapsed = now - ai.cached->tout_timestamp;
				assert(((int64_t)elapsed) >= 0);
				elapsed = elapsed > UINT_MAX ? UINT_MAX : elapsed;
				if (elapsed > ctx->cache_rtt_tout_retry_interval) {
					/* Select this NS for probing in this particular query,
					 * but don't change the cached score.
					 * For other queries this NS will remain "timeouted". */
					ai.score = KR_NS_LONG - 1;
					ai.is_timeouted = true;
				} else {
					continue;
				}

			} else if (feeling_lucky) {
				/* Known RTT and lucky?  (and not timeouted)
				 * The usual lucky choice: just ignore the knowledge. */
				ai.score = kr_rand_uint(KR_NS_UNKNOWN);

			} else { /* Known RTT, not lucky and not timeouted.
				  * Let's actually use the RTT :-) */
				ai.score = ai.cached->score;
			}
		}

		if (!feeling_lucky && !ai.is_timeouted) {
			ai.score += penalty;
			/* Now we add 0--25% random jitter to spread load
			 * a little if we have multiple similar choices.
			 * This only makes sense if (!feeling_lucky), and for
			 * is_timeouted we don't want to get over KR_NS_LONG ATM. */
			ai.score += kr_rand_uint(ai.score / 4);
			ai.score = MIN(KR_NS_MAX_SCORE, ai.score);
		}

		/* Insert ai into the sorted ais list (by the score). */
		for (int i = 0; i < KR_NSREP_MAXADDR; ++i) {
			if (!ais[i].addr) { /* empty place at the end */
				ais[i] = ai;
				break;
			}
			/* We give preference to "timeouted" servers,
			 * to make sure that at least one of them is retried. */
			if (ai.is_timeouted > ais[i].is_timeouted
			    || ais[i].score > ai.score) {
				/* Insert on this position i. LATER: memmove might be faster. */
				for (int j = KR_NSREP_MAXADDR - 1; j > i; --j) {
					ais[j] = ais[j - 1];
				}
				ais[i] = ai;
				break;
			}
		}
	}

	/* Copy the result and bump timeouted NSs. */
	bool has_touted = false;
	for (int i = 0; i < KR_NSREP_MAXADDR; ++i) {
		addr[i] = ais[i].addr;
		if (!addr[i]) break; /* this was the last (non-sensical) element */

		if (!ais[i].is_timeouted) continue;
		has_touted = true;
		/* If we've decided to add timeouted NSs into the list, we bump
		 * their timestamps so they aren't also attempted in the meantime
		 * before we know the result of this probe.
		 * TODO: this isn't perfect at all, as there's no guarantee
		 * that we will actually probe *all* of those servers.
		 */
		if (!ais[i].cached) {
			/* Never happens, but the linter is unable to deduce that,
			 * and it would block CI. */
			assert(false);
			continue;
		}
		ais[i].cached->tout_timestamp = now;
		if (VERBOSE_STATUS) {
			void *val = pack_obj_val(addr[i]);
			size_t len = pack_obj_len(addr[i]);
			char sa_str[INET6_ADDRSTRLEN];
			int af = (len == sizeof(struct in6_addr)) ? AF_INET6 : AF_INET;
			inet_ntop(af, val, sa_str, sizeof(sa_str));
			kr_log_verbose("[     ][nsre] adding timeouted NS: %s, score %i\n",
				       sa_str, ais[i].cached->score);
		}
	}

	if (retry_timeouted != NULL) {
		*retry_timeouted = has_touted;
	}
	return ais[0].score;
}

struct nsrep_p {
	/** If true, choose NSs by randomness instead of RTT estimates. */
	bool feeling_lucky;
	struct kr_query *qry;
};

static int eval_nsrep(const char *k, void *v, void *baton)
{
	struct nsrep_p *param = baton;
	struct kr_nsrep *ns = &param->qry->ns;
	struct kr_context *ctx = ns->ctx;
	unsigned score = KR_NS_MAX_SCORE;
	unsigned reputation = 0;
	uint8_t *addr_choice[KR_NSREP_MAXADDR] = { NULL, };

	/* Fetch NS reputation */
	if (ctx->cache_rep) {
		unsigned *cached = lru_get_try(ctx->cache_rep, k,
					       knot_dname_size((const uint8_t *)k));
		if (cached) {
			reputation = *cached;
		}
	}

	pack_t *addr_set = (pack_t *)v;
	bool retry_timeouted = false;
	if (addr_set->len == 0) {
		/* We don't even know any address for the NS.
		 * Let's prefer it if we're feeling lucky, with a bit of random jitter. */
		score = KR_NS_UNKNOWN;
		if (param->feeling_lucky) {
			score = kr_rand_uint(6);
		}

		/* If the server doesn't have IPv6, give it disadvantage. */
		if (reputation & KR_NS_NOIP6) {
			score += FAVOUR_IPV6;
			/* If the server is unknown but has rep record, treat it as timeouted */
			/* TODO: time limits for this as well, as if timeouted. */
			if (reputation & KR_NS_NOIP4) {
				score = KR_NS_UNKNOWN;
				/* Try to start with clean slate */
				if (!(ctx->options.NO_IPV6)) {
					reputation &= ~KR_NS_NOIP6;
				}
				if (!(ctx->options.NO_IPV4)) {
					reputation &= ~KR_NS_NOIP4;
				}
			}
		}
	} else {
		score = eval_addr_set(addr_set, ctx, param->feeling_lucky,
					addr_choice, &retry_timeouted);
	}

	/* Probabilistic bee foraging strategy (naive).
	 * The fastest NS is preferred by workers until it is depleted (timeouts or degrades),
	 * at the same time long distance scouts probe other sources (low probability).
	 * Well, we've warped this strategy a lot over time.
	 * TODO: kill NO_THROTTLE or something?
	 */
	int ret = kr_ok();
	if (addr_set->len != 0 && addr_choice[0] == NULL) {
		/* All IPs filtered out (timeouts); skip this name. */
		return kr_ok();

	} else if (retry_timeouted) {
		/* We decided to re-probe the IP(s), so let's choose this NS name
		 * and stop looking for others. */
		ret = 1;

	} else if (score < ns->score) {
		/* It's better, let's take it. */

	} else { /* We don't want this one. */
		return kr_ok();
	}

	update_nsrep_set(ns, (const knot_dname_t *)k, addr_choice, score);
	ns->reputation = reputation;

	return ret;
}

int kr_nsrep_set(struct kr_query *qry, size_t index, const struct sockaddr *sock)
{
	if (!qry) {
		return kr_error(EINVAL);
	}
	if (index >= KR_NSREP_MAXADDR) {
		return kr_error(ENOSPC);
	}
	qry->ns.name = (const uint8_t *)"";
	/* Reset score on first entry */
	if (index == 0) {
		qry->ns.score = KR_NS_UNKNOWN;
		qry->ns.reputation = 0;
	}

	if (!sock) {
		qry->ns.addr[index].ip.sa_family = AF_UNSPEC;
		return kr_ok();
	}

	switch (sock->sa_family) {
	case AF_INET:
		qry->ns.addr[index].ip4 = *(const struct sockaddr_in *)sock;
		break;
	case AF_INET6:
		qry->ns.addr[index].ip6 = *(const struct sockaddr_in6 *)sock;
		break;
	default:
		qry->ns.addr[index].ip.sa_family = AF_UNSPEC;
		return kr_error(EINVAL);
	}

	/* Retrieve RTT from cache */
	struct kr_context *ctx = qry->ns.ctx;
	kr_nsrep_rtt_lru_entry_t *rtt_cache_entry = ctx
		? lru_get_try(ctx->cache_rtt, kr_inaddr(sock), kr_family_len(sock->sa_family))
		: NULL;
	if (rtt_cache_entry) {
		qry->ns.score = MIN(qry->ns.score, rtt_cache_entry->score);
	}

	return kr_ok();
}

#define ELECT_INIT(ns, ctx_) do { \
	(ns)->ctx = (ctx_); \
	(ns)->addr[0].ip.sa_family = AF_UNSPEC; \
	(ns)->reputation = 0; \
	(ns)->score = KR_NS_MAX_SCORE + 1; \
} while (0)

static inline bool am_i_lucky()
{
	return kr_rand_uint(100) < 20;
}

int kr_nsrep_elect(struct kr_query *qry, struct kr_context *ctx)
{
	if (!qry || !ctx) {
		return kr_error(EINVAL);
	}

	struct kr_nsrep *ns = &qry->ns;
	ELECT_INIT(ns, ctx);
	struct nsrep_p param = {
		.qry = qry,
		.feeling_lucky = am_i_lucky(),
	};
	int ret = map_walk(&qry->zone_cut.nsset, eval_nsrep, &param);
	if (qry->ns.score <= KR_NS_MAX_SCORE && qry->ns.score >= KR_NS_LONG) {
		/* This is a low-reliability probe,
		 * go with TCP to get ICMP reachability check. */
		qry->flags.TCP = true;
	}
	return ret;
}

int kr_nsrep_elect_addr(struct kr_query *qry, struct kr_context *ctx)
{
	if (!qry || !ctx) {
		return kr_error(EINVAL);
	}

	/* Get address list for this NS */
	struct kr_nsrep *ns = &qry->ns;
	ELECT_INIT(ns, ctx);
	pack_t *addr_set = map_get(&qry->zone_cut.nsset, (const char *)ns->name);
	if (!addr_set) {
		return kr_error(ENOENT);
	}
	/* Evaluate addr list */
	uint8_t *addr_choice[KR_NSREP_MAXADDR] = { NULL, };
	unsigned score = eval_addr_set(addr_set, ctx, am_i_lucky(), addr_choice, NULL);
	update_nsrep_set(ns, ns->name, addr_choice, score);
	return kr_ok();
}

#undef ELECT_INIT

int kr_nsrep_update_rtt(struct kr_nsrep *ns, const struct sockaddr *addr,
			unsigned score, kr_nsrep_rtt_lru_t *cache, int umode)
{
	if (!cache || umode > KR_NS_MAX || umode < 0) {
		return kr_error(EINVAL);
	}

	const char *addr_in = NULL;
	size_t addr_len = 0;
	if (addr) { /* Caller provided specific address */
		if (addr->sa_family == AF_INET) {
			addr_in = (const char *)&((struct sockaddr_in *)addr)->sin_addr;
			addr_len = sizeof(struct in_addr);
		} else if (addr->sa_family == AF_INET6) {
			addr_in = (const char *)&((struct sockaddr_in6 *)addr)->sin6_addr;
			addr_len = sizeof(struct in6_addr);
		} else {
			assert(false && "kr_nsrep_update_rtt: unexpected address family");
		}
	} else if (ns != NULL && ns->addr[0].ip.sa_family != AF_UNSPEC) {
		addr_in = kr_inaddr(&ns->addr[0].ip);
		addr_len = kr_inaddr_len(&ns->addr[0].ip);
	} else {
		return kr_error(EINVAL);
	}

	assert(addr_in != NULL && addr_len > 0);

	bool is_new_entry = false;
	kr_nsrep_rtt_lru_entry_t  *cur = lru_get_new(cache, addr_in, addr_len,
						     (&is_new_entry));
	if (!cur) {
		return kr_ok();
	}
	if (score <= KR_NS_GLUED) {
		score = KR_NS_GLUED + 1;
	}
	/* If there's nothing to update, we reset it unless KR_NS_UPDATE_NORESET
	 * mode was requested.  New items are zeroed by LRU automatically. */
	if (is_new_entry && umode != KR_NS_UPDATE_NORESET) {
		umode = KR_NS_RESET;
	}
	unsigned new_score = 0;
	/* Update score, by default smooth over last two measurements. */
	switch (umode) {
	case KR_NS_UPDATE:
	case KR_NS_UPDATE_NORESET:
		new_score = (cur->score + score) / 2; break;
	case KR_NS_RESET:  new_score = score; break;
	case KR_NS_ADD:    new_score = MIN(KR_NS_MAX_SCORE - 1, cur->score + score); break;
	case KR_NS_MAX:    new_score = MAX(cur->score, score); break;
	default:           return kr_error(EINVAL);
	}
	/* Score limits */
	if (new_score > KR_NS_MAX_SCORE) {
		new_score = KR_NS_MAX_SCORE;
	}
	if (new_score >= KR_NS_TIMEOUT && cur->score < KR_NS_TIMEOUT) {
		/* Set the timestamp only when NS became "timeouted" */
		cur->tout_timestamp = kr_now();
	}
	cur->score = new_score;
	return kr_ok();
}

int kr_nsrep_update_rep(struct kr_nsrep *ns, unsigned reputation, kr_nsrep_lru_t *cache)
{
	if (!ns || !cache ) {
		return kr_error(EINVAL);
	}

	/* Store in the struct */
	ns->reputation = reputation;
	/* Store reputation in the LRU cache */
	unsigned *cur = lru_get_new(cache, (const char *)ns->name,
				    knot_dname_size(ns->name), NULL);
	if (cur) {
		*cur = reputation;
	}
	return kr_ok();
}

int kr_nsrep_copy_set(struct kr_nsrep *dst, const struct kr_nsrep *src)
{
	if (!dst || !src ) {
		return kr_error(EINVAL);
	}

	memcpy(dst, src, sizeof(struct kr_nsrep));
	dst->name = (const uint8_t *)"";
	dst->score = KR_NS_UNKNOWN;
	dst->reputation = 0;

	return kr_ok();
}

int kr_nsrep_sort(struct kr_nsrep *ns, kr_nsrep_rtt_lru_t *rtt_cache)
{
	if (!ns || !rtt_cache) {
		assert(false);
		return kr_error(EINVAL);
	}

	if (ns->addr[0].ip.sa_family == AF_UNSPEC) {
		return kr_error(EINVAL);
	}

	if (ns->addr[1].ip.sa_family == AF_UNSPEC) {
		/* We have only one entry here, do nothing */
		return kr_ok();
	}

	/* Compute the scores.  Unfortunately there's no space for scores
	 * along the addresses. */
	unsigned scores[KR_NSREP_MAXADDR];
	int i;
	for (i = 0; i < KR_NSREP_MAXADDR; ++i) {
		const struct sockaddr *sa = &ns->addr[i].ip;
		if (sa->sa_family == AF_UNSPEC) {
			break;
		}
		kr_nsrep_rtt_lru_entry_t *rtt_cache_entry = lru_get_try(rtt_cache,
									kr_inaddr(sa),
									kr_family_len(sa->sa_family));
		if (!rtt_cache_entry) {
			scores[i] = 1; /* prefer unknown to probe RTT */
		} else if ((kr_rand_uint(100) < 10) &&
			   (kr_rand_uint(KR_NS_MAX_SCORE) >= rtt_cache_entry->score)) {
			/* some probability to bump bad ones up for re-probe */
			scores[i] = 1;
		} else {
			scores[i] = rtt_cache_entry->score;
			if (sa->sa_family == AF_INET) {
				scores[i] += FAVOUR_IPV6;
			}
		}
		if (VERBOSE_STATUS) {
			char sa_str[INET6_ADDRSTRLEN];
			inet_ntop(sa->sa_family, kr_inaddr(sa), sa_str, sizeof(sa_str));
			kr_log_verbose("[     ][nsre] score %d for %s;\t cached RTT: %d\n",
					scores[i], sa_str,
					rtt_cache_entry ? rtt_cache_entry->score : -1);
		}
	}

	/* Select-sort the addresses. */
	const int count = i;
	for (i = 0; i < count - 1; ++i) {
		/* find min from i onwards */
		int min_i = i;
		for (int j = i + 1; j < count; ++j) {
			if (scores[j] < scores[min_i]) {
				min_i = j;
			}
		}
		/* swap the indices */
		if (min_i != i) {
			SWAP(scores[min_i], scores[i]);
			SWAP(ns->addr[min_i], ns->addr[i]);
		}
	}

	/* At least two addresses must be in the address list */
	assert(count > 0);
	ns->score = scores[0];
	ns->reputation = 0;
	return kr_ok();
}
