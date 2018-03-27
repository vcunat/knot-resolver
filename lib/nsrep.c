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
#include "contrib/cleanup.h"
#include "contrib/ucw/lib.h"

#define VERBOSE_MSG(qry, fmt...) QRVERBOSE(qry, "nsre", fmt)

/** Some built-in unfairness ... */
#ifndef FAVOUR_IPV6
#define FAVOUR_IPV6 20 /* 20ms bonus for v6 */
#endif


/** Select which addresses to query xor for which NS to obtain addresses.
 *
 * \param probed_ns give advantage to qry->ns.name addresses
 * 		    (and don't select yet another NS to obtain addresses for)
 */
static int elect(struct kr_query *qry, bool probed_ns);
/** One big step of elect. */
static int elect_step(const char *ns_name, void *ns_addrs, void *elect_p);

int kr_nsrep_elect(struct kr_query *qry, struct kr_context *ctx)
{
	if (!qry || !ctx) {
		return kr_error(EINVAL);
	}
	return elect(qry, false);
}

int kr_nsrep_elect_addr(struct kr_query *qry, struct kr_context *ctx)
{
	if (!qry || !ctx) {
		return kr_error(EINVAL);
	}
	return elect(qry, true);
}

/** Address info for elect* functions. */
struct elect_ai {
	uint8_t *addr; /**< address - pointer to pack_obj  */
	unsigned score; /**< it may be RTT estimate and it may be something else */
	bool is_timeouted; /**< address previously classified as non-responding */
	kr_nsrep_rtt_lru_entry_t *cached; /**< cached RTT estimate or NULL */
};

/** Various data for elect* functions. */
struct elect_p {
	/* Selection options (constant during the process). */
	bool explore_ns; /**< Whether to prefer NSs without any known IPs. */
	bool explore_ip; /**< Whether to prepend some random IP into ai_explored. */
	struct kr_query *qry;
	uint64_t now; /**< cached kr_now() */

	/** Input: if (!explore_ns && ns_name), this NS's IPs are to be preferred.
	 *
	 * Output: if non-NULL, the current winner is to obtain addresses for this NS.
	 * That case makes ais redundant.
	 * The associated score and reputation for this case is separate. */
	const knot_dname_t *ns_name;
	unsigned score, reputation;

	/* Logged counts: considered addresses (after IPvX filter), names without addresses. */
	int cnt_ip, cnt_noip;

	/** Additional address, for exploration (unknown RTT). */
	struct elect_ai ai_explored;
	/** Otherwise this is the currently best list of addresses. */
	struct elect_ai ais[KR_NSREP_MAXADDR];
};

static int elect(struct kr_query *qry, bool probed_ns)
{
	if (!qry) {
		return kr_error(EINVAL);
	}

	struct kr_nsrep *ns = &qry->ns;
	ns->ctx = qry->request->ctx;

	/* Set up a struct elect_p; it's slightly messy. */
	struct elect_p p;
	if (probed_ns) {
		assert(ns->name && *ns->name);
		p.ns_name = ns->name;
		p.explore_ns = false;
		p.explore_ip = false;
	} else {
		p.ns_name = NULL;
		int rnd = kr_rand_uint(100);
		p.explore_ns = rnd < 20; /*< can be relatively costly */
		p.explore_ip = rnd < 40; /*< only adds one KR_CONN_RETRY at worst */
	}
	p.qry = qry;
	p.now = kr_now();
	p.score = KR_NS_MAX_SCORE + 1;
	p.reputation = 0;
 	p.ais[0] = p.ai_explored =
		(struct elect_ai){ .addr = NULL, .score = KR_NS_MAX_SCORE + 1, };
	p.cnt_ip = p.cnt_noip = 0;

	int ret = map_walk(&qry->zone_cut.nsset, elect_step, &p);
	assert(ret == kr_ok()); /* not using this so far */

	if (!p.ais[0].addr) {
		/* No address chosen.
		 * TODO: two options: with NS exploration and without it. verify! */
		ns->addr[0].ip.sa_family = AF_UNSPEC;
		if (p.ns_name) {
			/* we at least chose a NS name */
			ns->name = p.ns_name;
			ns->score = KR_NS_UNKNOWN;
			ns->reputation = p.reputation;
		} else {
			ns->score = KR_NS_MAX_SCORE + 1;
		}
		WITH_VERBOSE(qry) {
			auto_free char *ns_stor = NULL;
			const char *ns_str;
			if (p.ns_name) {
				ns_str = ns_stor = kr_dname_text(p.ns_name);
			} else {
				ns_str = "<NONE>";
			}
			VERBOSE_MSG(qry, "decided to find addresses of %s "
					"(IP cnt: %d, noIP cnt: %d, mode: %s%s%s, reput: %d)\n",
					ns_str,
					p.cnt_ip, p.cnt_noip, probed_ns ? "1" : "a",
					p.explore_ns ? "n" : "", p.explore_ip ? "i" : "",
					p.reputation);
		}
		return kr_ok();
	}

	VERBOSE_MSG(qry, "chosen NS addresses to try "
			"(IP cnt: %d, noIP cnt: %d, mode: %s%s%s):\n",
			p.cnt_ip, p.cnt_noip, probed_ns ? "1" : "a",
			p.explore_ns ? "n" : "", p.explore_ip ? "i" : "");
	/* Now collect all the chosen addresses.  If we have ai_explored,
	 * it gets prepended at the start of the array, shifting it effectively.
	 * Also bump timeouted addresses on the way, if we've chosen them. */
	assert(p.ais - 1 == &p.ai_explored); /*< we use this hack, so check it */
	struct elect_ai *ais = p.ai_explored.addr ? &p.ai_explored : p.ais;
	ns->score = (ais[0].addr && !ais[0].cached) ? KR_NS_UNKNOWN : ais[0].score;
	ns->name = p.ns_name;
	ns->reputation = 0;
	for (int i = 0; i < KR_NSREP_MAXADDR; ++i) {
		if (!ais[i].addr) { /* this was the last (non-sensical) element */
			ns->addr[i].ip.sa_family = AF_UNSPEC;
			break;
		}
		/* Set ns->addr[i] */
		const void *val = pack_obj_val(ais[i].addr);
		const int len = pack_obj_len(ais[i].addr);
		switch (len) {
		case sizeof(struct in_addr):
			ns->addr[i].ip4.sin_family = AF_INET;
			ns->addr[i].ip4.sin_port = htons(KR_DNS_PORT);
			memcpy(&ns->addr[i].ip4.sin_addr, val, len);
			break;
		case sizeof(struct in6_addr):
			ns->addr[i].ip6.sin6_family = AF_INET6;
			ns->addr[i].ip6.sin6_port = htons(KR_DNS_PORT);
			ns->addr[i].ip6.sin6_flowinfo = 0;
			memcpy(&ns->addr[i].ip6.sin6_addr, val, len);
			ns->addr[i].ip6.sin6_scope_id = 0;
			/* TODO: are those two zeros the right thing to do? */
			break;
		default:
			assert(false);
			ns->addr[i].ip.sa_family = AF_UNSPEC;
		}

		WITH_VERBOSE(qry) {
			char sa_str[INET6_ADDRSTRLEN];
			int af = (len == sizeof(struct in6_addr)) ? AF_INET6 : AF_INET;
			inet_ntop(af, val, sa_str, sizeof(sa_str));
			const char *score_tag = ais[i].is_timeouted ? "T" :
				(p.ai_explored.addr && i == 0 ? "E" : " ");
			VERBOSE_MSG(qry, "  score %4d%s rtt %4d    %s\n",
					ais[i].score, score_tag,
					ais[i].cached ? ais[i].cached->score : -1,
					sa_str);
		}

		if (!ais[i].is_timeouted) continue;
		/* If we've decided to add timeouted NSs into the list, we bump
		 * their timestamps so they aren't also attempted in the meantime
		 * before we know the result of this probe.
		 * TODO: this isn't perfect, as there's no guarantee
		 * that we will actually probe *all* of those servers.
		 */
		if (!ais[i].cached) {
			/* Never happens, but the linter is unable to deduce that,
			 * and it would block CI. */
			assert(false);
			continue;
		}
		ais[i].cached->tout_timestamp = p.now;
	}

	if (ns->score <= KR_NS_MAX_SCORE && ns->score >= KR_NS_LONG) {
		/* This is a low-reliability probe,
		 * go with TCP to get ICMP reachability check.
		 * LATER: better do such things per-IP. */
		qry->flags.TCP = true;
	}
	return kr_ok();
}

static int elect_step(const char *ns_name, void *ns_addrs, void *elect_p)
{
	const knot_dname_t *name = (const knot_dname_t *)ns_name;
	struct elect_p *p = elect_p;
	struct kr_context *ctx = p->qry->ns.ctx;
	pack_t *addr_set = (pack_t *)ns_addrs;

	/* Try to fill ns_name at least with something. */
	if (!p->ns_name) {
		p->ns_name = name;
	}

	if (addr_set->len == 0) {
		++p->cnt_noip;
		/* No addresses known for this NS; we choose it
		 * if we have no addresses so far or if feeling_lucky. */
		const bool ok = !p->ais[0].addr || p->explore_ns;
		if (!ok) return kr_ok();

		/* Fetch NS reputation */
		unsigned reputation = 0;
		if (ctx->cache_rep) {
			unsigned *cached = lru_get_try(ctx->cache_rep, ns_name,
						       knot_dname_size(name));
			if (cached) {
				reputation = *cached;
			}
		}

		/* If the server doesn't have IPv6, give it disadvantage. */
		unsigned score = kr_rand_uint(FAVOUR_IPV6);
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

		/* Switch the current winner, if we're better. */
		if (score < p->score) {
			p->ns_name = name;
			p->score = score;
			p->reputation = reputation;
		}
		return kr_ok();
	}

	/* Otherwise we know (some?) addresses for this NS, so and inspect them all
	 * and sort them into the best-of list.
	 * We don't do this it we've already decided that exploring another
	 * new NS is better.
	 */
	if (p->explore_ns && p->ns_name) {
		return kr_ok();
	}
	const bool prefer_this_ns = !p->explore_ns && p->ns_name
				&& knot_dname_is_equal(p->ns_name, name);

	const struct kr_qflags opts = ctx->options;
	kr_nsrep_rtt_lru_t *rtt_cache = ctx->cache_rtt;
	for (uint8_t *it = pack_head(*addr_set); it != pack_tail(*addr_set);
						it = pack_obj_next(it)) {
		void *val = pack_obj_val(it);
		size_t len = pack_obj_len(it);
		unsigned penalty = 0;

		/* Check if the address isn't disabled. */
		bool is_valid = false;
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
		++p->cnt_ip;

		/* Get all the information for the current address. */
		struct elect_ai ai;
		memset(&ai, 0, sizeof(ai));
		ai.addr = it;
		if (prefer_this_ns) {
			ai.score = 1;
		} else {
			ai.cached = rtt_cache ? lru_get_try(rtt_cache, val, len) : NULL;
			ai.score = ai.cached ? ai.cached->score : kr_rand_uint(KR_NS_UNKNOWN);
		}
		if (ai.cached && ai.score >= KR_NS_TIMEOUT) {
			/* If NS was marked as "timeouted",
			 * it won't participate in NS elections
			 * at least ctx->cache_rtt_tout_retry_interval milliseconds. */
			uint64_t elapsed = p->now - ai.cached->tout_timestamp;
			assert(((int64_t)elapsed) >= 0);
			if (elapsed < ctx->cache_rtt_tout_retry_interval) {
				continue;
			}
			ai.score = kr_rand_uint(KR_NS_UNKNOWN);
			ai.is_timeouted = true;
		}
		ai.score = MIN(KR_NS_MAX_SCORE, ai.score + penalty);

		/* The "best" address to explore is kept separately (random choice). */
		if (p->explore_ip) {
			unsigned e_score = kr_rand_uint(KR_NS_UNKNOWN);
			if (p->ai_explored.score > e_score) {
				p->ai_explored = ai;
				p->ai_explored.score = e_score;
				p->ns_name = name;
			}
		}

		/* Insert ai into the sorted ais list (by the score). */
		for (int i = 0; i < KR_NSREP_MAXADDR; ++i) {
			if (!p->ais[i].addr) { /* empty place at the end */
				p->ais[i] = ai;
				if (i + 1 < KR_NSREP_MAXADDR) {
					p->ais[i + 1].addr = NULL;
				}
				if (i == 0) {
					p->ns_name = name;
				}
				break;
			}
			if (p->ais[i].score > ai.score) {
				/* Insert on this position i. LATER: memmove might be faster. */
				for (int j = KR_NSREP_MAXADDR - 1; j > i; --j) {
					p->ais[j] = p->ais[j - 1];
				}
				p->ais[i] = ai;
				if (i == 0) {
					p->ns_name = name;
				}
				break;
			}
		}
	}

	return kr_ok();
}
/* End of elect* functions. */


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
			VERBOSE_MSG(NULL, "score %d for %s;\t cached RTT: %d\n",
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
