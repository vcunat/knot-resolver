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

#include <assert.h>

#include <libknot/descriptor.h>
#include <libknot/errcode.h>
#include <libknot/rrset.h>
#include <libknot/rrtype/rrsig.h>
#include <libknot/rrtype/rdname.h>
#include <ucw/config.h>
#include <ucw/lib.h>

#include "lib/layer/iterate.h"
#include "lib/cache.h"
#include "lib/module.h"
#include "lib/utils.h"
#include "lib/resolve.h"

#define VERBOSE_MSG(qry, fmt...) QRVERBOSE((qry), " rc ",  fmt)
#define DEFAULT_MINTTL (5) /* Short-time "no data" retention to avoid bursts */

/** Record is expiring if it has less than 1% TTL (or less than 5s) */
static inline bool is_expiring(const knot_rrset_t *rr, uint32_t drift)
{
	return 100 * (drift + 5) > 99 * knot_rrset_ttl(rr);
}

static int loot_rr(struct kr_cache *cache, knot_pkt_t *pkt, const knot_dname_t *name,
                  uint16_t rrclass, uint16_t rrtype, struct kr_query *qry,
                  uint8_t *rank, uint8_t *flags, bool fetch_rrsig, uint8_t lowest_rank)
{
	/* Check if record exists in cache */
	int ret = 0;
	uint32_t drift = qry->timestamp.tv_sec;
	knot_rrset_t cache_rr;
	knot_rrset_init(&cache_rr, (knot_dname_t *)name, rrtype, rrclass);
	if (fetch_rrsig) {
		ret = kr_cache_peek_rrsig(cache, &cache_rr, rank, flags, &drift);
	} else {
		ret = kr_cache_peek_rr(cache, &cache_rr, rank, flags, &drift);
	}
	if (ret != 0) {
		return ret;
	}

	if (rank && (*rank < lowest_rank)) {
		return kr_error(ENOENT);
	}

	/* Mark as expiring if it has less than 1% TTL (or less than 5s) */
	if (is_expiring(&cache_rr, drift)) {
		qry->flags |= QUERY_EXPIRING;
	}

	assert(flags != NULL);
	if ((*flags) & KR_CACHE_FLAG_WCARD_PROOF) {
		/* Record was found, but wildcard answer proof is needed.
		 * Do not update packet, try to fetch whole packet from pktcache instead. */
		qry->flags |= QUERY_DNSSEC_WEXPAND;
		return kr_error(ENOENT);
	}

	/* Update packet question */
	if (!knot_dname_is_equal(knot_pkt_qname(pkt), name)) {
		kr_pkt_recycle(pkt);
		knot_pkt_put_question(pkt, qry->sname, qry->sclass, qry->stype);
	}

	/* Update packet answer */
	knot_rrset_t rr_copy;
	ret = kr_cache_materialize(&rr_copy, &cache_rr, drift, qry->reorder, &pkt->mm);
	if (ret == 0) {
		ret = knot_pkt_put(pkt, KNOT_COMPR_HINT_QNAME, &rr_copy, KNOT_PF_FREE);
		if (ret != 0) {
			knot_rrset_clear(&rr_copy, &pkt->mm);
		}
	}
	return ret;
}

/** @internal Try to find a shortcut directly to searched record. */
static int loot_rrcache(struct kr_cache *cache, knot_pkt_t *pkt,
			struct kr_query *qry, uint16_t rrtype, const bool cdbit)
{
	/* Lookup direct match first */
	uint8_t rank  = 0;
	uint8_t flags = 0;
	uint8_t lowest_rank = cdbit ? KR_RANK_BAD : KR_RANK_INSECURE;
	const bool dobit = (qry->flags & QUERY_DNSSEC_WANT);
	int ret = loot_rr(cache, pkt, qry->sname, qry->sclass, rrtype, qry,
			  &rank, &flags, 0, lowest_rank);
	if (ret != 0 && rrtype != KNOT_RRTYPE_CNAME) {
		/* Chase CNAME if no direct hit */
		rrtype = KNOT_RRTYPE_CNAME;
		ret = loot_rr(cache, pkt, qry->sname, qry->sclass, rrtype, qry,
			      &rank, &flags, 0, lowest_rank);
	}
	/* Record is flagged as INSECURE => doesn't have RRSIG. */
	if (ret == 0 && (rank & KR_RANK_INSECURE)) {
		qry->flags |= QUERY_DNSSEC_INSECURE;
		qry->flags &= ~QUERY_DNSSEC_WANT;
	/* Record may have RRSIG, try to find it. */
	} else if (ret == 0 && dobit) {
		ret = loot_rr(cache, pkt, qry->sname, qry->sclass, rrtype, qry,
			      &rank, &flags, true, lowest_rank);
	}
	return ret;
}

static int rrcache_peek(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;
	if (ctx->state & (KR_STATE_FAIL|KR_STATE_DONE) || (qry->flags & QUERY_NO_CACHE)) {
		return ctx->state; /* Already resolved/failed */
	}
	if (qry->ns.addr[0].ip.sa_family != AF_UNSPEC) {
		return ctx->state; /* Only lookup before asking a query */
	}
	const bool cd_is_set = knot_wire_get_cd(req->answer->wire);
	/* Reconstruct the answer from the cache,
	 * it may either be a CNAME chain or direct answer.
	 * Only one step of the chain is resolved at a time.
	 */
	struct kr_cache *cache = &req->ctx->cache;
	int ret = -1;
	if (qry->stype != KNOT_RRTYPE_ANY) {
		ret = loot_rrcache(cache, pkt, qry, qry->stype, cd_is_set);
	} else {
		/* ANY query are used by either qmail or certain versions of Firefox.
		 * Probe cache for a few interesting records. */
		static uint16_t any_types[] = { KNOT_RRTYPE_A, KNOT_RRTYPE_AAAA, KNOT_RRTYPE_MX };
		for (size_t i = 0; i < sizeof(any_types)/sizeof(any_types[0]); ++i) {
			if (loot_rrcache(cache, pkt, qry, any_types[i], cd_is_set) == 0) {
				ret = 0; /* At least single record matches */
			}
		}
	}
	if (ret == 0) {
		VERBOSE_MSG(qry, "=> satisfied from cache\n");
		qry->flags |= QUERY_CACHED|QUERY_NO_MINIMIZE;
		pkt->parsed = pkt->size;
		knot_wire_set_qr(pkt->wire);
		knot_wire_set_aa(pkt->wire);
		return KR_STATE_DONE;
	}
	return ctx->state;
}

/** @internal Baton for stash_commit */
struct rrcache_baton
{
	struct kr_request *req;
	struct kr_query *qry;
	struct kr_cache *cache;
	unsigned timestamp;
	uint32_t min_ttl;
};

static int commit_rrsig(struct rrcache_baton *baton, uint8_t rank, uint8_t flags, knot_rrset_t *rr)
{
	/* If not doing secure resolution, ignore (unvalidated) RRSIGs. */
	if (!(baton->qry->flags & QUERY_DNSSEC_WANT)) {
		return kr_ok();
	}
	/* Commit covering RRSIG to a separate cache namespace. */
	return kr_cache_insert_rrsig(baton->cache, rr, rank, flags, baton->timestamp);
}

static int commit_rr(const char *key, void *val, void *data)
{
	knot_rrset_t *rr = val;
	struct rrcache_baton *baton = data;
	/* Ensure minimum TTL */
	knot_rdata_t *rd = rr->rrs.data;
	for (uint16_t i = 0; i < rr->rrs.rr_count; ++i) {
		if (knot_rdata_ttl(rd) < baton->min_ttl) {
			knot_rdata_set_ttl(rd, baton->min_ttl);
		}
		rd = kr_rdataset_next(rd);
	}

	/* Save RRSIG in a special cache. */
	uint8_t rank = KEY_FLAG_RANK(key);
	/* Non-authoritative NSs should never be trusted,
	 * it may be present in an otherwise secure answer but it
	 * is only a hint for local state. */
	if (rr->type != KNOT_RRTYPE_NS || (rank & KR_RANK_AUTH)) {
		if (baton->qry->flags & QUERY_DNSSEC_WANT &&
		    rank != KR_RANK_BAD) {
			rank |= KR_RANK_SECURE;
		}
	}
	if (baton->qry->flags & QUERY_DNSSEC_INSECURE && rank != KR_RANK_BAD) {
		rank |= KR_RANK_INSECURE;
	}
	if (KEY_COVERING_RRSIG(key)) {
		return commit_rrsig(baton, rank, KR_CACHE_FLAG_NONE, rr);
	}
	/* Accept only better rank (if not overriding) */
	if (!(rank & KR_RANK_SECURE) && !(baton->qry->flags & QUERY_NO_CACHE)) {
		int cached_rank = kr_cache_peek_rank(baton->cache, KR_CACHE_RR, rr->owner, rr->type, baton->timestamp);
		if (cached_rank >= rank) {
			return kr_ok();
		}
	}

	uint8_t flags = KR_CACHE_FLAG_NONE;
	if ((rank & KR_RANK_AUTH) && (baton->qry->flags & QUERY_DNSSEC_WEXPAND)) {
		flags |= KR_CACHE_FLAG_WCARD_PROOF;
	}
	return kr_cache_insert_rr(baton->cache, rr, rank, flags, baton->timestamp);
}

static int stash_commit(map_t *stash, struct kr_query *qry, struct kr_cache *cache, struct kr_request *req)
{
	struct rrcache_baton baton = {
		.req = req,
		.qry = qry,
		.cache = cache,
		.timestamp = qry->timestamp.tv_sec,
		.min_ttl = DEFAULT_MINTTL
	};
	return map_walk(stash, &commit_rr, &baton);
}

static void stash_glue(map_t *stash, knot_pkt_t *pkt, const knot_dname_t *ns_name, knot_mm_t *pool)
{
	const knot_pktsection_t *additional = knot_pkt_section(pkt, KNOT_ADDITIONAL);
	for (unsigned i = 0; i < additional->count; ++i) {
		const knot_rrset_t *rr = knot_pkt_rr(additional, i);
		if ((rr->type != KNOT_RRTYPE_A && rr->type != KNOT_RRTYPE_AAAA) ||
		    !knot_dname_is_equal(rr->owner, ns_name)) {
			continue;
		}
		kr_rrmap_add(stash, rr, KR_RANK_EXTRA, pool);
	}
}

/* @internal DS is special and is present only parent-side */
static void stash_ds(struct kr_request *req, knot_pkt_t *pkt, map_t *stash, knot_mm_t *pool)
{
	ranked_rr_array_t *arr= &req->auth_selected;
	if (!arr->len) {
		return;
	}
	struct kr_query *qry = req->current_query;
	uint8_t rank = KR_RANK_AUTH;
	if (knot_wire_get_cd(req->answer->wire)) {
		/* Signature validation is disabled,
		 * save it to the BAD cache */
		rank = KR_RANK_BAD;
	}
	/* uncached entries are located at the end */
	for (ssize_t i = arr->len - 1; i >= 0; --i) {
		ranked_rr_array_entry_t *entry = arr->at[i];
		const knot_rrset_t *rr = entry->rr;
		if (entry->qry_uid != qry->uid) {
			continue;
		}
		if (entry->cached) {
			continue;
		}
		if (rr->type == KNOT_RRTYPE_DS || rr->type == KNOT_RRTYPE_RRSIG) {
			kr_rrmap_add(stash, rr, rank, pool);
			entry->cached = true;
		}
	}
}

static int stash_authority(struct kr_request *req, knot_pkt_t *pkt, map_t *stash, knot_mm_t *pool)
{
	ranked_rr_array_t *arr= &req->auth_selected;
	if (!arr->len) {
		return kr_ok();
	}
	struct kr_query *qry = req->current_query;
	uint8_t rank = KR_RANK_NONAUTH;
	if (knot_wire_get_cd(req->answer->wire)) {
		/* Signature validation is disabled,
		 * save authority to the BAD cache */
		rank = KR_RANK_BAD;
	}
	/* uncached entries are located at the end */
	for (ssize_t i = arr->len - 1; i >= 0; --i) {
		ranked_rr_array_entry_t *entry = arr->at[i];
		const knot_rrset_t *rr = entry->rr;
		if (entry->qry_uid != qry->uid) {
			continue;
		}
		if (entry->cached) {
			continue;
		}
		/* Look up glue records for NS */
		if (rr->type == KNOT_RRTYPE_NS) {
			const knot_dname_t *ns_name = knot_ns_name(&rr->rrs, 0);
			if (qry->flags & QUERY_PERMISSIVE || knot_dname_in(qry->zone_cut.name, ns_name)) {
				stash_glue(stash, pkt, ns_name, pool);
			}
		}
		kr_rrmap_add(stash, rr, rank, pool);
		entry->cached = true;
	}
	return kr_ok();
}

static int stash_answer(struct kr_request *req, knot_pkt_t *pkt, map_t *stash, knot_mm_t *pool)
{
	ranked_rr_array_t *arr= &req->answ_selected;
	struct kr_query *qry = req->current_query;
	if (!arr->len) {
		return kr_ok();
	}
	uint8_t rank = KR_RANK_AUTH;
	if (knot_wire_get_cd(req->answer->wire)) {
		/* Signature validation is disabled.
		 * Save answer to the BAD cache. */
		rank = KR_RANK_BAD;
	}
	/* uncached entries are located at the end */
	for (ssize_t i = arr->len - 1; i >= 0; --i) {
		ranked_rr_array_entry_t *entry = arr->at[i];
		if (entry->qry_uid != qry->uid) {
			continue;
		}
		if (entry->cached) {
			continue;
		}
		const knot_rrset_t *rr = entry->rr;
		kr_rrmap_add(stash, rr, rank, pool);
		entry->cached = true;
	}
	return kr_ok();
}

static int rrcache_stash(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;
	if (!qry || ctx->state & KR_STATE_FAIL) {
		return ctx->state;
	}
	/* Do not cache truncated answers. */
	if (knot_wire_get_tc(pkt->wire)) {
		return ctx->state;
	}

	/* Cache only positive answers, not meta types or RRSIG. */
	const uint16_t qtype = knot_pkt_qtype(pkt);
	const bool is_eligible = !(knot_rrtype_is_metatype(qtype) || qtype == KNOT_RRTYPE_RRSIG);
	if (qry->flags & QUERY_CACHED || knot_wire_get_rcode(pkt->wire) != KNOT_RCODE_NOERROR || !is_eligible) {
		return ctx->state;
	}
	/* Stash in-bailiwick data from the AUTHORITY and ANSWER. */
	map_t stash = map_make();
	stash.malloc = (map_alloc_f) mm_alloc;
	stash.free = (map_free_f) mm_free;
	stash.baton = &req->pool;
	int ret = 0;
	bool is_auth = knot_wire_get_aa(pkt->wire);
	if (is_auth) {
		ret = stash_answer(req, pkt, &stash, &req->pool);
		if (ret == 0) {
			ret = stash_authority(req, pkt, &stash, &req->pool);
		}
	/* Cache authority only if chasing referral/cname chain */
	} else if (knot_pkt_section(pkt, KNOT_ANSWER)->count == 0 ||
		   qry->flags & QUERY_CNAME) {
		ret = stash_authority(req, pkt, &stash, &req->pool);
	}
	/* Cache DS records in referrals */
	if (!is_auth && knot_pkt_has_dnssec(pkt)) {
		stash_ds(req, pkt, &stash, &req->pool);
	}
	/* Cache stashed records */
	if (ret == 0 && stash.root != NULL) {
		/* Open write transaction */
		struct kr_cache *cache = &req->ctx->cache;
		ret = stash_commit(&stash, qry, cache, req);
		/* Clear if full */
		if (ret == kr_error(ENOSPC)) {
			ret = kr_cache_clear(cache);
			if (ret != 0 && ret != kr_error(EEXIST)) {
				kr_log_error("[cache] failed to clear cache: %s\n", kr_strerror(ret));
			}
		}
		kr_cache_sync(cache);
	}
	return ctx->state;
}

/** Module implementation. */
const kr_layer_api_t *rrcache_layer(struct kr_module *module)
{
	static const kr_layer_api_t _layer = {
		.produce = &rrcache_peek,
		.consume = &rrcache_stash
	};

	return &_layer;
}

KR_MODULE_EXPORT(rrcache)

#undef VERBOSE_MSG
