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
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

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

#define DEBUG_MSG(fmt...) QRDEBUG(kr_rplan_current(rplan), " rc ",  fmt)
#define DEFAULT_MINTTL (5) /* Short-time "no data" retention to avoid bursts */

/* Stash key flags */
#define KEY_FLAG_NO 0x01
#define KEY_FLAG_RRSIG 0x02
#define KEY_FLAG_SET(key, flag) key[0] = (flag);
#define KEY_COVERING_RRSIG(key) (key[0] & KEY_FLAG_RRSIG)

/** Record is expiring if it has less than 1% TTL (or less than 5s) */
static inline bool is_expiring(const knot_rrset_t *rr, uint32_t drift)
{
	return 100 * (drift + 5) > 99 * knot_rrset_ttl(rr);
}

static int loot_rr(struct kr_cache_txn *txn, knot_pkt_t *pkt, const knot_dname_t *name,
                  uint16_t rrclass, uint16_t rrtype, struct kr_query *qry, bool fetch_rrsig)
{
	/* Check if record exists in cache */
	int ret = 0;
	uint32_t drift = qry->timestamp.tv_sec;
	knot_rrset_t cache_rr;
	knot_rrset_init(&cache_rr, (knot_dname_t *)name, rrtype, rrclass);
	if (fetch_rrsig) {
		ret = kr_cache_peek_rrsig(txn, &cache_rr, &drift);
	} else {
		ret = kr_cache_peek_rr(txn, &cache_rr, &drift);	
	}
	if (ret != 0) {
		return ret;
	}

	/* Mark as expiring if it has less than 1% TTL (or less than 5s) */
	if (is_expiring(&cache_rr, drift)) {
		if (qry->flags & QUERY_NO_EXPIRING) {
			return kr_error(ENOENT);
		} else {
			qry->flags |= QUERY_EXPIRING;
		}
	}

	/* Update packet question */
	if (!knot_dname_is_equal(knot_pkt_qname(pkt), name)) {
		KR_PKT_RECYCLE(pkt);
		knot_pkt_put_question(pkt, qry->sname, qry->sclass, qry->stype);
	}

	/* Update packet answer */
	knot_rrset_t rr_copy;
	ret = kr_cache_materialize(&rr_copy, &cache_rr, drift, &pkt->mm);
	if (ret == 0) {
		ret = knot_pkt_put(pkt, KNOT_COMPR_HINT_QNAME, &rr_copy, KNOT_PF_FREE);
		if (ret != 0) {
			knot_rrset_clear(&rr_copy, &pkt->mm);
		}
	}
	return ret;
}

/** @internal Try to find a shortcut directly to searched record. */
static int loot_cache(struct kr_cache *cache, knot_pkt_t *pkt, struct kr_query *qry, bool dobit)
{
	struct kr_cache_txn txn;
	int ret = kr_cache_txn_begin(cache, &txn, NAMEDB_RDONLY);
	if (ret != 0) {
		return ret;
	}
	/* Lookup direct match first */
	uint16_t rrtype = qry->stype;
	ret = loot_rr(&txn, pkt, qry->sname, qry->sclass, rrtype, qry, 0);
	if (ret != 0 && rrtype != KNOT_RRTYPE_CNAME) { /* Chase CNAME if no direct hit */
		rrtype = KNOT_RRTYPE_CNAME;
		ret = loot_rr(&txn, pkt, qry->sname, qry->sclass, rrtype, qry, 0);
	}
	/* Loot RRSIG if matched. */
	if (ret == 0 && dobit) {
		ret = loot_rr(&txn, pkt, qry->sname, qry->sclass, rrtype, qry, true);
	}
	kr_cache_txn_abort(&txn);
	return ret;
}

static int peek(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_request *req = ctx->data;
	struct kr_rplan *rplan = &req->rplan;
	struct kr_query *qry = kr_rplan_current(rplan);
	if (!qry || ctx->state & (KNOT_STATE_FAIL|KNOT_STATE_DONE)) {
		return ctx->state; /* Already resolved/failed */
	}
	if (qry->ns.addr.ip.sa_family != AF_UNSPEC) {
		return ctx->state; /* Only lookup before asking a query */
	}

	/* Reconstruct the answer from the cache,
	 * it may either be a CNAME chain or direct answer.
	 * Only one step of the chain is resolved at a time.
	 */
	struct kr_cache *cache = &req->ctx->cache;
	int ret = loot_cache(cache, pkt, qry, (qry->flags & QUERY_DNSSEC_WANT));
	if (ret == 0) {
		DEBUG_MSG("=> satisfied from cache\n");
		qry->flags |= QUERY_CACHED|QUERY_NO_MINIMIZE;
		pkt->parsed = pkt->size;
		knot_wire_set_qr(pkt->wire);
		knot_wire_set_aa(pkt->wire);
		return KNOT_STATE_DONE;
	}
	return ctx->state;
}

/** @internal Baton for stash_commit */
struct stash_baton
{
	struct kr_request *req;
	struct kr_query *qry;
	struct kr_cache_txn *txn;
	unsigned timestamp;
	uint32_t min_ttl;
};

static int commit_rrsig(struct stash_baton *baton, knot_rrset_t *rr)
{
	/* If not doing secure resolution, ignore (unvalidated) RRSIGs. */
	if (!(baton->qry->flags & QUERY_DNSSEC_WANT)) {
		return kr_ok();
	}
	/* Commit covering RRSIG to a separate cache namespace. */
	uint16_t covered = knot_rrsig_type_covered(&rr->rrs, 0);
	unsigned drift = baton->timestamp;
	knot_rrset_t query_rrsig;
	knot_rrset_init(&query_rrsig, rr->owner, covered, rr->rclass);
	if (kr_cache_peek_rrsig(baton->txn, &query_rrsig, &drift) == 0) {
		return kr_ok();
	}
	return kr_cache_insert_rrsig(baton->txn, rr, covered, baton->timestamp);
}

static int commit_rr(const char *key, void *val, void *data)
{
	knot_rrset_t *rr = val;
	struct stash_baton *baton = data;
	/* Ensure minimum TTL */
	knot_rdata_t *rd = rr->rrs.data;
	for (uint16_t i = 0; i < rr->rrs.rr_count; ++i) {
		if (knot_rdata_ttl(rd) < baton->min_ttl) {
			knot_rdata_set_ttl(rd, baton->min_ttl);
		}
		rd = kr_rdataset_next(rd);
	}

	/* Save RRSIG in a special cache. */
	unsigned drift = baton->timestamp;
	if (KEY_COVERING_RRSIG(key)) {
		return commit_rrsig(baton, rr);
	}

	/* Check if already cached */
	/** @todo This should check if less trusted data is in the cache,
	          for that the cache would need to trace data trust level.
	   */
	knot_rrset_t query_rr;
	knot_rrset_init(&query_rr, rr->owner, rr->type, rr->rclass);
	if (kr_cache_peek_rr(baton->txn, &query_rr, &drift) == 0) {
		/* Allow replace if RRSet in the cache is about to expire. */
		if (!is_expiring(&query_rr, drift)) {
		        return kr_ok();
		}
	}
	return kr_cache_insert_rr(baton->txn, rr, baton->timestamp);
}

static int stash_commit(map_t *stash, struct kr_query *qry, struct kr_cache_txn *txn, struct kr_request *req)
{
	struct stash_baton baton = {
		.req = req,
		.qry = qry,
		.txn = txn,
		.timestamp = qry->timestamp.tv_sec,
		.min_ttl = DEFAULT_MINTTL
	};
	return map_walk(stash, &commit_rr, &baton);
}

static int stash_add(const knot_pkt_t *pkt, map_t *stash, const knot_rrset_t *rr, mm_ctx_t *pool)
{
	/* Stash key = {[1] flags, [1-255] owner, [1-5] type, [1] \x00 } */
	char key[9 + KNOT_DNAME_MAXLEN];
	uint16_t rrtype = rr->type;
	KEY_FLAG_SET(key, KEY_FLAG_NO);

	/* Stash RRSIGs in a special cache, flag them and set type to its covering RR.
	 * This way it the stash won't merge RRSIGs together. */
	if (rr->type == KNOT_RRTYPE_RRSIG) {
		rrtype = knot_rrsig_type_covered(&rr->rrs, 0);
		KEY_FLAG_SET(key, KEY_FLAG_RRSIG);
	}

	uint8_t *key_buf = (uint8_t *)key + 1;
	int ret = knot_dname_to_wire(key_buf, rr->owner, KNOT_DNAME_MAXLEN);
	if (ret <= 0) {
		return ret;
	}
	knot_dname_to_lower(key_buf);
	/* Must convert to string, as the key must not contain 0x00 */
	ret = snprintf((char *)key_buf + ret - 1, sizeof(key) - KNOT_DNAME_MAXLEN, "%hu", rrtype);
	if (ret <= 0 || ret >= KNOT_DNAME_MAXLEN) {
		return kr_error(EILSEQ);
	}

	/* Check if already exists */
	knot_rrset_t *stashed = map_get(stash, key);
	if (!stashed) {
		stashed = knot_rrset_copy(rr, pool);
		if (!stashed) {
			return kr_error(ENOMEM);
		}
		return map_set(stash, key, stashed);
	}
	/* Merge rdataset */
	return knot_rdataset_merge(&stashed->rrs, &rr->rrs, pool);
}

static void stash_glue(map_t *stash, knot_pkt_t *pkt, const knot_dname_t *ns_name, mm_ctx_t *pool)
{
	const knot_pktsection_t *additional = knot_pkt_section(pkt, KNOT_ADDITIONAL);
	for (unsigned i = 0; i < additional->count; ++i) {
		const knot_rrset_t *rr = knot_pkt_rr(additional, i);
		if ((rr->type != KNOT_RRTYPE_A && rr->type != KNOT_RRTYPE_AAAA) ||
		    !knot_dname_is_equal(rr->owner, ns_name)) {
			continue;
		}
		stash_add(pkt, stash, rr, pool);
	}
}

/* @internal DS is special and is present only parent-side */
static void stash_ds(struct kr_query *qry, knot_pkt_t *pkt, map_t *stash, mm_ctx_t *pool)
{
	const knot_pktsection_t *authority = knot_pkt_section(pkt, KNOT_AUTHORITY);
	for (unsigned i = 0; i < authority->count; ++i) {
		const knot_rrset_t *rr = knot_pkt_rr(authority, i);
		if (rr->type == KNOT_RRTYPE_DS || rr->type == KNOT_RRTYPE_RRSIG) {
			stash_add(pkt, stash, rr, pool);
		}
	}
}

static int stash_authority(struct kr_query *qry, knot_pkt_t *pkt, map_t *stash, mm_ctx_t *pool)
{
	const knot_pktsection_t *authority = knot_pkt_section(pkt, KNOT_AUTHORITY);
	for (unsigned i = 0; i < authority->count; ++i) {
		const knot_rrset_t *rr = knot_pkt_rr(authority, i);
		/* Cache in-bailiwick data only */
		if (!knot_dname_in(qry->zone_cut.name, rr->owner)) {
			continue;
		}
		/* Look up glue records for NS */
		if (rr->type == KNOT_RRTYPE_NS) {
			stash_glue(stash, pkt, knot_ns_name(&rr->rrs, 0), pool);
		}
		/* Stash record */
		stash_add(pkt, stash, rr, pool);
	}
	return kr_ok();
}

static int stash_answer(struct kr_query *qry, knot_pkt_t *pkt, map_t *stash, mm_ctx_t *pool)
{
	const knot_dname_t *cname = qry->sname;
	const knot_pktsection_t *answer = knot_pkt_section(pkt, KNOT_ANSWER);
	for (unsigned i = 0; i < answer->count; ++i) {
		/* Stash direct answers (equal to current QNAME/CNAME),
		 * accept out-of-order RRSIGS. */
		const knot_rrset_t *rr = knot_pkt_rr(answer, i);
		if (!knot_dname_is_equal(rr->owner, cname)
		    && rr->type != KNOT_RRTYPE_RRSIG) {
			continue;
		}
		stash_add(pkt, stash, rr, pool);
		/* Follow CNAME chain */
		if (rr->type == KNOT_RRTYPE_CNAME) {
			cname = knot_cname_name(&rr->rrs);
		} else {
			cname = qry->sname;
		}
	}
	return kr_ok();
}

static int stash(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_request *req = ctx->data;
	struct kr_rplan *rplan = &req->rplan;
	struct kr_query *qry = kr_rplan_current(rplan);
	if (!qry || ctx->state & KNOT_STATE_FAIL) {
		return ctx->state;
	}

	/* Cache only positive answers. */
	if (qry->flags & QUERY_CACHED || knot_wire_get_rcode(pkt->wire) != KNOT_RCODE_NOERROR) {
		return ctx->state;
	}
	/* Stash in-bailiwick data from the AUTHORITY and ANSWER. */
	map_t stash = map_make();
	stash.malloc = (map_alloc_f) mm_alloc;
	stash.free = (map_free_f) mm_free;
	stash.baton = rplan->pool;
	int ret = 0;
	bool is_auth = knot_wire_get_aa(pkt->wire);
	if (is_auth) {
		ret = stash_answer(qry, pkt, &stash, rplan->pool);
	}
	/* Cache authority only if chasing referral/cname chain */
	if (!is_auth || qry != HEAD(rplan->pending)) {
		ret = stash_authority(qry, pkt, &stash, rplan->pool);
	}
	/* Cache DS records in referrals */
	if (!is_auth && knot_pkt_has_dnssec(pkt)) {
		stash_ds(qry, pkt, &stash, rplan->pool);
	}
	/* Cache stashed records */
	if (ret == 0) {
		/* Open write transaction */
		struct kr_cache *cache = &req->ctx->cache;
		struct kr_cache_txn txn;
		if (kr_cache_txn_begin(cache, &txn, 0) == 0) {
			ret = stash_commit(&stash, qry, &txn, req);
			if (ret == 0) {
				kr_cache_txn_commit(&txn);
			} else {
				kr_cache_txn_abort(&txn);
			}
		}
		/* Clear if full */
		if (ret == KNOT_ESPACE) {
			if (kr_cache_txn_begin(cache, &txn, 0) == 0) {
				ret = kr_cache_clear(&txn);
				if (ret == 0) {
					kr_cache_txn_commit(&txn);
				} else {
					kr_cache_txn_abort(&txn);
				}
			}
		}
	}
	
	return ctx->state;
}

/** Module implementation. */
const knot_layer_api_t *rrcache_layer(struct kr_module *module)
{
	static const knot_layer_api_t _layer = {
		.produce = &peek,
		.consume = &stash
	};

	return &_layer;
}

KR_MODULE_EXPORT(rrcache)
