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

#include <sys/time.h>
#include <assert.h>

#include <libknot/descriptor.h>
#include <libknot/rrtype/rdname.h>
#include <libknot/rrtype/rrsig.h>

#include "lib/layer/iterate.h"
#include "lib/resolve.h"
#include "lib/rplan.h"
#include "lib/defines.h"
#include "lib/nsrep.h"
#include "lib/module.h"
#include "lib/dnssec/ta.h"

#define DEBUG_MSG(fmt...) QRDEBUG(req->current_query, "iter", fmt)

/* Iterator often walks through packet section, this is an abstraction. */
typedef int (*rr_callback_t)(const knot_rrset_t *, unsigned, struct kr_request *);

/** Return minimized QNAME/QTYPE for current zone cut. */
static const knot_dname_t *minimized_qname(struct kr_query *query, uint16_t *qtype)
{
	/* Minimization disabled. */
	const knot_dname_t *qname = query->sname;
	if (qname[0] == '\0' || query->flags & (QUERY_NO_MINIMIZE|QUERY_STUB)) {
		return qname;
	}

	/* Minimize name to contain current zone cut + 1 label. */
	int cut_labels = knot_dname_labels(query->zone_cut.name, NULL);
	int qname_labels = knot_dname_labels(qname, NULL);
	while(qname[0] && qname_labels > cut_labels + 1) {
		qname = knot_wire_next_label(qname, NULL);
		qname_labels -= 1;
	}

	/* Hide QTYPE if minimized. */
	if (qname != query->sname) {
		*qtype = KNOT_RRTYPE_NS;
	}

	return qname;
}

/** Answer is paired to query. */
static bool is_paired_to_query(const knot_pkt_t *answer, struct kr_query *query)
{
	uint16_t qtype = query->stype;
	const knot_dname_t *qname = minimized_qname(query, &qtype);

	return query->id      == knot_wire_get_id(answer->wire) &&
	       knot_wire_get_qdcount(answer->wire) > 0 &&
	       (query->sclass == KNOT_CLASS_ANY || query->sclass  == knot_pkt_qclass(answer)) &&
	       qtype          == knot_pkt_qtype(answer) &&
	       knot_dname_is_equal(qname, knot_pkt_qname(answer));
}

/** Relaxed rule for AA, either AA=1 or SOA matching zone cut is required. */
static bool is_authoritative(const knot_pkt_t *answer, struct kr_query *query)
{
	if (knot_wire_get_aa(answer->wire)) {
		return true;
	}

	const knot_pktsection_t *ns = knot_pkt_section(answer, KNOT_AUTHORITY);
	for (unsigned i = 0; i < ns->count; ++i) {
		const knot_rrset_t *rr = knot_pkt_rr(ns, i);
		if (rr->type == KNOT_RRTYPE_SOA && knot_dname_in(query->zone_cut.name, rr->owner)) {
			return true;
		}
	}

#ifndef STRICT_MODE
	/* Last resort to work around broken auths, if the zone cut is at/parent of the QNAME. */
	if (knot_dname_is_equal(query->zone_cut.name, knot_pkt_qname(answer))) {
		return true;
	}
#endif
	return false;
}

int kr_response_classify(knot_pkt_t *pkt)
{
	const knot_pktsection_t *an = knot_pkt_section(pkt, KNOT_ANSWER);
	switch (knot_wire_get_rcode(pkt->wire)) {
	case KNOT_RCODE_NOERROR:
		return (an->count == 0) ? PKT_NODATA : PKT_NOERROR;
	case KNOT_RCODE_NXDOMAIN:
		return PKT_NXDOMAIN;
	case KNOT_RCODE_REFUSED:
		return PKT_REFUSED;
	default:
		return PKT_ERROR;
	}
}

/** @internal Filter ANY or loopback addresses. */
static bool is_valid_addr(const uint8_t *addr, size_t len)
{
	if (len == sizeof(struct in_addr)) {
		/* Filter ANY and 127.0.0.0/8 */
		uint32_t ip_host = ntohl(*(const uint32_t *)(addr));
		if (ip_host == 0 || (ip_host & 0xff000000) == 0x7f000000) {
			return false;
		}
	} else if (len == sizeof(struct in6_addr)) {
		struct in6_addr ip6_mask;
		memset(&ip6_mask, 0, sizeof(ip6_mask));
		/* All except last byte are zeroed, last byte defines ANY/::1 */
		if (memcmp(addr, ip6_mask.s6_addr, sizeof(ip6_mask.s6_addr) - 1) == 0) {
			return (addr[len - 1] > 1);
		}
	}
	return true;
}

static int update_nsaddr(const knot_rrset_t *rr, struct kr_query *query)
{
	if (rr->type == KNOT_RRTYPE_A || rr->type == KNOT_RRTYPE_AAAA) {
		const knot_rdata_t *rdata = rr->rrs.data;
		if (!(query->flags & QUERY_ALLOW_LOCAL) &&
			!is_valid_addr(knot_rdata_data(rdata), knot_rdata_rdlen(rdata))) {
			return KNOT_STATE_CONSUME; /* Ignore invalid addresses */
		}
		int ret = kr_zonecut_add(&query->zone_cut, rr->owner, rdata);
		if (ret != 0) {
			return KNOT_STATE_FAIL;
		}
	}

	return KNOT_STATE_CONSUME;
}

static int update_parent(const knot_rrset_t *rr, struct kr_query *qry)
{
	return update_nsaddr(rr, qry->parent);
}

static int update_answer(const knot_rrset_t *rr, unsigned hint, knot_pkt_t *answer)
{
	/* Scrub DNSSEC records when not requested. */
	if (!knot_pkt_has_dnssec(answer)) {
		if (rr->type != knot_pkt_qtype(answer) && knot_rrtype_is_dnssec(rr->type)) {
			return KNOT_STATE_DONE; /* Scrub */
		}
	}
	/* Copy record, as it may be accessed after packet processing. */
	knot_rrset_t *copy = knot_rrset_copy(rr, &answer->mm);
	/* Write to final answer. */
	int ret = knot_pkt_put(answer, hint, copy, KNOT_PF_FREE);
	if (ret != KNOT_EOK) {
		knot_wire_set_tc(answer->wire);
		return KNOT_STATE_DONE;
	}

	return KNOT_STATE_DONE;
}

static void fetch_glue(knot_pkt_t *pkt, const knot_dname_t *ns, struct kr_request *req)
{
	bool used_glue = false;
	for (knot_section_t i = KNOT_ANSWER; i <= KNOT_ADDITIONAL; ++i) {
		const knot_pktsection_t *sec = knot_pkt_section(pkt, i);
		for (unsigned k = 0; k < sec->count; ++k) {
			const knot_rrset_t *rr = knot_pkt_rr(sec, k);
			if (knot_dname_is_equal(ns, rr->owner)) {
				(void) update_nsaddr(rr, req->current_query);
				used_glue = true;
			}
		}
	}
	WITH_DEBUG {
		char name_str[KNOT_DNAME_MAXLEN];
		knot_dname_to_str(name_str, ns, sizeof(name_str));
		if (used_glue) {
			DEBUG_MSG("<= using glue for '%s'\n", name_str);
		}
	}
}

/** Attempt to find glue for given nameserver name (best effort). */
static int has_glue(knot_pkt_t *pkt, const knot_dname_t *ns)
{
	for (knot_section_t i = KNOT_ANSWER; i <= KNOT_ADDITIONAL; ++i) {
		const knot_pktsection_t *sec = knot_pkt_section(pkt, i);
		for (unsigned k = 0; k < sec->count; ++k) {
			const knot_rrset_t *rr = knot_pkt_rr(sec, k);
			if (knot_dname_is_equal(ns, rr->owner) &&
			    (rr->type == KNOT_RRTYPE_A || rr->type == KNOT_RRTYPE_AAAA)) {
				return 1;
			}
		}
	}
	return 0;
}

static int update_cut(knot_pkt_t *pkt, const knot_rrset_t *rr, struct kr_request *req)
{
	struct kr_query *qry = req->current_query;
	struct kr_zonecut *cut = &qry->zone_cut;
	int state = KNOT_STATE_CONSUME;

	/* Authority MUST be at/below the authority of the nameserver, otherwise
	 * possible cache injection attempt. */
	if (!knot_dname_in(cut->name, rr->owner)) {
		DEBUG_MSG("<= authority: ns outside bailiwick\n");
#ifdef STRICT_MODE
		return KNOT_STATE_FAIL;
#else
		/* Workaround: ignore out-of-bailiwick NSs for authoritative answers,
		 * but fail for referrals. This is important to detect lame answers. */
		if (knot_pkt_section(pkt, KNOT_ANSWER)->count == 0) {
			state = KNOT_STATE_FAIL;
		}
		return state;
#endif
	}

	/* Remember current bailiwick for NS processing. */
	const knot_dname_t *current_cut = cut->name;
	/* Update zone cut name */
	if (!knot_dname_is_equal(rr->owner, cut->name)) {
		/* Remember parent cut and descend to new (keep keys and TA). */
		struct kr_zonecut *parent = mm_alloc(&req->pool, sizeof(*parent));
		if (parent) {
			memcpy(parent, cut, sizeof(*parent));
			kr_zonecut_init(cut, rr->owner, &req->pool);
			cut->key = parent->key;
			cut->trust_anchor = parent->trust_anchor;
			cut->parent = parent;
		} else {
			kr_zonecut_set(cut, rr->owner);
		}
		state = KNOT_STATE_DONE;
	}

	/* Fetch glue for each NS */
	for (unsigned i = 0; i < rr->rrs.rr_count; ++i) {
		const knot_dname_t *ns_name = knot_ns_name(&rr->rrs, i);
		int glue_records = has_glue(pkt, ns_name);
		/* Glue is mandatory for NS below zone */
		if (!glue_records && knot_dname_in(rr->owner, ns_name)) {
			DEBUG_MSG("<= authority: missing mandatory glue, rejecting\n");
			continue;
		}
		kr_zonecut_add(cut, ns_name, NULL);
		/* Choose when to use glue records. */
		if (qry->flags & QUERY_PERMISSIVE) {
			fetch_glue(pkt, ns_name, req);
		} else if (qry->flags & QUERY_STRICT) {
			/* Strict mode uses only mandatory glue. */
			if (knot_dname_in(cut->name, ns_name))
				fetch_glue(pkt, ns_name, req);
		} else {
			/* Normal mode uses in-bailiwick glue. */
			if (knot_dname_in(current_cut, ns_name))
				fetch_glue(pkt, ns_name, req);
		}
	}

	return state;
}

static int process_authority(knot_pkt_t *pkt, struct kr_request *req)
{
	int result = KNOT_STATE_CONSUME;
	struct kr_query *qry = req->current_query;
	const knot_pktsection_t *ns = knot_pkt_section(pkt, KNOT_AUTHORITY);

	/* Stub resolution doesn't process authority */
	if (qry->flags & QUERY_STUB) {
		return KNOT_STATE_CONSUME;
	}

#ifdef STRICT_MODE
	/* AA, terminate resolution chain. */
	if (knot_wire_get_aa(pkt->wire)) {
		return KNOT_STATE_CONSUME;
	}
#else
	/* Work around servers sending back CNAME with different delegation and no AA. */
	const knot_pktsection_t *an = knot_pkt_section(pkt, KNOT_ANSWER);
	if (an->count > 0 && ns->count > 0) {
		const knot_rrset_t *rr = knot_pkt_rr(an, 0);
		if (rr->type == KNOT_RRTYPE_CNAME) {
			return KNOT_STATE_CONSUME;
		}
	}
#endif

	/* Update zone cut information. */
	for (unsigned i = 0; i < ns->count; ++i) {
		const knot_rrset_t *rr = knot_pkt_rr(ns, i);
		if (rr->type == KNOT_RRTYPE_NS) {
			int state = update_cut(pkt, rr, req);
			switch(state) {
			case KNOT_STATE_DONE: result = state; break;
			case KNOT_STATE_FAIL: return state; break;
			default:              /* continue */ break;
			}
		} else if (rr->type == KNOT_RRTYPE_SOA && knot_dname_is_sub(rr->owner, qry->zone_cut.name)) {
			/* SOA below cut in authority indicates different authority, but same NS set. */
			qry->zone_cut.name = knot_dname_copy(rr->owner, &req->pool);
		}
	}

	/* CONSUME => Unhelpful referral.
	 * DONE    => Zone cut updated.  */
	return result;
}

static void finalize_answer(knot_pkt_t *pkt, struct kr_query *qry, struct kr_request *req)
{
	/* Finalize header */
	knot_pkt_t *answer = req->answer;
	knot_wire_set_rcode(answer->wire, knot_wire_get_rcode(pkt->wire));

	/* Fill in bailiwick records in authority */
	const bool scrub_dnssec = !knot_pkt_has_dnssec(answer);
	const uint16_t qtype = knot_pkt_qtype(answer);
	struct kr_zonecut *cut = &qry->zone_cut;
	int pkt_class = kr_response_classify(pkt);
	if ((pkt_class & (PKT_NXDOMAIN|PKT_NODATA))) {
		const knot_pktsection_t *ns = knot_pkt_section(pkt, KNOT_AUTHORITY);
		for (unsigned i = 0; i < ns->count; ++i) {
			const knot_rrset_t *rr = knot_pkt_rr(ns, i);
			/* Scrub DNSSEC records when not requested. */
			if (scrub_dnssec && rr->type != qtype && knot_rrtype_is_dnssec(rr->type)) {
				continue;
			}
			/* Stash the authority records, they will be written to wire on answer finalization. */
			if (knot_dname_in(cut->name, rr->owner)) {
				kr_rrarray_add(&req->authority, rr, &answer->mm);
			}
		}
	}
}

static bool is_rrsig_type_covered(const knot_rrset_t *rr, uint16_t type)
{
	bool ret = false;
	for (unsigned i = 0; i < rr->rrs.rr_count; ++i) {
		if (knot_rrsig_type_covered(&rr->rrs, i) == type) {
			ret = true;
			break;
		}
	}
	return ret;
}

static int process_answer(knot_pkt_t *pkt, struct kr_request *req)
{
	struct kr_query *query = req->current_query;
	/* Response for minimized QNAME.
	 * NODATA   => may be empty non-terminal, retry (found zone cut)
	 * NOERROR  => found zone cut, retry
	 * NXDOMAIN => parent is zone cut, retry as a workaround for bad authoritatives
	 */
	bool is_final = (query->parent == NULL);
	int pkt_class = kr_response_classify(pkt);
	if (!knot_dname_is_equal(knot_pkt_qname(pkt), query->sname) &&
	    (pkt_class & (PKT_NOERROR|PKT_NXDOMAIN|PKT_REFUSED|PKT_NODATA))) {
		DEBUG_MSG("<= found cut, retrying with non-minimized name\n");
		query->flags |= QUERY_NO_MINIMIZE;
		return KNOT_STATE_CONSUME;
	}

	/* This answer didn't improve resolution chain, therefore must be authoritative (relaxed to negative). */
	if (!(query->flags & QUERY_STUB) && !is_authoritative(pkt, query)) {
		if (pkt_class & (PKT_NXDOMAIN|PKT_NODATA)) {
			DEBUG_MSG("<= lame response: non-auth sent negative response\n");
			return KNOT_STATE_FAIL;
		}
	}

	/* Process answer type */
	const knot_pktsection_t *an = knot_pkt_section(pkt, KNOT_ANSWER);
	const knot_dname_t *cname = NULL;
	const knot_dname_t *pending_cname = query->sname;
	unsigned cname_chain_len = 0;
	bool can_follow = false;
	bool strict_mode = (query->flags & QUERY_STRICT) && !(query->flags & QUERY_STUB);
	do {
		/* CNAME was found at previous iteration, but records may not follow the correct order.
		 * Try to find records for pending_cname owner from section start. */
		cname = pending_cname;
		pending_cname = NULL;
		/* If not secure, always follow cname chain. */
		can_follow = !(query->flags & QUERY_DNSSEC_WANT) || (query->flags & QUERY_STUB);
		for (unsigned i = 0; i < an->count; ++i) {
			const knot_rrset_t *rr = knot_pkt_rr(an, i);
			if (!knot_dname_is_equal(rr->owner, cname)) {
				continue;
			}
			/* Process records matching current SNAME */
			unsigned hint = 0;
			if(knot_dname_is_equal(cname, knot_pkt_qname(req->answer))) {
				hint = KNOT_COMPR_HINT_QNAME;
			}
			int state = is_final ? update_answer(rr, hint, req->answer) : update_parent(rr, query);
			if (state == KNOT_STATE_FAIL) {
				return state;
			}
			/* can_follow is false, therefore QUERY_DNSSEC_WANT flag is set.
			 * Follow cname chain only if rrsig exists. */
			if (!can_follow && rr->type == KNOT_RRTYPE_RRSIG &&
			    is_rrsig_type_covered(rr, KNOT_RRTYPE_CNAME)) {
				can_follow = true;
			}
			/* Jump to next CNAME target */
			if ((query->stype == KNOT_RRTYPE_CNAME) || (rr->type != KNOT_RRTYPE_CNAME)) {
				continue;
			}
			cname_chain_len += 1;
			pending_cname = knot_cname_name(&rr->rrs);
			if (!pending_cname || strict_mode) {
				break;
			}
			if (cname_chain_len > an->count || cname_chain_len > KR_CNAME_CHAIN_LIMIT) {
				DEBUG_MSG("<= too long cname chain\n");
				return KNOT_STATE_FAIL;
			}
			/* Don't use pending_cname immediately.
			 * There are can be records for "old" cname. */
		}
		/* In strict mode, explicitly fetch each CNAME target. */
		if (strict_mode && pending_cname) {
			cname = pending_cname;
			break;
		}
	} while (pending_cname && can_follow);

	/* Make sure that this is an authoritative answer (even with AA=0) for other layers */
	knot_wire_set_aa(pkt->wire);
	/* Either way it resolves current query. */
	query->flags |= QUERY_RESOLVED;
	/* Follow canonical name as next SNAME. */
	if (!knot_dname_is_equal(cname, query->sname)) {
		/* Check if target record has been already copied */
		query->flags |= QUERY_CNAME;
		if (is_final) {
			const knot_pktsection_t *an = knot_pkt_section(req->answer, KNOT_ANSWER);
			for (unsigned i = 0; i < an->count; ++i) {
				const knot_rrset_t *rr = knot_pkt_rr(an, i);
				if (!knot_dname_is_equal(rr->owner, cname)) {
					continue;
				}
				if ((rr->rclass != query->sclass) ||
				    (rr->type != query->stype)) {
					continue;
				}
				finalize_answer(pkt, query, req);
				return KNOT_STATE_DONE;
			}
		}
		DEBUG_MSG("<= cname chain, following\n");
		/* Check if the same query was already resolved */
		for (int i = 0; i < req->rplan.resolved.len; ++i) {
			struct kr_query * q = req->rplan.resolved.at[i];
			if (q->sclass == query->sclass &&
			    q->stype == query->stype   &&
			    knot_dname_is_equal(q->sname, cname)) {
				DEBUG_MSG("<= cname chain loop\n");
				return KNOT_STATE_FAIL;
			}
		}
		struct kr_query *next = kr_rplan_push(&req->rplan, query->parent, cname, query->sclass, query->stype);
		if (!next) {
			return KNOT_STATE_FAIL;
		}
		next->flags |= QUERY_AWAIT_CUT;
		/* Want DNSSEC if it's posible to secure this name (e.g. is covered by any TA) */
		if (kr_ta_covers(&req->ctx->trust_anchors, cname) &&
		    !kr_ta_covers(&req->ctx->negative_anchors, cname)) {
			next->flags |= QUERY_DNSSEC_WANT;
		}
	} else if (!query->parent) {
		finalize_answer(pkt, query, req);
	}
	return KNOT_STATE_DONE;
}

/** Error handling, RFC1034 5.3.3, 4d. */
static int resolve_error(knot_pkt_t *pkt, struct kr_request *req)
{
	return KNOT_STATE_FAIL;
}

/* State-less single resolution iteration step, not needed. */
static int reset(knot_layer_t *ctx)  { return KNOT_STATE_PRODUCE; }

/* Set resolution context and parameters. */
static int begin(knot_layer_t *ctx, void *module_param)
{
	if (ctx->state & (KNOT_STATE_DONE|KNOT_STATE_FAIL)) {
		return ctx->state;
	}
	/*
	 * RFC7873 5.4 extends the QUERY operation code behaviour in order to
	 * be able to generate requests for server cookies. Such requests have
	 * QDCOUNT equal to zero and must contain a cookie option.
	 * Server cookie queries must be handled by the cookie module/layer
	 * before this layer.
	 */
	const struct kr_request *req = ctx->data;
	const knot_pkt_t *pkt = req->qsource.packet;
	if (!pkt || knot_wire_get_qdcount(pkt->wire) == 0) {
		return KNOT_STATE_FAIL;
	}
	return reset(ctx);
}

int kr_make_query(struct kr_query *query, knot_pkt_t *pkt)
{
	/* Minimize QNAME (if possible). */
	uint16_t qtype = query->stype;
	const knot_dname_t *qname = minimized_qname(query, &qtype);

	/* Form a query for the authoritative. */
	knot_pkt_clear(pkt);
	int ret = knot_pkt_put_question(pkt, qname, query->sclass, qtype);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Query built, expect answer. */
	query->id = kr_rand_uint(UINT16_MAX);
	knot_wire_set_id(pkt->wire, query->id);
	pkt->parsed = pkt->size;
	return kr_ok();
}

static int prepare_query(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	assert(pkt && ctx);
	struct kr_request *req = ctx->data;
	struct kr_query *query = req->current_query;
	if (!query || ctx->state & (KNOT_STATE_DONE|KNOT_STATE_FAIL)) {
		return ctx->state;
	}

	/* Make query */
	int ret = kr_make_query(query, pkt);
	if (ret != 0) {
		return KNOT_STATE_FAIL;
	}

	return KNOT_STATE_CONSUME;
}

static int resolve_badmsg(knot_pkt_t *pkt, struct kr_request *req, struct kr_query *query)
{
#ifndef STRICT_MODE
	/* Work around broken auths/load balancers */
	if (query->flags & QUERY_SAFEMODE) {
		return resolve_error(pkt, req);
	} else {
		query->flags |= QUERY_SAFEMODE;
		return KNOT_STATE_DONE;
	}
#else
		return resolve_error(pkt, req);
#endif
}

/** Resolve input query or continue resolution with followups.
 *
 *  This roughly corresponds to RFC1034, 5.3.3 4a-d.
 */
static int resolve(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	assert(pkt && ctx);
	struct kr_request *req = ctx->data;
	struct kr_query *query = req->current_query;
	if (!query || (query->flags & (QUERY_RESOLVED|QUERY_BADCOOKIE_AGAIN))) {
		return ctx->state;
	}

	/* Check for packet processing errors first.
	 * Note - we *MUST* check if it has at least a QUESTION,
	 * otherwise it would crash on accessing QNAME. */
	if (pkt->parsed < pkt->size || pkt->parsed <= KNOT_WIRE_HEADER_SIZE) {
		DEBUG_MSG("<= malformed response\n");
		return resolve_badmsg(pkt, req, query);
	} else if (!is_paired_to_query(pkt, query)) {
		DEBUG_MSG("<= ignoring mismatching response\n");
		/* Force TCP, to work around authoritatives messing up question
		 * without yielding to spoofed responses. */
		query->flags |= QUERY_TCP;
		return resolve_badmsg(pkt, req, query);
	} else if (knot_wire_get_tc(pkt->wire)) {
		DEBUG_MSG("<= truncated response, failover to TCP\n");
		if (query) {
			/* Fail if already on TCP. */
			if (query->flags & QUERY_TCP) {
				DEBUG_MSG("<= TC=1 with TCP, bailing out\n");
				return resolve_error(pkt, req);
			}
			query->flags |= QUERY_TCP;
		}
		return KNOT_STATE_CONSUME;
	}

#ifndef NDEBUG
	const knot_lookup_t *rcode = knot_lookup_by_id(knot_rcode_names, knot_wire_get_rcode(pkt->wire));
#endif

	/* Check response code. */
	switch(knot_wire_get_rcode(pkt->wire)) {
	case KNOT_RCODE_NOERROR:
	case KNOT_RCODE_NXDOMAIN:
		break; /* OK */
	case KNOT_RCODE_REFUSED:
	case KNOT_RCODE_SERVFAIL: {
		if (query->flags & QUERY_STUB) { break; } /* Pass through in stub mode */
		DEBUG_MSG("<= rcode: %s\n", rcode ? rcode->name : "??");
		query->fails += 1;
		if (query->fails >= KR_QUERY_NSRETRY_LIMIT) {
			query->fails = 0; /* Reset per-query counter. */
			return resolve_error(pkt, req);
		} else {
			query->flags |= QUERY_NO_MINIMIZE; /* Drop minimisation as a safe-guard. */
			return KNOT_STATE_CONSUME;
		}
	}
	case KNOT_RCODE_FORMERR:
	case KNOT_RCODE_NOTIMPL:
		DEBUG_MSG("<= rcode: %s\n", rcode ? rcode->name : "??");
		return resolve_badmsg(pkt, req, query);
	default:
		DEBUG_MSG("<= rcode: %s\n", rcode ? rcode->name : "??");
		return resolve_error(pkt, req);
	}

	/* Resolve authority to see if it's referral or authoritative. */
	int state = process_authority(pkt, req);
	switch(state) {
	case KNOT_STATE_CONSUME: /* Not referral, process answer. */
		DEBUG_MSG("<= rcode: %s\n", rcode ? rcode->name : "??");
		state = process_answer(pkt, req);
		break;
	case KNOT_STATE_DONE: /* Referral */
		DEBUG_MSG("<= referral response, follow\n");
		break;
	default:
		break;
	}

	return state;
}

/** Module implementation. */
const knot_layer_api_t *iterate_layer(struct kr_module *module)
{
	static const knot_layer_api_t _layer = {
		.begin = &begin,
		.reset = &reset,
		.consume = &resolve,
		.produce = &prepare_query
	};
	return &_layer;
}

KR_MODULE_EXPORT(iterate)

#undef DEBUG_MSG
