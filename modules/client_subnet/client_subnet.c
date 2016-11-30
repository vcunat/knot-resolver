
#include <arpa/inet.h>

#include <maxminddb.h>
#include <libknot/descriptor.h>

#include "lib/client_subnet.h"
#include "lib/module.h"
#include "lib/layer.h"
#include "lib/layer/iterate.h"
#include "lib/resolve.h"
#include "lib/rplan.h"
#include "lib/utils.h"

#define MSG(type, fmt...) kr_log_##type ("[mecs] " fmt)
#define MSG_QRDEBUG(qry, fmt...) QRDEBUG(qry, "mecs", fmt)

static const kr_ecs_t ecs_loc_scope0 = {
	.loc = "0",
	.loc_len = 1,
};

typedef struct kr_ecs_ctx {
	/*! ECS data; for request, ANS query (except scope_len), and answer. */
	knot_edns_client_subnet_t query_ecs;
	kr_ecs_t loc; /*!< Note: loc_len == 0 means to use qry->ecs = NULL */
	//bool is_explicit;
} data_t;

/** Add ECS section into a packet. */
static int add_ecs_opt(const knot_edns_client_subnet_t *ecs, knot_pkt_t *pkt) {
	if (!ecs || !pkt) {
		assert(false);
		return kr_error(EINVAL);
	}

	size_t wire_size_orig = 0;
	if (pkt->opt_rr) {
		wire_size_orig = knot_edns_wire_size(pkt->opt_rr);
	} else {
		pkt->opt_rr = mm_alloc(&pkt->mm, sizeof(*pkt->opt_rr));
		if (!pkt->opt_rr)
			return kr_error(ENOMEM);
		knot_edns_init(pkt->opt_rr, KR_EDNS_PAYLOAD, 0, KR_EDNS_VERSION, &pkt->mm);
	}

	uint8_t *option = NULL;
	uint16_t option_size = knot_edns_client_subnet_size(ecs);
	int ret = knot_edns_reserve_unique_option(pkt->opt_rr,
			KNOT_EDNS_OPTION_CLIENT_SUBNET,
			option_size, &option, &pkt->mm);
	if (ret != KNOT_EOK)
		return ret;
	if (!option) {
		assert(false);
		return KNOT_ERROR;
	}
	ret = knot_edns_client_subnet_write(option, option_size, ecs);
	if (!ret)
		ret = knot_pkt_reserve(pkt, knot_edns_wire_size(pkt->opt_rr) - wire_size_orig);
	return ret;
}

/** Try to find a corresponding DB entry; fill data->loc* and data->query_ecs.scope_len;
 * return error code. */
static int probe_geodb(kr_layer_t *ctx, const struct sockaddr *ecs_addr, data_t *data) {
	struct kr_module *module = ctx->api->data;
	MMDB_s *mmdb = module->data;
	if (!mmdb->filename)  /* DB not loaded successfully. */
		return kr_error(ENOENT);
	int err;
	MMDB_lookup_result_s lookup_result = MMDB_lookup_sockaddr(mmdb, ecs_addr, &err);
	if (err != MMDB_SUCCESS)
		goto err_db;
	if (!lookup_result.found_entry)
		goto err_not_found;
	MMDB_entry_data_s entry;
	err = MMDB_get_value(&lookup_result.entry, &entry, "country", "iso_code", NULL);
	if (err != MMDB_SUCCESS)
		goto err_db;
	/* The ISO code is supposed to be two characters. */
	if (!entry.has_data || entry.type != MMDB_DATA_TYPE_UTF8_STRING || entry.data_size != 2)
		goto err_not_found;
	data->loc.loc_len = entry.data_size;
	memcpy(data->loc.loc, entry.utf8_string, data->loc.loc_len);
	MSG(debug, "geo DB located query in: %c%c\n", data->loc.loc[0], data->loc.loc[1]);
	data->query_ecs.scope_len = lookup_result.netmask;
	return kr_ok();

err_db:
	MSG(error, "GEO DB failure: %s\n", MMDB_strerror(err));
	return kr_error(err);

err_not_found:;
	char addr_str[INET6_ADDRSTRLEN];
	if (NULL == inet_ntop(ecs_addr->sa_family, ecs_addr->sa_data,
				addr_str, sizeof(addr_str)))
	{
		addr_str[0] = '\0';
	}
	MSG(debug, "location of client's address not found: '%s'\n", addr_str);
	return kr_error(ENOENT);
}

/** Fill kr_request::ecs_ctx appropriately (a data_t instance). */
static int begin(kr_layer_t *ctx)
{
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;
	assert(!qry->parent && !req->ecs && !qry->ecs);

	if (qry->sclass != KNOT_CLASS_IN)
		return ctx->state;
		// TODO: it's unclear whether/how to react if is_explicit

	/* TODO: the RFC requires in 12.1 that we should avoid ECS on public suffixes
	 * https://publicsuffix.org but we only check very roughly (number of labels).
	 * Perhaps use some library, e.g. http://stricaud.github.io/faup/ */
	bool is_public = knot_dname_labels(qry->sname, NULL) <= 2;

       	uint8_t *ecs_wire = req->qsource.opt == NULL ? NULL :
		knot_edns_get_option(req->qsource.opt, KNOT_EDNS_OPTION_CLIENT_SUBNET);
	bool is_explicit = ecs_wire != NULL; /* explicit ECS request */

	data_t *data = (is_public && !is_explicit)
		? NULL : mm_alloc(&req->pool, sizeof(data_t));

	/* Determine ecs_addr: the address to look up in DB. */
	const struct sockaddr *ecs_addr = NULL;
	struct sockaddr_storage ecs_addr_storage;
	if (is_explicit) {
		uint8_t *ecs_data = knot_edns_opt_get_data(ecs_wire);
		uint16_t ecs_len = knot_edns_opt_get_length(ecs_wire);
		int err = knot_edns_client_subnet_parse(&data->query_ecs, ecs_data, ecs_len);
		if (err == KNOT_EOK)
			err = knot_edns_client_subnet_get_addr(&ecs_addr_storage, &data->query_ecs);
		if (err != KNOT_EOK || data->query_ecs.scope_len != 0) {
			MSG(debug, "request with malformed client subnet or family\n");
			knot_wire_set_rcode(req->answer->wire, KNOT_RCODE_FORMERR);
			ctx->state = KR_STATE_FAIL;
			goto go_without_ecs;
		}
		ecs_addr = (struct sockaddr *)&ecs_addr_storage;
		MSG(debug, "explicit ECS record is OK\n");
	} else {
		if (req->qsource.opt)
			MSG(debug, "no OPT records found\n");
		else
			MSG(debug, "OPT record(s) found but not ECS\n");

		/* We take the full client's address, but that shouldn't matter
		 * for privacy as we only use the location code inferred from it. */
		ecs_addr = req->qsource.addr;
	}

	/* Prepare data->query_ecs for answer and queries, as necessary. */
	if (is_public) {
		/* Answer with scope /0 if ECS was requested. */
		if (is_explicit)
			data->query_ecs.scope_len = 0;

	} else if (is_explicit && data->query_ecs.source_len == 0) {
		/* Explicit /0 special case. */
		data->loc.loc_len = 1;
		data->loc.loc[0] = '0';
		data->query_ecs.scope_len = 0;

	} else {
		/* Find location code */
		if (probe_geodb(ctx, ecs_addr, data) != kr_ok())
			goto go_without_ecs;
			// TODO: we SHOULD return REFUSED instead if data->is_explicit (and not /0)

		int max_prefix; // privacy https://tools.ietf.org/html/rfc7871#section-11.1
		switch (ecs_addr->sa_family) {
		case AF_INET:
			max_prefix = 24; break;
		case AF_INET6:
			max_prefix = 56; break;
		default:
			assert(false);
			max_prefix = 0;
		}
		data->query_ecs.scope_len = MIN(max_prefix, data->query_ecs.scope_len);
		if (is_explicit) {
			knot_edns_client_subnet_set_addr(&data->query_ecs,
							 (struct sockaddr_storage *)ecs_addr);
				/* ^ not very efficient way but should be OK */
			data->query_ecs.source_len = data->query_ecs.scope_len;
		}
	}
	
	// FIXME
	if (is_explicit) {
		/* Prepare the ECS section into the answer, as we know it already. */
		if (add_ecs_opt(&data->query_ecs, req->answer)) {
			MSG(error, "failed to prepare ECS into the answer\n");
			goto go_without_ecs;
		}
		MSG(debug, "prepared ECS into the answer\n");
	}

	if (!is_public) {
		/* All cases where we want to use ECS will get here. */
		data->query_ecs.scope_len = 0; /* Ready for out-going queries. */
		//data->is_explicit = is_explicit;
		req->ecs = data;
		qry->ecs = &data->loc; /* for initial cache search */
		return ctx->state;
	} /* else fall through */

go_without_ecs: /* no ECS to be used for cache or upstream queries */
	mm_free(&req->pool, data);
	return ctx->state;
}

/** Return whether ECS RR would be added to query packet, and adjust qry->ecs accordingly. */
static bool maybe_use_ecs(struct kr_request *req)
{
	struct kr_query *qry = req->current_query;
	/* First the ECS location for cache. FIXME */
	//qry->ecs = (qry->ecs && !qry->parent) ? &req->ecs->loc : NULL;
	//MSG_QRDEBUG(qry, "   ECS for cache: %d\n", (int)(qry->ecs != NULL));

	if (req->ecs && qry->ecs && !qry->parent && qry->cut_is_final && qry->ns.name) {
		if (qry->ns.reputation & KR_NS_NOECS) {
			qry->ecs = &ecs_loc_scope0; /* cache as if answered with /0 */
			MSG_QRDEBUG(qry, "   ECS for upstream - bad reputation\n");
		} else {
			if (qry->ecs && qry->ecs->loc_len) {
				MSG_QRDEBUG(qry, "   ECS for upstream - yes\n");
				return true;
			}
		}
	}
	return false;
}

static int produce(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_request *req = ctx->req;
	if (!ctx || !req || !req->current_query) {
		assert(false);
		return ctx ? ctx->state : KR_STATE_FAIL;
	}
	struct kr_query *qry = req->current_query;

	if (ctx->state & KR_STATE_DONE) {

	} else if (ctx->state & KR_STATE_FAIL) {
		/* TODO: verify in RFC what ECS should be in answer. */
	
	} else if (!(qry->flags & QUERY_CACHED)) {
		/* Prepare for sending query upstream. */
		bool add_ecs = maybe_use_ecs(req);
		if (add_ecs && pkt) {
			/* If query happens, do include ECS section. */
			add_ecs_opt(&req->ecs->query_ecs, pkt);
			MSG_QRDEBUG(qry, "   prepared ECS into query packet\n");
		}
	} else {
		MSG_QRDEBUG(qry, "   default branch\n");
	}
	return ctx->state;
}

static int consume(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_request *req = ctx->req;
	if (!ctx || !req || !req->current_query) {
		assert(false);
		return ctx->state;
	}
	struct kr_query *qry = req->current_query;
	//MSG(debug, "pending: %d\n", (int)req->rplan.pending.len);
	
	bool added_ecs = maybe_use_ecs(req);
	if (added_ecs && pkt) {
		MSG_QRDEBUG(qry, "   checking answer to an ECS-containing sub-query:\n");
		uint8_t *ecs_wire = pkt->opt_rr == NULL ? NULL :
			knot_edns_get_option(pkt->opt_rr, KNOT_EDNS_OPTION_CLIENT_SUBNET);

		if (!ecs_wire) {
			MSG_QRDEBUG(qry, "     no ECS returned\n");
		} else {
			/* Parse the ECS from packet. */
			knot_edns_client_subnet_t pkt_ecs;
			uint8_t *ecs_data = knot_edns_opt_get_data(ecs_wire);
			uint16_t ecs_len = knot_edns_opt_get_length(ecs_wire);
			int err = knot_edns_client_subnet_parse(&pkt_ecs, ecs_data, ecs_len);
			if (err) {
				ecs_wire = NULL;
			} else {
				//FIXME: check the address
			}
		}

		if (!ecs_wire)
			/* ECS not good, so flag the NS. */
			kr_nsrep_flags_set(qry, KR_NS_NOECS); /* ignore EINVAL */
		/*  */
	}
	

	if (!req->ecs || (ctx->state & (KR_STATE_DONE | KR_STATE_FAIL)))
		return ctx->state;



	return ctx->state;
	/*
	if (qry->parent || !pkt || qry->stype != knot_pkt_qtype(pkt)) {
		qry->ecs = NULL;
		return ctx->state;
	}
	*/
}


/* Only uninteresting stuff till the end of the file. */

static int load(struct kr_module *module, const char *db_path)
{
	MMDB_s *mmdb = module->data;
	assert(mmdb);
	int err = MMDB_open(db_path, 0/*defaults*/, mmdb);
	if (!err) {
		MSG(debug, "geo DB loaded succesfully\n");
		return kr_ok();
	}
	mmdb->filename = NULL;
	MSG(error, "failed to open the database\n");
	return kr_error(EIO);
}

static void unload(struct kr_module *module)
{
	MMDB_s *mmdb = module->data;
	if (!mmdb->filename)
		return;
	MMDB_close(mmdb);
	mmdb->filename = NULL;
}

/** Module implementation. */
KR_EXPORT
const kr_layer_api_t *client_subnet_layer(struct kr_module *module)
{
	static kr_layer_api_t _layer = {
		.begin = begin,
		.produce = produce,
		.consume = consume,
		.data = NULL,
		/* FIXME: add functions for produce and consume,
		 * and check whether the current sub-query is ECS-worthy
		 * and set qry->ecs either to NULL or req->ecs */
	};

	_layer.data = module;
	return &_layer;
}

KR_EXPORT
int client_subnet_init(struct kr_module *module)
{
	module->data = malloc(sizeof(struct MMDB_s));
	/* ->filename == NULL iff no DB is open */
	((MMDB_s *)module->data)->filename = NULL;
	return module->data != NULL ? kr_ok() : kr_error(ENOMEM);
}

KR_EXPORT
int client_subnet_deinit(struct kr_module *module)
{
	free(module->data);
       	module->data = NULL;
	return kr_ok();
}

KR_EXPORT
int client_subnet_config(struct kr_module *module, const char *db_path)
{
	unload(module);
	return load(module, db_path);
}

KR_MODULE_EXPORT(client_subnet)

