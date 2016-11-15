
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
	bool is_explicit; /*!< ECS was requested by client. */
	kr_ecs_t loc; /*!< Note: loc_len == 0 means to use qry->ecs = NULL */
} data_t;

/** Add ECS section into a packet. */
static int add_ecs_opt(const knot_edns_client_subnet_t *ecs, knot_pkt_t *pkt) {
	uint8_t *option = NULL;
	uint16_t option_size = knot_edns_client_subnet_size(ecs);
	int ret = knot_edns_reserve_option(pkt->opt_rr,
			KNOT_EDNS_OPTION_CLIENT_SUBNET,
			option_size, &option, &pkt->mm);
	if (ret != KNOT_EOK)
		return ret;
	if (!option) {
		assert(false);
		return KNOT_ERROR;
	}
	ret = knot_edns_client_subnet_write(option, option_size, ecs);
	return ret;
}

/** Fill kr_request::ecs_ctx appropriately (a data_t instance). */
static int begin(knot_layer_t *ctx, void *module_param)
{
	//FIXME: always check for the ECS option and force FORMERR if bogus
	(void)module_param;
	struct kr_request *req = ctx->data;
	struct kr_query *qry = req->current_query;
	assert(!qry->parent && !qry->ecs);

	if (qry->sclass != KNOT_CLASS_IN)
		return ctx->state;

	struct kr_module *module = ctx->api->data;
	MMDB_s *mmdb = module->data;
	if (!mmdb->filename) /* DB not loaded successfully; go without ECS. */
		return ctx->state;

	data_t *data = mm_alloc(&req->pool, sizeof(data_t));
	req->ecs = data;

	/* TODO: the RFC requires in 12.1 that we should avoid ECS on public suffixes
	 * https://publicsuffix.org but we only check very roughly (number of labels).
	 * Perhaps use some library, e.g. http://stricaud.github.io/faup/ */
	if (knot_dname_labels(qry->sname, NULL) <= 1) {
		data->loc.loc_len = 0;
		return ctx->state;
	}

	/* Determine ecs_addr: the address to look up in DB. */
	const struct sockaddr *ecs_addr = NULL;
	struct sockaddr_storage ecs_addr_storage;
       	uint8_t *ecs_wire = req->qsource.opt == NULL ? NULL :
		knot_edns_get_option(req->qsource.opt, KNOT_EDNS_OPTION_CLIENT_SUBNET);
	data->is_explicit = ecs_wire != NULL; /* explicit ECS request */
	if (data->is_explicit) {
		uint8_t *ecs_data = knot_edns_opt_get_data(ecs_wire);
		uint16_t ecs_len = knot_edns_opt_get_length(ecs_wire);
		int err = knot_edns_client_subnet_parse(&data->query_ecs, ecs_data, ecs_len);
		if (err == KNOT_EOK)
			err = knot_edns_client_subnet_get_addr(&ecs_addr_storage, &data->query_ecs);
		if (err != KNOT_EOK || data->query_ecs.scope_len != 0) {
			MSG(debug, "request with malformed client subnet or family\n");
			knot_wire_set_rcode(req->answer->wire, KNOT_RCODE_FORMERR);
			qry->ecs = NULL;
			mm_free(&req->pool, data);
			return KNOT_STATE_FAIL | KNOT_STATE_DONE;
		}
		ecs_addr = (struct sockaddr *)&ecs_addr_storage;
	} else {
		/* We take the full client's address, but that shouldn't matter
		 * for privacy as we only use the location code inferred from it. */
		ecs_addr = req->qsource.addr;
	}

	/* Explicit /0 special case. */
	if (data->is_explicit && data->query_ecs.source_len == 0) {
		data->loc.loc_len = 1;
		data->loc.loc[0] = '0';
		return ctx->state;
	}

	/* Now try to find a corresponding DB entry and fill data->loc*. */
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

	/* Esure data->query_ecs contains correct address, source_len, and also
	 * scope_len for answer. */
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
	if (!data->is_explicit) {
		knot_edns_client_subnet_set_addr(&data->query_ecs,
						 (struct sockaddr_storage *)ecs_addr);
			/* ^ not very efficient way but should be OK */
		data->query_ecs.source_len = MIN(max_prefix, lookup_result.netmask);
	}
	data->query_ecs.scope_len = MIN(max_prefix, lookup_result.netmask);

	if (data->is_explicit) {
		/* Prepare the ECS section into the answer, as we know it already. */
		if (add_ecs_opt(&data->query_ecs, req->answer))
			goto err_generic;
	}

	return ctx->state;

err_db:
	MSG(error, "GEO DB failure: %s\n", MMDB_strerror(err));
	goto err_generic;

err_not_found:;
	char addr_str[INET6_ADDRSTRLEN];
	if (NULL == inet_ntop(ecs_addr->sa_family, ecs_addr->sa_data,
				addr_str, sizeof(addr_str)))
	{
		addr_str[0] = '\0';
	}
	MSG(debug, "location of client's address not found: '%s'\n", addr_str);
	/* fall through */
err_generic:
	qry->ecs = NULL;
	mm_free(&req->pool, data);
	return ctx->state; /* Go without ECS. */

#if 0
	assert(!qry->ecs);
	/* Only consider ECS for original request, not sub-queries. */
	if (qry->parent)
		return ctx->state;


	if (ctx->state & (KNOT_STATE_FAIL|KNOT_STATE_DONE))
		return ctx->state; /* Already resolved/failed */
	if (qry->ns.addr[0].ip.sa_family != AF_UNSPEC)
		return ctx->state; /* Only lookup before asking a query */

	return ctx->state;
#endif
}

/** Returns whether ECS RR would be added to the packet. */
static bool maybe_use_ecs(struct kr_request *req)
{
	struct kr_query *qry = req->current_query;
	bool use_ecs = !qry->parent && qry->cut_is_final;
	MSG_QRDEBUG(qry, "use_ecs: %d\n", (int)use_ecs);
	qry->ecs = use_ecs ? &req->ecs->loc : NULL;

	if (qry->ns.name) {
		if (qry->ns.reputation & KR_NS_NOECS) {
			qry->ecs = &ecs_loc_scope0;
		} else {
			if (qry->ecs && qry->ecs->loc_len)
				return true;
		}
	}
	return false;
}

static int produce(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_request *req = ctx->data;
	if (!ctx || !req || !req->current_query) {
		assert(false);
		return ctx->state;
	}
	struct kr_query *qry = req->current_query;

	// At this point we can't know for sure if query or answer will get
	// produced in this round, as the caches (rr+pkt) may intervene.
	bool add_ecs = maybe_use_ecs(req);
	if (add_ecs && pkt) {
		/* If query happens, do include ECS section. */
		add_ecs_opt(&req->ecs->query_ecs, pkt);
		MSG_QRDEBUG(qry, "prepared ECS into packet\n");
	}

	return ctx->state;
}

static int consume(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_request *req = ctx->data;
	if (!ctx || !req || !req->current_query) {
		assert(false);
		return ctx->state;
	}
	struct kr_query *qry = req->current_query;
	//MSG(debug, "pending: %d\n", (int)req->rplan.pending.len);
	
	bool added_ecs = maybe_use_ecs(req);
	if (added_ecs && pkt) {
		MSG_QRDEBUG(qry, "checking answer to an ECS-containing sub-query\n");
		/*  */
	}
	

	if (!req->ecs || (ctx->state & (KNOT_STATE_DONE | KNOT_STATE_FAIL)))
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
const knot_layer_api_t *client_subnet_layer(struct kr_module *module)
{
	static knot_layer_api_t _layer = {
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

