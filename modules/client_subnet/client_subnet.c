
#include <maxminddb.h>
#include <libknot/rrtype/opt.h>

#include "lib/module.h"
#include "lib/layer/iterate.h"
#include "lib/resolve.h"
#include "lib/rplan.h"
#include "lib/utils.h"

#define DEBUG_MSG(qry, fmt...) QRDEBUG(qry, "client subnet",  fmt)

typedef struct kr_client_subnet {
	knot_edns_client_subnet_t query_ecs;
} data_t;

static int begin(knot_layer_t *ctx, void *module_param)
{
	struct kr_module *module = ctx->api->data;
	MMDB_s *mmdb = module->data;
	// FIXME: TMP DEBUG
	kr_log_info("[module client_subnet]: db %s\n", mmdb->filename);

	struct kr_request *req = ctx->data;
	//struct kr_query *qry = req->current_query;

#if 0
	assert(!qry->client_subnet);
	/* Only consider ECS for original request, not sub-queries. */
	if (qry->parent)
		return ctx->state;

	data_t *data = mm_alloc(&req->pool, sizeof(data_t));
	uint8_t *ecs_wire, *ecs_data;
	uint16_t ecs_size;
       	ecs_wire = req->qsource.opt == NULL ? NULL :
		knot_edns_get_option(req->qsource.opt, KNOT_EDNS_OPTION_CLIENT_SUBNET);
	if (ecs_wire) { /* explicit ECS request */
		ecs_data = knot_edns_opt_get_data(ecs_wire);
		ecs_size = knot_edns_opt_get_length(ecs_wire);
		int r = knot_edns_client_subnet_parse(&data->query_ecs, ecs_data, ecs_size);
		if (r != KNOT_EOK || data->query_ecs.scope_len != 0) {
			DEBUG_MSG(qry, "%s\n", "request with malformed client subnet");
			knot_wire_set_rcode(req->answer->wire, KNOT_RCODE_FORMERR);
			return KNOT_STATE_FAIL | KNOT_STATE_DONE;
		}
	} else {
	}

	qry->client_subnet = data;
#endif
#if 0

	if (r != KNOT_EOK) {
		return r;
	}

	r = knot_edns_client_subnet_get_addr(&src->addr, &src->ecs_data);
	assert(r == KNOT_EOK);

	return KNOT_EOK;

#endif

	/* Return if the query isn't eligible. */
	bool is_eligible = true
		&& true;

	return 0;
#if 0
	if (ctx->state & (KNOT_STATE_FAIL|KNOT_STATE_DONE))
		return ctx->state; /* Already resolved/failed */
	if (qry->ns.addr[0].ip.sa_family != AF_UNSPEC)
		return ctx->state; /* Only lookup before asking a query */

	return ctx->state;
#endif
}

/* Only uninteresting stuff till the end of the file. */

static int load(struct kr_module *module, const char *db_path)
{
	MMDB_s *mmdb = module->data;
	assert(mmdb);
	int err = MMDB_open(db_path, 0/*defaults*/, mmdb);
	if (!err) {
		kr_log_info("[module client_subnet]: geo DB loaded succesfully\n");
		return kr_ok();
	}
	mmdb->filename = NULL;
	kr_log_error("[module client_subnet]: failed to open the database\n");
	return kr_error(999/*TODO: no suitable code?*/);
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
		.data = NULL,
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

