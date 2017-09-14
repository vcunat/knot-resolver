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

#include <uv.h>
#include <lua.h>
#include <libknot/packet/pkt.h>
#include <libknot/descriptor.h>
#include <contrib/ucw/lib.h>
#include <contrib/ucw/mempool.h>
#include <contrib/wire.h>
#if defined(__GLIBC__) && defined(_GNU_SOURCE)
#include <malloc.h>
#endif
#include <assert.h>
#include <sys/types.h>
#include <unistd.h>
#include "lib/utils.h"
#include "lib/layer.h"
#include "daemon/worker.h"
#include "daemon/bindings.h"
#include "daemon/engine.h"
#include "daemon/io.h"
#include "daemon/tls.h"

#define VERBOSE_MSG(qry, fmt...) QRVERBOSE(qry, "wrkr", fmt)

/* @internal Union of various libuv objects for freelist. */
struct req
{
	union {
		/* Socket handles, these have session as their `handle->data` and own it. */
		uv_udp_t      udp;
		uv_tcp_t      tcp;
		/* I/O events, these have only a reference to the task they're operating on. */
		uv_udp_send_t send;
		uv_write_t    write;
		uv_connect_t  connect;
		/* Timer events */
		uv_timer_t    timer;
	} as;
};

/* Convenience macros */
#define qr_task_ref(task) \
	do { ++(task)->refs; } while(0)
#define qr_task_unref(task) \
	do { if (--(task)->refs == 0) { qr_task_free(task); } } while (0)
#define qr_valid_handle(task, checked) \
	(!uv_is_closing((checked)) || (task)->ctx->source.session->handle == (checked))

/* Forward decls */
static void qr_task_free(struct qr_task *task);
static int qr_task_step(struct qr_task *task,
			const struct sockaddr *packet_source,
			knot_pkt_t *packet);
static int qr_task_send(struct qr_task *task, uv_handle_t *handle,
			struct sockaddr *addr, knot_pkt_t *pkt);
static int worker_add_tcp_connected(struct worker_ctx *worker,
				    const struct sockaddr *addr,
				    struct session *session);
static int worker_del_tcp_connected(struct worker_ctx *worker,
				    const struct sockaddr *addr);
static struct session* worker_find_tcp_connected(struct worker_ctx *worker,
						 const struct sockaddr *srv);
static int worker_add_tcp_waiting(struct worker_ctx *worker,
				  const struct sockaddr *addr,
				  struct session *session);
static int worker_del_tcp_waiting(struct worker_ctx *worker,
				  const struct sockaddr *addr);
static struct session* worker_find_tcp_waiting(struct worker_ctx *worker,
					       const struct sockaddr *srv);
static int session_add_waiting(struct session *session,
				   struct qr_task *task);
static int session_add_tasks(struct session *session,
				 struct qr_task *task);

static void on_session_tcp_timeout(uv_timer_t *timer);
static void session_close(struct session *session);

/** @internal Get singleton worker. */
static inline struct worker_ctx *get_worker(void)
{
	return uv_default_loop()->data;
}

/** @internal get key for tcp session
 *  @note return pointer to static string
 */
static const char *tcpsess_key(const struct sockaddr *addr)
{
	/* We are sinle-threaded application */
	static char key[INET6_ADDRSTRLEN + 6];
	size_t len = sizeof(key);
	int ret = kr_inaddr_str(addr, key, &len);
	return ret != kr_ok() || len == 0 ? NULL : key;
}


static inline struct req *req_borrow(struct worker_ctx *worker)
{
	struct req *req = NULL;
	if (worker->pool_ioreq.len > 0) {
		req = array_tail(worker->pool_ioreq);
		array_pop(worker->pool_ioreq);
		kr_asan_unpoison(req, sizeof(*req));
	} else {
		req = malloc(sizeof(*req));
	}
	return req;
}

static inline void req_release(struct worker_ctx *worker, struct req *req)
{
	if (!req || worker->pool_ioreq.len < 4 * MP_FREELIST_SIZE) {
		array_push(worker->pool_ioreq, req);
		kr_asan_poison(req, sizeof(*req));
	} else {
		free(req);
	}
}

/*! @internal Create a UDP/TCP handle for an outgoing AF_INET* connection.
 *  socktype is SOCK_* */
static uv_handle_t *ioreq_spawn(struct qr_task *task, int socktype, sa_family_t family)
{
	bool precond = (socktype == SOCK_DGRAM || socktype == SOCK_STREAM)
			&& (family == AF_INET  || family == AF_INET6);
	if (!precond) {
		/* assert(false); see #245 */
		kr_log_verbose("[work] ioreq_spawn: pre-condition failed\n");
		return NULL;
	}

	if (task->pending_count >= MAX_PENDING) {
		return NULL;
	}
	/* Create connection for iterative query */
	struct worker_ctx *worker = task->ctx->worker;
	uv_handle_t *handle = (uv_handle_t *)req_borrow(worker);
	if (!handle) {
		return NULL;
	}
	io_create(worker->loop, handle, socktype);

	/* Bind to outgoing address, according to IP v4/v6. */
	union inaddr *addr;
	if (family == AF_INET) {
		addr = (union inaddr *)&worker->out_addr4;
	} else {
		addr = (union inaddr *)&worker->out_addr6;
	}
	int ret = 0;
	if (addr->ip.sa_family != AF_UNSPEC) {
		assert(addr->ip.sa_family == family);
		if (socktype == SOCK_DGRAM) {
			ret = uv_udp_bind((uv_udp_t *)handle, &addr->ip, 0);
		} else {
			ret = uv_tcp_bind((uv_tcp_t *)handle, &addr->ip, 0);
		}
	}

	/* Set current handle as a subrequest type. */
	struct session *session = handle->data;
	if (ret == 0) {
		session->outgoing = true;
		ret = array_push(session->tasks, task);
	}
	if (ret < 0) {
		io_deinit(handle);
		req_release(worker, (struct req *)handle);
		return NULL;
	}
	task->current_session = session;
	qr_task_ref(task);
	/* Connect or issue query datagram */
	task->pending[task->pending_count] = handle;
	task->pending_count += 1;
	return handle;
}

static void on_session_close(uv_handle_t *handle)
{
	struct worker_ctx *worker = get_worker();
	io_deinit(handle);
	req_release(worker, (struct req *)handle);
}

static void ioreq_kill_udp(uv_handle_t *req, struct qr_task *task)
{
	assert(req);
	struct session *session = req->data;

	for (size_t i = 0; i < session->tasks.len; ++i) {
		if (session->tasks.at[i] == task) {
			array_del(session->tasks, i);
			qr_task_unref(task);
			break;
		}
	}

	assert(session->outgoing && session->tasks.len == 0);

	session_close(session);
}

static void ioreq_kill_tcp(uv_handle_t *req, struct qr_task *task)
{
	assert(req);
	struct session *session = req->data;

	for (size_t i = 0; i < session->waiting.len; ++i) {
		if (session->waiting.at[i] == task) {
			array_del(session->waiting, i);
			qr_task_unref(task);
			break;
		}
	}

	for (size_t i = 0; i < session->tasks.len; ++i) {
		if (session->tasks.at[i] == task) {
			array_del(session->tasks, i);
			qr_task_unref(task);
			break;
		}
	}

	int res = 0;

	if (session->outgoing && session->peer.ip.sa_family != AF_UNSPEC &&
	    session->tasks.len == 0 && session->waiting.len == 0 &&
	    session->connected ) {
		/* This is outbound TCP connection which can be reused.
		 * Close it after timeout */
		uv_timer_t *timer = &session->timeout;
		timer->data = session;
		res = uv_timer_start(timer, on_session_tcp_timeout,
				     KR_CONN_RTT_MAX, 0);
	}

	if (res != 0) {
		/* if any errors, close the session immediately */
		session_close(session);
	}
}

static void ioreq_kill_pending(struct qr_task *task)
{
	for (uint16_t i = 0; i < task->pending_count; ++i) {
		if (task->pending[i]->type != UV_TCP) {
			ioreq_kill_udp(task->pending[i], task);
		} else {
			ioreq_kill_tcp(task->pending[i], task);
		}
	}
	struct session *session = task->current_session;
	if (session &&
	    session->outgoing &&
	    session->peer.ip.sa_family != AF_UNSPEC) {
		/* Remove itself from the session task list. */
		for (size_t i = 0; i < session->tasks.len; ++i) {
			if (session->tasks.at[i] == task) {
				array_del(session->tasks, i);
				break;
			}
		}
	}
	task->current_session = NULL;
	task->pending_count = 0;
}

static void session_close(struct session *session)
{
	if (!uv_is_closing(session->handle)) {
		uv_close(session->handle, on_session_close);
		session->connected = false;
	}

	if (session->outgoing &&
	    session->peer.ip.sa_family != AF_UNSPEC) {
		char key[INET6_ADDRSTRLEN + 6];
		size_t len = sizeof(key);
		int ret = kr_inaddr_str(&session->peer.ip, key, &len);

		struct worker_ctx *worker = get_worker();
		struct sockaddr *peer = &session->peer.ip;
		worker_del_tcp_connected(worker, peer);
	}

	assert(session->tasks.len == 0 && session->waiting.len == 0);
}

static int session_add_waiting(struct session *session,
				struct qr_task *task)
{
	for (int i = 0; i < session->waiting.len; ++i) {
		if (session->waiting.at[i] == task) {
			return i;
		}
	}
	return array_push(session->waiting, task);
}

static int session_add_tasks(struct session *session,
			      struct qr_task *task)
{
	for (int i = 0; i < session->tasks.len; ++i) {
		if (session->tasks.at[i] == task) {
			return i;
		}
	}
	return array_push(session->tasks, task);
}


/** @cond This memory layout is internal to mempool.c, use only for debugging. */
#if defined(__SANITIZE_ADDRESS__)
struct mempool_chunk {
  struct mempool_chunk *next;
  size_t size;
};
static void mp_poison(struct mempool *mp, bool poison)
{
	if (!poison) { /* @note mempool is part of the first chunk, unpoison it first */
		kr_asan_unpoison(mp, sizeof(*mp));
	}
	struct mempool_chunk *chunk = mp->state.last[0];
	void *chunk_off = (void *)chunk - chunk->size;
	if (poison) {
		kr_asan_poison(chunk_off, chunk->size);
	} else {
		kr_asan_unpoison(chunk_off, chunk->size);
	}
}
#else
#define mp_poison(mp, enable)
#endif
/** @endcond */

static inline struct mempool *pool_borrow(struct worker_ctx *worker)
{
	/* Recycle available mempool if possible */
	struct mempool *mp = NULL;
	if (worker->pool_mp.len > 0) {
		mp = array_tail(worker->pool_mp);
		array_pop(worker->pool_mp);
		mp_poison(mp, 0);
	} else { /* No mempool on the freelist, create new one */
		mp = mp_new (4 * CPU_PAGE_SIZE);
	}
	return mp;
}

static inline void pool_release(struct worker_ctx *worker, struct mempool *mp)
{
	/* Return mempool to ring or free it if it's full */
	if (worker->pool_mp.len < MP_FREELIST_SIZE) {
		mp_flush(mp);
		array_push(worker->pool_mp, mp);
		mp_poison(mp, 1);
	} else {
		mp_delete(mp);
	}
}

/** @internal Get key from current outgoing subrequest. */
static int subreq_key(char *dst, knot_pkt_t *pkt)
{
	assert(pkt);
	return kr_rrkey(dst, knot_pkt_qname(pkt), knot_pkt_qtype(pkt), knot_pkt_qclass(pkt));
}

static struct request_ctx *request_create(struct worker_ctx *worker,
					  uv_handle_t *handle,
					  const struct sockaddr *addr)
{
	/* Recycle available mempool if possible */
	knot_mm_t pool = {
		.ctx = pool_borrow(worker),
		.alloc = (knot_mm_alloc_t) mp_alloc
	};

	/* Create request context */
	struct request_ctx *ctx = mm_alloc(&pool, sizeof(*ctx));
	if (!ctx) {
		mp_delete(pool.ctx);
		return NULL;
	}

	/* TODO Relocate pool to struct request */
	ctx->worker = worker;
	array_init(ctx->tasks);
	ctx->source.session = handle ? handle->data : NULL;

	struct kr_request *req = &ctx->req;

	req->pool = pool;
	req->answer = NULL;
	req->qsource.key = NULL;
	req->qsource.addr = NULL;
	req->qsource.dst_addr = NULL;
	req->qsource.packet = NULL;
	req->qsource.opt = NULL;

	/* TODO add counter for concurrent queries */
	worker->stats.concurrent += 1;

	/* Remember query source addr */
	if (!addr) {
		ctx->source.addr.ip4.sin_family = AF_UNSPEC;
	} else {
		size_t addr_len = sizeof(struct sockaddr_in);
		if (addr->sa_family == AF_INET6)
			addr_len = sizeof(struct sockaddr_in6);
		memcpy(&ctx->source.addr, addr, addr_len);
		ctx->req.qsource.addr = (const struct sockaddr *)&ctx->source.addr;
	}

	if (!handle) {
		return ctx;
	}

	/* Remember the destination address. */
	int addr_len = sizeof(ctx->source.dst_addr);
	struct sockaddr *dst_addr = (struct sockaddr *)&ctx->source.dst_addr;
	ctx->source.dst_addr.ip4.sin_family = AF_UNSPEC;
	if (handle->type == UV_UDP) {
		if (uv_udp_getsockname((uv_udp_t *)handle, dst_addr, &addr_len) == 0) {
			req->qsource.dst_addr = dst_addr;
		}
		req->qsource.tcp = false;
	} else if (handle->type == UV_TCP) {
		if (uv_tcp_getsockname((uv_tcp_t *)handle, dst_addr, &addr_len) == 0) {
			req->qsource.dst_addr = dst_addr;
		}
		req->qsource.tcp = true;
	}

	return ctx;
}

static int request_start(struct request_ctx *ctx, knot_pkt_t *query)
{
	assert(query && ctx);
	size_t answer_max = KNOT_WIRE_MIN_PKTSIZE;
	struct kr_request *req = &ctx->req;

	/* source.session can be empty if request was generated by kresd itself */
	if (!ctx->source.session ||
	     ctx->source.session->handle->type == UV_TCP) {
		answer_max = KNOT_WIRE_MAX_PKTSIZE;
	} else if (knot_pkt_has_edns(query)) { /* EDNS */
		answer_max = MAX(knot_edns_get_payload(query->opt_rr),
				 KNOT_WIRE_MIN_PKTSIZE);
	}

	knot_pkt_t *answer = knot_pkt_new(NULL, answer_max, &req->pool);
	if (!answer) {
		return kr_error(ENOMEM);
	}
	req->answer = answer;

	/* Remember query source TSIG key */
	if (query->tsig_rr) {
		req->qsource.key = knot_rrset_copy(query->tsig_rr, &req->pool);
	}

	/* Remember query source EDNS data */
	if (query->opt_rr) {
		req->qsource.opt = knot_rrset_copy(query->opt_rr, &req->pool);
	}
	/* Start resolution */
	struct worker_ctx *worker = ctx->worker;
	struct engine *engine = worker->engine;
	kr_resolve_begin(req, &engine->resolver, answer);
	worker->stats.queries += 1;
	/* Throttle outbound queries only when high pressure */
	if (worker->stats.concurrent < QUERY_RATE_THRESHOLD) {
		req->options.NO_THROTTLE = true;
	}
	return 0;
}

static void request_free(struct request_ctx *ctx)
{
	struct worker_ctx *worker = ctx->worker;
	/* Return mempool to ring or free it if it's full */
	pool_release(worker, ctx->req.pool.ctx);
	/* @note The 'task' is invalidated from now on. */
	/* Decommit memory every once in a while */
	static int mp_delete_count = 0;
	if (++mp_delete_count == 100000) {
		lua_gc(worker->engine->L, LUA_GCCOLLECT, 0);
#if defined(__GLIBC__) && defined(_GNU_SOURCE)
		malloc_trim(0);
#endif
		mp_delete_count = 0;
	}
}

static struct qr_task *qr_task_create(struct request_ctx *ctx)
{
	/* How much can client handle? */
	struct engine *engine = ctx->worker->engine;
	size_t pktbuf_max = KR_EDNS_PAYLOAD;
	if (engine->resolver.opt_rr) {
		pktbuf_max = MAX(knot_edns_get_payload(engine->resolver.opt_rr),
				 pktbuf_max);
	}

	/* Create resolution task */
	struct qr_task *task = mm_alloc(&ctx->req.pool, sizeof(*task));
	if (!task) {
		return NULL;
	}

	/* Create packet buffers for answer and subrequests */
	knot_pkt_t *pktbuf = knot_pkt_new(NULL, pktbuf_max, &ctx->req.pool);
	if (!pktbuf) {
		return NULL;
	}
	pktbuf->size = 0;
	task->ctx = ctx;
	task->pktbuf = pktbuf;
	array_init(task->waiting);
	task->addrlist = NULL;
	task->pending_count = 0;
	task->bytes_remaining = 0;
	task->iter_count = 0;
	task->timeouts = 0;
	task->refs = 1;
	task->finished = false;
	task->leading = false;
	task->current_session = NULL;
	task->timeout = NULL;
	task->on_complete = NULL;
	int ret = array_push(ctx->tasks, task);
	return ret < 0 ? NULL : task;
}

/* This is called when the task refcount is zero, free memory. */
static void qr_task_free(struct qr_task *task)
{
	struct request_ctx *ctx = task->ctx;

	assert(ctx);

	/* Process outbound session. */
	struct session *session = task->current_session;
	struct session *source_session = ctx->source.session;
	struct worker_ctx *worker = ctx->worker;
	task->current_session = NULL;
	if (session) {
		assert (session->outgoing);
		/* Remove itself from the session task list. */
		for (size_t i = 0; i < session->tasks.len; ++i) {
			if (session->tasks.at[i] == task) {
				array_del(session->tasks, i);
				break;		
			}
		}
	}

	/* Process source session. */
	if (source_session) {
		/* Walk the session task list and remove itself. */
		for (size_t i = 0; i < source_session->tasks.len; ++i) {
			if (source_session->tasks.at[i] == task) {
				array_del(source_session->tasks, i);
				break;
			}
		}
		/* Start reading again if the session is throttled and
		 * the number of outgoing requests is below watermark. */
		uv_handle_t *handle = source_session->handle;
		if (handle && source_session->tasks.len < worker->tcp_pipeline_max/2) {
			if (!uv_is_closing(handle) && source_session->throttled) {
				io_start_read(handle);
				source_session->throttled = false;
			}
		}
	}

	for (size_t i = 0; i < ctx->tasks.len; ++i) {
		if (ctx->tasks.at[i] == task) {
			array_del(ctx->tasks, i);
			break;
		}
	}
	if (ctx->tasks.len == 0) {
		array_clear(ctx->tasks);
	}

	/* Update stats */
	worker->stats.concurrent -= 1;
	if (ctx->tasks.len == 0) {
		request_free(ctx);
	}
}

/*@ Register new qr_task within session. */
static int qr_task_register(struct qr_task *task, struct session *session)
{
	assert(session->outgoing == false);

	int ret = array_reserve(session->tasks, session->tasks.len + 1);
	if (ret != 0) {
		return kr_error(ENOMEM);
	}

	array_push(session->tasks, task);

	struct request_ctx *ctx = task->ctx;
	assert(ctx && (ctx->source.session == NULL || ctx->source.session == session));
	ctx->source.session = session;
	/* Soft-limit on parallel queries, there is no "slow down" RCODE
	 * that we could use to signalize to client, but we can stop reading,
	 * an in effect shrink TCP window size. To get more precise throttling,
	 * we would need to copy remainder of the unread buffer and reassemble
	 * when resuming reading. This is NYI.  */
	if (session->tasks.len >= task->ctx->worker->tcp_pipeline_max) {
		uv_handle_t *handle = session->handle;
		if (handle && !session->throttled && !uv_is_closing(handle)) {
			io_stop_read(handle);
			session->throttled = true;
		}
	}

	return 0;
}

static void qr_task_complete(struct qr_task *task)
{
	struct request_ctx *ctx = task->ctx;
	struct worker_ctx *worker = ctx->worker;
	/* Kill pending I/O requests */
	ioreq_kill_pending(task);
	assert(task->waiting.len == 0);
	assert(task->leading == false);
	/* Run the completion callback. */
	if (task->on_complete) {
		task->on_complete(worker, &ctx->req, task->baton);
	}
	/* Release primary reference to task. */
	qr_task_unref(task);
}

/* This is called when we send subrequest / answer */
static int qr_task_on_send(struct qr_task *task, uv_handle_t *handle, int status)
{
	if (task->finished) {
		assert(task->timeout == NULL);
		qr_task_complete(task);
		return status;
	}
	if (status == 0 && handle) {
		struct session* session = handle->data;
		if (handle->type == UV_TCP && session->outgoing &&
		    session->waiting.len > 0) {
			struct qr_task *t = session->waiting.at[0];
			assert (t == task);
			array_del(session->waiting, 0);
			int ret = (session_add_tasks(session, task) >= 0);
			if (ret < 0) {
				assert(task->timeout == NULL);
				qr_task_complete(task);
				return status;
			}
			if (session->waiting.len > 0) {
				t = session->waiting.at[0];
				ret = qr_task_send(t, (uv_handle_t *)handle,
						   &session->peer.ip, t->pktbuf);
				if (ret != kr_ok()) {
					assert(task->timeout == NULL);
					qr_task_complete(task);
					return status;
				}
			}
		}
		io_start_read(handle); /* Start reading new query */
	}
	return status;
}

static void on_send(uv_udp_send_t *req, int status)
{
	struct worker_ctx *worker = get_worker();
	struct qr_task *task = req->data;
	if (qr_valid_handle(task, (uv_handle_t *)req->handle)) {
		qr_task_on_send(task, (uv_handle_t *)req->handle, status);
	}
	qr_task_unref(task);
	req_release(worker, (struct req *)req);
}

static void on_write(uv_write_t *req, int status)
{
	struct worker_ctx *worker = get_worker();
	struct qr_task *task = req->data;
	if (qr_valid_handle(task, (uv_handle_t *)req->handle)) {
		qr_task_on_send(task, (uv_handle_t *)req->handle, status);
	}
	qr_task_unref(task);
	req_release(worker, (struct req *)req);
}

static int qr_task_send(struct qr_task *task, uv_handle_t *handle, struct sockaddr *addr, knot_pkt_t *pkt)
{
	if (!handle) {
		return qr_task_on_send(task, handle, kr_error(EIO));
	}

	/* Synchronous push to TLS context, bypassing event loop. */
	struct session *session = handle->data;
	if (session->has_tls) {
		assert(false);
		int ret = tls_push(task, handle, pkt);
		return qr_task_on_send(task, handle, ret);
	}

	int ret = 0;
	struct request_ctx *ctx = task->ctx;
	struct worker_ctx *worker = ctx->worker;
	struct kr_request *req = &ctx->req;
	struct req *send_req = req_borrow(worker);
	if (!send_req) {
		return qr_task_on_send(task, handle, kr_error(ENOMEM));
	}
	if (knot_wire_get_qr(pkt->wire) == 0) {
		/*
		 * Query must be finalised using destination address before
		 * sending.
		 *
		 * Libuv does not offer a convenient way how to obtain a source
		 * IP address from a UDP handle that has been initialised using
		 * uv_udp_init(). The uv_udp_getsockname() fails because of the
		 * lazy socket initialisation.
		 *
		 * @note -- A solution might be opening a separate socket and
		 * trying to obtain the IP address from it.
		 */
		ret = kr_resolve_checkout(req, NULL, addr,
		                          handle->type == UV_UDP ? SOCK_DGRAM : SOCK_STREAM,
		                          pkt);
		if (ret != kr_ok()) {
			req_release(worker, send_req);
			return ret;
		}
	}
	/* Send using given protocol */
	if (handle->type == UV_UDP) {
		uv_buf_t buf = { (char *)pkt->wire, pkt->size };
		send_req->as.send.data = task;
		ret = uv_udp_send(&send_req->as.send, (uv_udp_t *)handle, &buf, 1, addr, &on_send);
	} else {
		uint16_t pkt_size = htons(pkt->size);
		uv_buf_t buf[2] = {
			{ (char *)&pkt_size, sizeof(pkt_size) },
			{ (char *)pkt->wire, pkt->size }
		};
		send_req->as.write.data = task;
		ret = uv_write(&send_req->as.write, (uv_stream_t *)handle, buf, 2, &on_write);
	}
	if (ret == 0) {
		qr_task_ref(task); /* Pending ioreq on current task */
	} else {
		req_release(worker, send_req);
	}

	/* Update statistics */
	if (ctx->source.session &&
	    handle != ctx->source.session->handle &&
	    addr) {
		if (handle->type == UV_UDP)
			worker->stats.udp += 1;
		else
			worker->stats.tcp += 1;
		if (addr->sa_family == AF_INET6)
			worker->stats.ipv6 += 1;
		else
			worker->stats.ipv4 += 1;
	}
	return ret;
}

static void on_timer_close(uv_handle_t *handle)
{
	struct qr_task *task = handle->data;
	req_release(task->ctx->worker, (struct req *)handle);
	qr_task_unref(task);
}

static void on_session_tcp_timer_close(uv_handle_t *handle)
{
	struct session *s = handle->data;
	session_close(s);
}

static void on_connect(uv_connect_t *req, int status)
{
	struct worker_ctx *worker = get_worker();
	uv_stream_t *handle = req->handle;
	struct session *session = handle->data;

	union inaddr *peer = &session->peer;
	worker_del_tcp_waiting(worker, &peer->ip);

	if (uv_is_closing((uv_handle_t *)handle)) {
		while (session->waiting.len > 0) {
			struct qr_task *task = session->waiting.at[0];
			array_del(session->waiting, 0);
			qr_task_unref(task);
		}
		req_release(worker, (struct req *)req);
		return;
	} else if (status != 0) {
		while (session->waiting.len > 0) {
			struct qr_task *task = session->waiting.at[0];
			array_del(session->waiting, 0);
			qr_task_step(task, task->addrlist, NULL);
			qr_task_unref(task);
		}
		req_release(worker, (struct req *)req);
		return;
	}

	session->connected = true;

	char peer_str[INET6_ADDRSTRLEN + 6];
	size_t peer_str_len = sizeof(peer_str);
	kr_inaddr_str(&peer->ip, peer_str, &peer_str_len);

	session->handle = (uv_handle_t *)handle;
	worker_add_tcp_connected(worker, &session->peer.ip, session);

	session->timeout.data = session;
	uv_timer_init(worker->loop, &session->timeout);

	if (session->waiting.len > 0) {
		struct qr_task *task = session->waiting.at[0];
		if (task->timeout != NULL) {
			uv_timer_stop(task->timeout);
			uv_close((uv_handle_t *)task->timeout, on_timer_close);
			task->timeout = NULL;
		}
		qr_task_send(task, (uv_handle_t *)handle, &peer->ip, task->pktbuf);
		qr_task_unref(task);
	}

	req_release(worker, (struct req *)req);
}

/* This is called when I/O timeouts */
static void on_timeout(uv_timer_t *req)
{
	struct qr_task *task = req->data;

	/* Penalize all tried nameservers with a timeout. */
	struct worker_ctx *worker = task->ctx->worker;
	if (task->leading && task->pending_count > 0) {
		struct kr_query *qry = array_tail(task->ctx->req.rplan.pending);
		struct sockaddr_in6 *addrlist = (struct sockaddr_in6 *)task->addrlist;
		for (uint16_t i = 0; i < MIN(task->pending_count, task->addrlist_count); ++i) {
			struct sockaddr *choice = (struct sockaddr *)(&addrlist[i]);
			WITH_VERBOSE {
				char addr_str[INET6_ADDRSTRLEN];
				inet_ntop(choice->sa_family, kr_inaddr(choice), addr_str, sizeof(addr_str));
				VERBOSE_MSG(qry, "=> server: '%s' flagged as 'bad'\n", addr_str);
			}
			kr_nsrep_update_rtt(&qry->ns, choice, KR_NS_TIMEOUT,
					    worker->engine->resolver.cache_rtt, KR_NS_UPDATE);
		}
	}
	/* Release timer handle */
	task->timeout = NULL;
	uv_close((uv_handle_t *)req, on_timer_close); /* Return borrowed task here */
	/* Interrupt current pending request. */
	task->timeouts += 1;
	worker->stats.timeout += 1;
	qr_task_step(task, NULL, NULL);
}

static void on_session_tcp_timeout(uv_timer_t *timer)
{
	struct session *s = timer->data;
	assert(s && s->outgoing);
	uv_close((uv_handle_t *)timer, on_session_tcp_timer_close);
}

static bool retransmit(struct qr_task *task)
{
	if (task && task->addrlist && task->addrlist_count > 0) {
		struct sockaddr_in6 *choice = &((struct sockaddr_in6 *)task->addrlist)[task->addrlist_turn];
		uv_handle_t *subreq = ioreq_spawn(task, SOCK_DGRAM, choice->sin6_family);
		if (subreq) { /* Create connection for iterative query */
			if (qr_task_send(task, subreq, (struct sockaddr *)choice, task->pktbuf) == 0) {
				task->addrlist_turn = (task->addrlist_turn + 1) % task->addrlist_count; /* Round robin */
				return true;
			}
		}
	}
	return false;
}

static void on_retransmit(uv_timer_t *req)
{
	struct qr_task *task = req->data;
	assert(task->finished == false);
	assert(task->timeout != NULL);

	uv_timer_stop(req);
	if (!retransmit(req->data)) {
		/* Not possible to spawn request, start timeout timer with remaining deadline. */
		uint64_t timeout = KR_CONN_RTT_MAX - task->pending_count * KR_CONN_RETRY;
		uv_timer_start(req, on_timeout, timeout, 0);
	} else {
		uv_timer_start(req, on_retransmit, KR_CONN_RETRY, 0);
	}
}

static int timer_start(struct qr_task *task, uv_timer_cb cb,
		       uint64_t timeout, uint64_t repeat)
{
	assert(task->timeout == NULL);
	struct worker_ctx *worker = task->ctx->worker;
	uv_timer_t *timer = (uv_timer_t *)req_borrow(worker);
	if (!timer) {
		return kr_error(ENOMEM);
	}
	uv_timer_init(worker->loop, timer);
	int ret = uv_timer_start(timer, cb, timeout, repeat);
	if (ret != 0) {
		uv_timer_stop(timer);
		req_release(worker, (struct req *)timer);
		return kr_error(ENOMEM);
	}
	timer->data = task;
	qr_task_ref(task);
	task->timeout = timer;
	return 0;
}

static void subreq_finalize(struct qr_task *task, const struct sockaddr *packet_source, knot_pkt_t *pkt)
{
	/* Close pending timer */
	if (task->timeout) {
		/* Timer was running so it holds reference to task, make sure the timer event
		 * never fires and release the reference on timer close instead. */
		uv_timer_stop(task->timeout);
		uv_close((uv_handle_t *)task->timeout, on_timer_close);
		task->timeout = NULL;
	}
	ioreq_kill_pending(task);
	/* Clear from outgoing table. */
	if (!task->leading)
		return;
	char key[KR_RRKEY_LEN];
	int ret = subreq_key(key, task->pktbuf);
	if (ret > 0) {
		assert(map_get(&task->ctx->worker->outgoing, key) == task);
		map_del(&task->ctx->worker->outgoing, key);
	}
	/* Notify waiting tasks. */
	struct kr_query *leader_qry = array_tail(task->ctx->req.rplan.pending);
	for (size_t i = task->waiting.len; i --> 0;) {
		struct qr_task *follower = task->waiting.at[i];
		/* Reuse MSGID and 0x20 secret */
		if (follower->ctx->req.rplan.pending.len > 0) {
			struct kr_query *qry = array_tail(follower->ctx->req.rplan.pending);
			qry->id = leader_qry->id;
			qry->secret = leader_qry->secret;
			leader_qry->secret = 0; /* Next will be already decoded */
		}
		qr_task_step(follower, packet_source, pkt);
		qr_task_unref(follower);
	}
	task->waiting.len = 0;
	task->leading = false;
}

static void subreq_lead(struct qr_task *task)
{
	assert(task);
	char key[KR_RRKEY_LEN];
	if (subreq_key(key, task->pktbuf) > 0) {
		assert(map_contains(&task->ctx->worker->outgoing, key) == false);
		map_set(&task->ctx->worker->outgoing, key, task);
		task->leading = true;
	}
}

static bool subreq_enqueue(struct qr_task *task)
{
	assert(task);
	char key[KR_RRKEY_LEN];
	if (subreq_key(key, task->pktbuf) > 0) {
		struct qr_task *leader = map_get(&task->ctx->worker->outgoing, key);
		if (leader) {
			/* Enqueue itself to leader for this subrequest. */
			int ret = array_reserve_mm(leader->waiting, leader->waiting.len + 1,
						   kr_memreserve, &leader->ctx->req.pool);
			if (ret == 0) {
				array_push(leader->waiting, task);
				qr_task_ref(task);
				return true;
			}
		}
	}
	return false;
}

static int qr_task_finalize(struct qr_task *task, int state)
{
	assert(task && task->leading == false);
	struct request_ctx *ctx = task->ctx;
	kr_resolve_finish(&ctx->req, state);
	task->finished = true;
	/* Send back answer */
	if (ctx->source.session != NULL) {
		(void) qr_task_send(task, ctx->source.session->handle,
				    (struct sockaddr *)&ctx->source.addr,
				    ctx->req.answer);
	}
	return state == KR_STATE_DONE ? 0 : kr_error(EIO);
}

static int qr_task_step(struct qr_task *task,
			const struct sockaddr *packet_source, knot_pkt_t *packet)
{
	/* No more steps after we're finished. */
	if (!task || task->finished) {
		return kr_error(ESTALE);
	}

	/* Close pending I/O requests */
	subreq_finalize(task, packet_source, packet);
	/* Consume input and produce next query */
	struct request_ctx *ctx = task->ctx;
	struct kr_request *req = &ctx->req;
	int sock_type = -1;
	task->addrlist = NULL;
	task->addrlist_count = 0;
	task->addrlist_turn = 0;
	req->has_tls = (ctx->source.session && ctx->source.session->has_tls);
	int state = kr_resolve_consume(req, packet_source, packet);
	while (state == KR_STATE_PRODUCE) {
		state = kr_resolve_produce(req, &task->addrlist,
					   &sock_type, task->pktbuf);
		if (unlikely(++task->iter_count > KR_ITER_LIMIT ||
			     task->timeouts >= KR_TIMEOUT_LIMIT)) {
			return qr_task_finalize(task, KR_STATE_FAIL);
		}
	}

	/* We're done, no more iterations needed */
	if (state & (KR_STATE_DONE|KR_STATE_FAIL)) {
		return qr_task_finalize(task, state);
	} else if (!task->addrlist || sock_type < 0) {
		return qr_task_step(task, NULL, NULL);
	}

	/* Count available address choices */
	struct sockaddr_in6 *choice = (struct sockaddr_in6 *)task->addrlist;
	for (size_t i = 0; i < KR_NSREP_MAXADDR && choice->sin6_family != AF_UNSPEC; ++i) {
		task->addrlist_count += 1;
		choice += 1;
	}

	/* Start fast retransmit with UDP, otherwise connect. */
	int ret = 0;
	if (sock_type == SOCK_DGRAM) {
		/* If there is already outgoing query, enqueue to it. */
		if (subreq_enqueue(task)) {
			return kr_ok(); /* Will be notified when outgoing query finishes. */
		}
		/* Start transmitting */
		if (retransmit(task)) {
			/* Check current query NSLIST */
			struct kr_query *qry = array_tail(req->rplan.pending);
			assert(qry != NULL);
			/* Retransmit at default interval, or more frequently if the mean
			 * RTT of the server is better. If the server is glued, use default rate. */
			size_t timeout = qry->ns.score;
			if (timeout > KR_NS_GLUED) {
				/* We don't have information about variance in RTT, expect +10ms */
				timeout = MIN(qry->ns.score + 10, KR_CONN_RETRY);
			} else {
				timeout = KR_CONN_RETRY;
			}
			ret = timer_start(task, on_retransmit, timeout, 0);
		} else {
			return qr_task_step(task, NULL, NULL);
		}
		/* Announce and start subrequest.
		 * @note Only UDP can lead I/O as it doesn't touch 'task->pktbuf' for reassembly.
		 */
		subreq_lead(task);
	} else {
		const struct sockaddr *addr =
			packet_source ? packet_source : task->addrlist;
		struct session* session = NULL;
		if ((session = worker_find_tcp_waiting(ctx->worker, addr)) != NULL) {
			/* There are waiting tasks.
			 * It means that connection establishing or data sending
			 * is comingright now. */
			/* Task will be notified in on_connect() or qr_task_on_send(). */
			ret = (session_add_waiting(session, task) < 0);
		} else if ((session = worker_find_tcp_connected(ctx->worker, addr)) != NULL) {
			/* Connection has been already established */
			assert(session->outgoing);
			if (session->tasks.len == 0) {
				uv_timer_stop(&session->timeout);
			}
			/* will be removed in qr_task_on_send() */
			ret = session_add_waiting(session, task);
			if (ret < 0) {
				subreq_finalize(task, packet_source, packet);
				return qr_task_finalize(task, KR_STATE_FAIL);
			}
			task->current_session = session;
			task->pending[task->pending_count] = session->handle;
			task->pending_count += 1;
			qr_task_ref(task);
			ret = qr_task_send(task, session->handle,
					   &session->peer.ip, task->pktbuf);
		} else {
			/* Make connection */
			uv_connect_t *conn = (uv_connect_t *)req_borrow(ctx->worker);
			if (!conn) {
				return qr_task_step(task, NULL, NULL);
			}
			uv_handle_t *client = ioreq_spawn(task, sock_type,
							  addr->sa_family);
			if (!client) {
				req_release(ctx->worker, (struct req *)conn);
				return qr_task_step(task, NULL, NULL);
			}
			session = client->data;
			conn->data = session;
			uint16_t msg_id = knot_wire_get_id(task->pktbuf->wire);
			memcpy(&session->peer, addr, sizeof(session->peer));
			if (uv_tcp_connect(conn, (uv_tcp_t *)client,
					   addr , on_connect) != 0) {
				req_release(ctx->worker, (struct req *)conn);
				return qr_task_step(task, NULL, NULL);
			}
			qr_task_ref(task); /* Connect request borrows task */
			ret = worker_add_tcp_waiting(ctx->worker, addr, session);
			if (ret < 0) {
				subreq_finalize(task, packet_source, packet);
				return qr_task_finalize(task, KR_STATE_FAIL);
			}
			/* will be removed in qr_task_on_send() */
			ret = session_add_waiting(session, task);
			if (ret < 0) {
				subreq_finalize(task, packet_source, packet);
				return qr_task_finalize(task, KR_STATE_FAIL);
			}
			ret = timer_start(task, on_timeout, KR_CONN_RTT_MAX, 0);
		}
	}

	/* Start next step with timeout, fatal if can't start a timer. */
	if (ret != 0) {
		subreq_finalize(task, packet_source, packet);
		return qr_task_finalize(task, KR_STATE_FAIL);
	}
	return kr_ok();
}

static int parse_packet(knot_pkt_t *query)
{
	if (!query){
		return kr_error(EINVAL);
	}

	/* Parse query packet. */
	int ret = knot_pkt_parse(query, 0);
	if (ret != KNOT_EOK) {
		return kr_error(EPROTO); /* Ignore malformed query. */
	}

	/* Check if at least header is parsed. */
	if (query->parsed < query->size) {
		return kr_error(EMSGSIZE);
	}

	return kr_ok();
}

static struct qr_task* find_task(const struct session *session, uint16_t msg_id)
{
	struct qr_task *ret = NULL;
	const qr_tasklist_t *tasklist = &session->tasks;
	for (size_t i = 0; i < tasklist->len; ++i) {
		struct qr_task *task = tasklist->at[i];
		uint16_t task_msg_id = knot_wire_get_id(task->pktbuf->wire);
		if (task_msg_id == msg_id) {
			ret = task;
			break;
		}
	}
	return ret;
}


int worker_submit(struct worker_ctx *worker, uv_handle_t *handle,
		  knot_pkt_t *msg, const struct sockaddr* addr)
{
	if (!worker || !handle) {
		return kr_error(EINVAL);
	}

	struct session *session = handle->data;
	assert(session);

	/* Parse packet */
	int ret = parse_packet(msg);

	/* Start new task on listening sockets,
	 * or resume if this is subrequest */
	struct qr_task *task = NULL;
	if (!session->outgoing) {
		/* Ignore badly formed queries or responses. */
		if (!msg || ret != 0 || knot_wire_get_qr(msg->wire)) {
			if (msg) worker->stats.dropped += 1;
			return kr_error(EINVAL); /* Ignore. */
		}
		struct request_ctx *ctx = request_create(worker, handle, addr);
		if (!ctx) {
			return kr_error(ENOMEM);
		}

		ret = request_start(ctx, msg);
		if (ret != 0) {
			request_free(ctx);
			return kr_error(ENOMEM);
		}

		task = qr_task_create(ctx);
		if (!task) {
			request_free(ctx);
			return kr_error(ENOMEM);
		}
	} else if (msg) {
		task = find_task(session, knot_wire_get_id(msg->wire));
	}

	/* Consume input and produce next message */
	return qr_task_step(task, NULL, msg);
}

static int map_add_tcp_session(map_t *map, const struct sockaddr* addr,
			       struct session *session)
{
	assert(map && addr);
	const char *key = tcpsess_key(addr);
	assert(key);
	assert(map_contains(map, key) == 0);
	int ret = map_set(map, key, session);
	ret = ret ? kr_error(ret) : kr_ok();
	return ret;
}

static int map_del_tcp_session(map_t *map, const struct sockaddr* addr)
{
	assert(map && addr);
	const char *key = tcpsess_key(addr);
	assert(key);
	int ret = map_del(map, key);
	ret = ret ? kr_error(ret) : kr_ok();
	return ret;
}

static struct session* map_find_tcp_session(map_t *map,
					    const struct sockaddr *addr)
{
	assert(map && addr);
	const char *key = tcpsess_key(addr);
	assert(key);
	struct session* ret = map_get(map, key);
	return ret;
}

static int worker_add_tcp_connected(struct worker_ctx *worker,
				    const struct sockaddr* addr,
				    struct session *session)
{
	return map_add_tcp_session(&worker->tcp_connected, addr, session);
}

static int worker_del_tcp_connected(struct worker_ctx *worker,
				    const struct sockaddr* addr)
{
	return map_del_tcp_session(&worker->tcp_connected, addr);
}

static struct session* worker_find_tcp_connected(struct worker_ctx *worker,
						 const struct sockaddr* addr)
{
	return map_find_tcp_session(&worker->tcp_connected, addr);
}

static int worker_add_tcp_waiting(struct worker_ctx *worker,
				  const struct sockaddr* addr,
				  struct session *session)
{
	return map_add_tcp_session(&worker->tcp_waiting, addr, session);
}

static int worker_del_tcp_waiting(struct worker_ctx *worker,
				  const struct sockaddr* addr)
{
	return map_del_tcp_session(&worker->tcp_waiting, addr);
}

static struct session* worker_find_tcp_waiting(struct worker_ctx *worker,
					       const struct sockaddr* addr)
{
	return map_find_tcp_session(&worker->tcp_waiting, addr);
}

/* Return DNS/TCP message size. */
static int get_msg_size(const uint8_t *msg)
{
		return wire_read_u16(msg);
}

/* If buffering, close last task as it isn't live yet. */
static void discard_buffered(struct session *session)
{
	if (session->buffering) {
		qr_task_free(session->buffering);
		session->buffering = NULL;
		session->msg_hdr_idx = 0;
	}
}

int worker_end_tcp(struct worker_ctx *worker, uv_handle_t *handle)
{
	if (!worker || !handle) {
		return kr_error(EINVAL);
	}
	/* If this is subrequest, notify parent task with empty input
	 * because in this case session doesn't own tasks, it has just
	 * borrowed the task from parent session. */
	struct session *session = handle->data;
	if (session->outgoing) {
		worker_submit(worker, (uv_handle_t *)handle, NULL, NULL);
	} else {
		discard_buffered(session);
	}
	return 0;
}

int worker_process_tcp(struct worker_ctx *worker, uv_stream_t *handle,
		       const uint8_t *msg, ssize_t len)

{
	if (!worker || !handle) {
		return kr_error(EINVAL);
	}
	/* Connection error or forced disconnect */
	struct session *session = handle->data;
	if (len < 0 || !msg) {
		/* If we have pending tasks, we must dissociate them from the
		 * connection so they don't try to access closed and freed handle.
		 * @warning Do not modify task if this is outgoing request
		 * as it is shared with originator.
		 */
		while (session->tasks.len > 0) {
			struct qr_task *task = session->tasks.at[0];
			array_del(session->tasks, 0);
			qr_task_complete(task);
		}
		return kr_error(ECONNRESET);
	}

	int submitted = 0;
	struct qr_task *task = session->buffering;
	knot_pkt_t *pkt_buf = NULL;
	if (task) {
		pkt_buf = task->pktbuf;
	} else {
		assert(session->msg_hdr_idx < sizeof(session->msg_hdr));
		ssize_t hdr_amount = sizeof(session->msg_hdr) -
				     session->msg_hdr_idx;
		if (hdr_amount > len) {
			hdr_amount = len;
		}
		if (hdr_amount > 0) {
			memcpy(session->msg_hdr, msg, hdr_amount);
			session->msg_hdr_idx += hdr_amount;
			len -= hdr_amount;
			msg += hdr_amount;
		}
		if (len == 0 && session->msg_hdr_idx < sizeof(session->msg_hdr)) {
			return kr_ok();
		}
		assert(session->msg_hdr_idx == sizeof(session->msg_hdr));
		session->msg_hdr_idx = 0;
		uint16_t msg_size = get_msg_size(session->msg_hdr);
		uint16_t msg_id = knot_wire_get_id(session->msg_hdr + 2);
		if (msg_size < KNOT_WIRE_HEADER_SIZE) {
			return kr_error(EINVAL);
		}

		if (!session->outgoing) {
			/* This is a new query, create a new task that we can use
			 * to buffer incoming message until it's complete.
			 * Get TCP peer name, keep zeroed address if it fails. */
			struct sockaddr_storage addr;
			memset(&addr, 0, sizeof(addr));
			int addr_len = sizeof(addr);
			uv_tcp_getpeername((uv_tcp_t *)handle,
					   (struct sockaddr *)&addr, &addr_len);
			struct request_ctx *ctx = request_create(worker,
								 (uv_handle_t *)handle,
								 (struct sockaddr *)&addr);
			if (!ctx) {
				return kr_error(ENOMEM);
			}
			task = qr_task_create(ctx);
			if (!task) {
				return kr_error(ENOMEM);
			}
			pkt_buf = task->pktbuf;
		} else {
			/* Start of response from upstream.
			 * The session task list must contain a task
			 * with the same msg id. */
			task = find_task(session, msg_id);
			if (!task) {
				/* Task was not found, ignore packet */
				return kr_error(ENOENT);
			}
			pkt_buf = task->pktbuf;
			knot_pkt_clear(pkt_buf);
		}
		knot_wire_set_id(pkt_buf->wire, msg_id);
		pkt_buf->size = 2;
		task->bytes_remaining = msg_size - 2;
		session->buffering = task;
	}
	/* At this point session must have either created new task
	 * or it's already assigned. */
	assert(task);
	assert(len > 0);
	/* Message is too long, can't process it. */
	ssize_t to_read = MIN(len, task->bytes_remaining);
	if (pkt_buf->size + to_read > pkt_buf->max_size) {
		pkt_buf->size = 0;
		task->bytes_remaining = 0;
		return kr_error(EMSGSIZE);
	}
	/* Buffer message and check if it's complete */
	memcpy(pkt_buf->wire + pkt_buf->size, msg, to_read);
	pkt_buf->size += to_read;
	if (to_read >= task->bytes_remaining) {
		task->bytes_remaining = 0;
		/* Message was assembled, clear temporary. */
		session->buffering = NULL;
		session->msg_hdr_idx = 0;
		/* Parse the packet and start resolving complete query */
		int ret = parse_packet(pkt_buf);
		if (ret == 0 && !session->outgoing) {
			/* Start only new queries,
			 * not subrequests that are already pending */
			ret = request_start(task->ctx, pkt_buf);
			if (ret != 0) {
				return ret;
			}
			ret = qr_task_register(task, session);
			if (ret != 0) {
				return ret;
			}
			submitted += 1;
		}
		if (ret == 0) {
			ret = qr_task_step(task, NULL, pkt_buf);
		}
		/* Process next message part in the stream if no error so far */
		if (ret != 0) {
			return ret;
		}
		if (len - to_read > 0 && !session->outgoing) {
			ret = worker_process_tcp(worker, handle, msg + to_read, len - to_read);
			if (ret < 0) {
				return ret;
			}
			submitted += ret;
		}
	} else {
		task->bytes_remaining -= to_read;	
	}
	return submitted;
}

int worker_resolve(struct worker_ctx *worker, knot_pkt_t *query,
		   struct kr_qflags options, worker_cb_t on_complete,
		   void *baton)
{
	if (!worker || !query) {
		return kr_error(EINVAL);
	}

	struct request_ctx *ctx = request_create(worker, NULL, NULL);
	if (!ctx) {
		return kr_error(ENOMEM);
	}

	/* Create task */
	struct qr_task *task = qr_task_create(ctx);
	if (!task) {
		return kr_error(ENOMEM);
	}
	task->baton = baton;
	task->on_complete = on_complete;
	/* Start task */
	int ret = request_start(ctx, query);

	/* Set options late, as qr_task_start() -> kr_resolve_begin() rewrite it. */
	kr_qflags_set(&task->ctx->req.options, options);

	if (ret != 0) {
		qr_task_unref(task);
		return ret;
	}
	return qr_task_step(task, NULL, query);
}

/** Reserve worker buffers */
static int worker_reserve(struct worker_ctx *worker, size_t ring_maxlen)
{
	array_init(worker->pool_mp);
	array_init(worker->pool_ioreq);
	array_init(worker->pool_sessions);
	if (array_reserve(worker->pool_mp, ring_maxlen) ||
		array_reserve(worker->pool_ioreq, ring_maxlen) ||
		array_reserve(worker->pool_sessions, ring_maxlen))
		return kr_error(ENOMEM);
	memset(&worker->pkt_pool, 0, sizeof(worker->pkt_pool));
	worker->pkt_pool.ctx = mp_new (4 * sizeof(knot_pkt_t));
	worker->pkt_pool.alloc = (knot_mm_alloc_t) mp_alloc;
	worker->outgoing = map_make();
	worker->tcp_connected = map_make();
	worker->tcp_waiting = map_make();
	worker->tcp_pipeline_max = MAX_PIPELINED;
	return kr_ok();
}

#define reclaim_freelist(list, type, cb) \
	for (unsigned i = 0; i < list.len; ++i) { \
		type *elm = list.at[i]; \
		kr_asan_unpoison(elm, sizeof(type)); \
		cb(elm); \
	} \
	array_clear(list)

void worker_reclaim(struct worker_ctx *worker)
{
	reclaim_freelist(worker->pool_mp, struct mempool, mp_delete);
	reclaim_freelist(worker->pool_ioreq, struct req, free);
	reclaim_freelist(worker->pool_sessions, struct session, session_free);
	mp_delete(worker->pkt_pool.ctx);
	worker->pkt_pool.ctx = NULL;
	map_clear(&worker->outgoing);
	map_clear(&worker->tcp_connected);
	map_clear(&worker->tcp_waiting);
}

struct worker_ctx *worker_create(struct engine *engine, knot_mm_t *pool,
		int worker_id, int worker_count)
{
	/* Load bindings */
	engine_lualib(engine, "modules", lib_modules);
	engine_lualib(engine, "net",     lib_net);
	engine_lualib(engine, "cache",   lib_cache);
	engine_lualib(engine, "event",   lib_event);
	engine_lualib(engine, "worker",  lib_worker);

	/* Create main worker. */
	struct worker_ctx *worker = mm_alloc(pool, sizeof(*worker));
	if (!worker) {
		return NULL;
	}
	memset(worker, 0, sizeof(*worker));
	worker->id = worker_id;
	worker->count = worker_count;
	worker->engine = engine;
	worker_reserve(worker, MP_FREELIST_SIZE);
	worker->out_addr4.sin_family = AF_UNSPEC;
	worker->out_addr6.sin6_family = AF_UNSPEC;
	/* Register worker in Lua thread */
	lua_pushlightuserdata(engine->L, worker);
	lua_setglobal(engine->L, "__worker");
	lua_getglobal(engine->L, "worker");
	lua_pushnumber(engine->L, worker_id);
	lua_setfield(engine->L, -2, "id");
	lua_pushnumber(engine->L, getpid());
	lua_setfield(engine->L, -2, "pid");
	lua_pushnumber(engine->L, worker_count);
	lua_setfield(engine->L, -2, "count");
	lua_pop(engine->L, 1);
	return worker;
}

#undef VERBOSE_MSG
