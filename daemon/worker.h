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

#pragma once

#include "daemon/engine.h"
#include "lib/generic/array.h"
#include "lib/generic/map.h"


/** Query resolution task (opaque). */
struct qr_task;
/** Worker state (opaque). */
struct worker_ctx;
/** Worker callback */
typedef void (*worker_cb_t)(struct worker_ctx *worker, struct kr_request *req, void *baton);

/** Create and initialize the worker. */
struct worker_ctx *worker_create(struct engine *engine, knot_mm_t *pool,
		int worker_id, int worker_count);

/**
 * Process an incoming packet (query from a client or answer from upstream).
 *
 * @param worker the singleton worker
 * @param handle socket through which the request came
 * @param query  the packet, or NULL on an error from the transport layer
 * @param addr   the address from which the packet came (or NULL, possibly, on error)
 * @return 0 or an error code
 */
int worker_submit(struct worker_ctx *worker, uv_handle_t *handle, knot_pkt_t *query,
		const struct sockaddr* addr);

/**
 * Process incoming DNS/TCP message fragment(s).
 * If the fragment contains only a partial message, it is buffered.
 * If the fragment contains a complete query or completes current fragment, execute it.
 * @return the number of newly-completed requests (>=0) or an error code
 */
int worker_process_tcp(struct worker_ctx *worker, uv_stream_t *handle,
		const uint8_t *msg, ssize_t len);

/**
 * End current DNS/TCP session, this disassociates pending tasks from this session
 * which may be freely closed afterwards.
 */
int worker_end_tcp(struct worker_ctx *worker, uv_handle_t *handle);

/**
 * Schedule query for resolution.
 *
 * After resolution finishes, invoke on_complete with baton.
 * @return 0 or an error code
 *
 * @note the options passed are |-combined with struct kr_context::options
 * @todo maybe better semantics for this?
 */
int worker_resolve(struct worker_ctx *worker, knot_pkt_t *query, struct kr_qflags options,
		   worker_cb_t on_complete, void *baton);

/** Collect worker mempools */
void worker_reclaim(struct worker_ctx *worker);


/** @cond internal */

/** Number of request within timeout window. */
#define MAX_PENDING KR_NSREP_MAXADDR

/** Freelist of available mempools. */
typedef array_t(void *) mp_freelist_t;

/** List of query resolution tasks. */
typedef array_t(struct qr_task *) qr_tasklist_t;

/** Session list. */
typedef array_t(struct session *) qr_sessionlist_t;

/** \details Worker state is meant to persist during the whole life of daemon. */
struct worker_ctx {
	struct engine *engine;
	uv_loop_t *loop;
	int id;
	int count;
	unsigned tcp_pipeline_max;

	/** Addresses to bind for outgoing connections or AF_UNSPEC. */
	struct sockaddr_in out_addr4;
	struct sockaddr_in6 out_addr6;

#if __linux__
	uint8_t wire_buf[RECVMMSG_BATCH * KNOT_WIRE_MAX_PKTSIZE];
#else
	uint8_t wire_buf[KNOT_WIRE_MAX_PKTSIZE];
#endif
	struct {
		size_t concurrent;
		size_t udp;
		size_t tcp;
		size_t ipv4;
		size_t ipv6;
		size_t queries;
		size_t dropped;
		size_t timeout;
	} stats;

	/* List of active outbound TCP sessions */
	map_t tcp_connected;
	/* List of outbound TCP sessions waiting to be accepted */
	map_t tcp_waiting;
	map_t outgoing;
	mp_freelist_t pool_mp;
	mp_freelist_t pool_ioreq;
	mp_freelist_t pool_sessions;
	knot_mm_t pkt_pool;
};


/** @endcond */

