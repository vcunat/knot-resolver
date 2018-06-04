/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <uv.h>

#include "lib/utils.h"

/* Style: "local/static" identifiers are usually named tst_* */

/** The number of seconds between synchronized rotation of TLS session ticket key. */
#define TST_KEY_LIFETIME 3600

/* FIXME: review session_ticket_key* again before merge! */
/** Value from gnutls:lib/ext/session_ticket.c
 * Beware: changing this needs to change the hashing implementation. */
#define SESSION_KEY_SIZE 64

#if GNUTLS_VERSION_NUMBER < 0x030400
	/* It's of little use anyway.  We may get the salt through lua,
	 * which creates a copy outside of our control. */
	#define gnutls_memset memset
#endif

#if GNUTLS_VERSION_NUMBER >= 0x030407
	#define TST_HASH GNUTLS_DIG_SHA3_512
#else
	#define TST_HASH GNUTLS_DIG_SHA512
#endif

/** Fields are internal to session_ticket_key_* functions. */
typedef struct tls_session_ticket_ctx {
	uv_timer_t timer;	/**< timer for rotation of the key */
	unsigned char key[SESSION_KEY_SIZE]; /**< the key itself */
	uint16_t hash_len;	/**< length of `hash_data` */
	uint16_t epoch_shift;	/**< all epochs are shifted by this many seconds */
	char hash_data[];	/**< data to hash to obtain `key` */
} tst_ctx_t;

/** Check invariants, based on gnutls version. */
static bool tst_key_invariants(void)
{
	static int result = 0;
	if (result) return result > 0;
	bool ok = true;
	/* SHA3-512 output size may never change, but let's check it anyway :-) */
	ok = ok && gnutls_hash_get_len(TST_HASH) == SESSION_KEY_SIZE;
	/* The ticket key size might change in a different gnutls version. */
	gnutls_datum_t key = { 0, 0 };
	ok = ok && gnutls_session_ticket_key_generate(&key) == 0
		&& key.size == SESSION_KEY_SIZE;
	free(key.data);
	result = ok ? 1 : -1;
	return ok;
}

/** Create the internal structures and copy the salt. Beware: salt must be kept secure. */
static tst_ctx_t * tst_key_create(const char *salt, size_t salt_len, uv_loop_t *loop)
{
	const size_t hash_len = salt_len == 0 ? 0 : sizeof(size_t) + salt_len;
	if (salt_len &&
	    (!salt || hash_len > UINT16_MAX || hash_len < salt_len)) {
		assert(!EINVAL);
		return NULL;
		/* reasonable salt_len is best enforced in config API */
	}
	if (!tst_key_invariants()) {
		assert(!EFAULT);
		return NULL;
	}

	tst_ctx_t *key =
		malloc(offsetof(tst_ctx_t, hash_data) + hash_len);
	if (!key) return NULL;
	key->hash_len = hash_len;
	if (salt_len) {
		memcpy(key->hash_data + sizeof(size_t), salt, salt_len);
	}

	/* determine epoch_shift, (pseudo-)randomly */
	const uint16_t rand = salt_len < 2
		? (unsigned)salt[0] + 256 * (unsigned)salt[1]
		: kr_rand_uint(0);
	key->epoch_shift = rand % TST_KEY_LIFETIME;

	if (uv_timer_init(loop, &key->timer) != 0) {
		free(key);
		return NULL;
	}
	key->timer.data = key;
	return key;
}

/** Recompute the session ticket key, deterministically from epoch and salt. */
static int tst_key_update(tst_ctx_t *key, size_t epoch, bool force_update)
{
	if (!key || (key->hash_len && key->hash_len <= sizeof(size_t))) {
		assert(!EINVAL);
		return kr_error(EINVAL);
	}
	if (!force_update && memcmp(key->hash_data, &epoch, sizeof(size_t)) == 0) {
		return kr_ok(); /* we are up to date */
		/* TODO: support mixing endians? */
	}
	memcpy(key->hash_data, &epoch, sizeof(size_t));
	if (key->hash_len) {
		/* Deterministic variant of the rotation. */
		int ret = gnutls_hash_fast(TST_HASH, key->hash_data,
					   key->hash_len, key->key);
		return ret == 0 ? kr_ok() : kr_error(ret);
	}
	/* Otherwise, random variant of the rotation: generate into key_tmp and copy. */
	gnutls_datum_t key_tmp = { NULL, 0 };
	int ret = gnutls_session_ticket_key_generate(&key_tmp);
	if (!ret) return kr_error(ret);
	if (key_tmp.size != SESSION_KEY_SIZE) {
		assert(!EFAULT);
		return kr_error(EFAULT);
	}
	memcpy(key->key, key_tmp.data, SESSION_KEY_SIZE);
	gnutls_memset(key_tmp.data, 0, SESSION_KEY_SIZE);
	free(key_tmp.data);
	return kr_ok();
}

/** Free all resources of the key (securely). */
static void tst_key_destroy(uv_handle_t *timer)
{
	assert(timer);
	tst_ctx_t *key = timer->data;
	assert(key);
	gnutls_memset(key, 0, offsetof(tst_ctx_t, hash_data)
				+ key->hash_len);
	free(key);
}

static void tst_key_check(uv_timer_t *timer, bool force_update);
static void tst_timer_callback(uv_timer_t *timer)
{
	tst_key_check(timer, false);
}

/** Update the ST key if needed and reschedule itself via the timer. */
static void tst_key_check(uv_timer_t *timer, bool force_update)
{
	tst_ctx_t *stst = (tst_ctx_t *)timer->data;
	/* Compute the current epoch. */
	struct timeval now;
	if (gettimeofday(&now, NULL)) {
		kr_log_error("[tls] session ticket: gettimeofday failed, %s\n",
				strerror(errno));
		return;
	}
	uv_update_time(timer->loop); /* to have sync. between real and mono time */
	const size_t epoch = (now.tv_sec + stst->epoch_shift) / TST_KEY_LIFETIME;
	/* Update the key; new sessions will fetch it from the location.
	 * Old ones hopefully can't get broken by that; documentation
	 * for gnutls_session_ticket_enable_server() doesn't say. */
	int ret = tst_key_update(stst, epoch, force_update);
	if (ret) {
		assert(ret != kr_error(EINVAL));
		kr_log_error("[tls] session ticket: failed rotation, ret = %d\n", ret);
	}
	/* Reschedule. */
	const time_t tv_sec_next = (epoch + 1) * TST_KEY_LIFETIME - stst->epoch_shift;
	const uint64_t ms_until_second = 1000 - (now.tv_usec + 501) / 1000;
	const uint64_t remain_ms = (tv_sec_next - now.tv_sec - 1) * (uint64_t)1000
				 + ms_until_second;
	assert(remain_ms < TST_KEY_LIFETIME * 1000);
	kr_log_verbose("[tls] session ticket: scheduling rotation check in %"PRIu64" ms\n",
			remain_ms);
	ret = uv_timer_start(timer, &tst_timer_callback, remain_ms, 0);
	if (ret) {
		assert(false);
		kr_log_error("[tls] session ticket: failed to schedule, ret = %d\n", ret);
	}
}

/* Implementation for prototypes from ./tls.h */

int tls_session_ticket_enable(struct tls_session_ticket_ctx *ctx, gnutls_session_t session)
{
	assert(ctx && session);
	const gnutls_datum_t gd = {
		.size = SESSION_KEY_SIZE,
		.data = ctx->key,
	};
	return gnutls_session_ticket_enable_server(session, &gd);
}

tst_ctx_t * tls_session_ticket_ctx_create(uv_loop_t *loop, const char *salt, size_t salt_len)
{
	assert(loop && (!salt_len || salt));
	tst_ctx_t *ctx = tst_key_create(salt, salt_len, loop);
	if (ctx) {
		tst_key_check(&ctx->timer, true);
	}
	return ctx;
}

void tls_session_ticket_ctx_destroy(tst_ctx_t *ctx)
{
	if (ctx == NULL) {
		return;
	}
	uv_close((uv_handle_t *)&ctx->timer, &tst_key_destroy);
}

