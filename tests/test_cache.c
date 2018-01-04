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

#include <stdlib.h>
#include <time.h>
#include <dlfcn.h>
#include <ucw/mempool.h>

#include "tests/test.h"
#include "lib/cache.h"
#include "lib/cache/impl.h"
#include "lib/cdb_lmdb.h"



knot_mm_t global_mm;
knot_rrset_t global_rr;
const char *global_env;
struct entry_h global_fake_ce;

#define NAMEDB_INTS 256
#define NAMEDB_DATA_SIZE (NAMEDB_INTS * sizeof(int))
uint8_t namedb_data[NAMEDB_DATA_SIZE];
knot_db_val_t global_namedb_data = {namedb_data, NAMEDB_DATA_SIZE};

#define CACHE_SIZE (64 * CPU_PAGE_SIZE)
#define CACHE_TTL 10
#define CACHE_TIME 0

int (*original_knot_rdataset_gather)(knot_rdataset_t *dst, knot_rdata_t **src,
		uint16_t count, knot_mm_t *mm) = NULL;

int knot_rdataset_gather(knot_rdataset_t *dst, knot_rdata_t **src, uint16_t count,
		knot_mm_t *mm)
{
	int err, err_mock;
	err_mock = (int)mock();
	if (original_knot_rdataset_gather == NULL) {
		original_knot_rdataset_gather = dlsym(RTLD_NEXT,"knot_rdataset_gather");
		assert_non_null (original_knot_rdataset_gather);
	}	
	err = original_knot_rdataset_gather(dst, src, count, mm);
	if (err_mock != 0)
	    err = err_mock;
	return err;
}

/* Simulate init failure */
static int fake_test_init(knot_db_t **db, struct kr_cdb_opts *opts, knot_mm_t *pool)
{
	static char static_buffer[1024];
	*db = static_buffer;
	return mock();
}

static int fake_test_sync(knot_db_t *db)
{
	return 0;
}

static void fake_test_deinit(knot_db_t *db)
{
}

/* Stub for find */
static int fake_test_find(knot_db_t *db, const knot_db_val_t *key, knot_db_val_t *val,
			  int maxcount)
{
	val->data = &global_fake_ce;
	return 0;
}

/* Stub for insert */
static int fake_test_ins(knot_db_t *db, const knot_db_val_t *key, knot_db_val_t *val,
			 int maxcount)
{
	struct entry_h *header = val->data;
	int  ret, err = (int)mock();
	if (val->len == sizeof(*header) + NAMEDB_DATA_SIZE) {
		header = val->data;
		ret = memcmp(header->data,namedb_data,NAMEDB_DATA_SIZE);
		if (header->time != global_fake_ce.time || header->ttl != global_fake_ce.ttl || ret != 0) {
			err = KNOT_EINVAL;
		}
	}
	return err;
}

/* Fake api */
static const struct kr_cdb_api *fake_knot_db_lmdb_api(void)
{
	static const struct kr_cdb_api api = {
		"lmdb_fake_api",
		fake_test_init, fake_test_deinit, NULL, NULL, fake_test_sync,
		fake_test_find, fake_test_ins, NULL,
		NULL, NULL, NULL
	};

	return &api;
}

/* Test cache open */
static int test_open(void **state, const struct kr_cdb_api *api)
{
	static struct kr_cache cache;
	struct kr_cdb_opts opts = {
		global_env,
		CACHE_SIZE,
	};
	memset(&cache, 0, sizeof(cache));
	*state = &cache;
	return kr_cache_open(&cache, api, &opts, &global_mm);
}

/* fake api test open */
static void test_open_fake_api(void **state)
{
	bool res = false;
	will_return(fake_test_init, KNOT_EINVAL);
	assert_int_equal(test_open(state, fake_knot_db_lmdb_api()), KNOT_EINVAL);
	will_return(fake_test_init, 0);
	assert_int_equal(test_open(state, fake_knot_db_lmdb_api()), 0);
	res = (((struct kr_cache *)(*state))->api == fake_knot_db_lmdb_api());
	assert_true(res);
}

static void test_open_conventional_api(void **state)
{
	bool res = false;
	assert_int_equal(test_open(state, NULL),0);
	res = (((struct kr_cache *)(*state))->api == kr_cdb_lmdb());
	assert_true(res);
}


/* Test cache teardown. */
static void test_close(void **state)
{
	kr_cache_close(*state);
	*state = NULL;
}

/* test invalid parameters and some api failures */
static void test_fake_invalid (void **state)
{
	const struct kr_cdb_api *api_saved = NULL;
	knot_dname_t dname[] = "";
	struct kr_cache *cache = *state;
	struct kr_cache_p entry = {};
	int ret = 0;

	ret = kr_cache_peek_exact(cache, dname, KNOT_RRTYPE_MX, &entry);
	assert_int_equal(ret, 0);
	api_saved = cache->api;
	cache->api = NULL;
	ret = kr_cache_peek_exact(cache, dname, KNOT_RRTYPE_MX, &entry);
	cache->api = api_saved;
	assert_int_not_equal(ret, 0);
	kr_cache_sync(cache);
}

/* Test invalid parameters and some api failures. */
static void test_invalid(void **state)
{
	knot_dname_t dname[] = "";
	uint32_t timestamp = CACHE_TIME;
	struct kr_cache_p entry = {};
	struct kr_cache *cache = (*state);
	struct kr_cdb_opts opts = {
		global_env,
		CACHE_SIZE,
	};

	knot_rrset_init_empty(&global_rr);

	assert_int_equal(kr_cache_open(NULL, NULL, &opts, &global_mm),KNOT_EINVAL);
	assert_int_not_equal(kr_cache_peek_exact(NULL, dname, KNOT_RRTYPE_MX, NULL), 0);
	assert_int_not_equal(kr_cache_peek_exact(cache, NULL, KNOT_RRTYPE_MX, &entry), 0);
	assert_int_not_equal(kr_cache_clear(NULL), 0);
	kr_cache_sync(cache);
}

// FIXME?
#if 0
static void test_materialize(void **state)
{
	knot_rrset_t output_rr;
	knot_dname_t * owner_saved = global_rr.owner;
	bool res_cmp_ok_empty, res_cmp_fail_empty;
	bool res_cmp_ok, res_cmp_fail;

	global_rr.owner = NULL;
	knot_rrset_init(&output_rr, NULL, 0, 0);
	kr_cache_materialize(&output_rr, &global_rr, 0, 0, &global_mm);
	res_cmp_ok_empty = knot_rrset_equal(&global_rr, &output_rr, KNOT_RRSET_COMPARE_HEADER);
	res_cmp_fail_empty = knot_rrset_equal(&global_rr, &output_rr, KNOT_RRSET_COMPARE_WHOLE);
	knot_rrset_clear(&output_rr, &global_mm);
	global_rr.owner = owner_saved;
	assert_true(res_cmp_ok_empty);
	assert_false(res_cmp_fail_empty);

	knot_rrset_init(&output_rr, NULL, 0, 0);
	will_return (knot_rdataset_gather, 0);
	kr_cache_materialize(&output_rr, &global_rr, 0, 0, &global_mm);
	res_cmp_ok = knot_rrset_equal(&global_rr, &output_rr, KNOT_RRSET_COMPARE_WHOLE);
	knot_rrset_clear(&output_rr, &global_mm);
	assert_true(res_cmp_ok);

	knot_rrset_init(&output_rr, NULL, 0, 0);
	will_return (knot_rdataset_gather, KNOT_ENOMEM);
	kr_cache_materialize(&output_rr, &global_rr, 0, 0, &global_mm);
	res_cmp_fail = knot_rrset_equal(&global_rr, &output_rr, KNOT_RRSET_COMPARE_WHOLE);
	knot_rrset_clear(&output_rr, &global_mm);
	assert_false(res_cmp_fail);
}

/* Test cache read */
static void test_query(void **state)
{
	struct kr_cache *cache = (*state);
	knot_rrset_t cache_rr;
	knot_rrset_init(&cache_rr, global_rr.owner, global_rr.type, global_rr.rclass);

	for (uint32_t timestamp = CACHE_TIME; timestamp < CACHE_TIME + CACHE_TTL; ++timestamp) {
		uint8_t rank = 0;
		uint8_t flags = 0;
		uint32_t drift = timestamp;
		int query_ret = kr_cache_peek_exact(cache, &cache_rr, &rank, &flags, &drift);
		bool rr_equal = knot_rrset_equal(&global_rr, &cache_rr, KNOT_RRSET_COMPARE_WHOLE);
		assert_int_equal(query_ret, 0);
		assert_true(rr_equal);
	}
	kr_cache_sync(cache);
}

/* Test cache read (simulate aged entry) */
static void test_query_aged(void **state)
{
	uint8_t rank = 0;
	uint8_t flags = 0;
	uint32_t timestamp = CACHE_TIME + CACHE_TTL + 1;
	knot_rrset_t cache_rr;
	knot_rrset_init(&cache_rr, global_rr.owner, global_rr.type, global_rr.rclass);

	struct kr_cache *cache = (*state);
	int ret = kr_cache_peek_rr(cache, &cache_rr, &rank, &flags, &timestamp);
	assert_int_equal(ret, kr_error(ESTALE));
	kr_cache_sync(cache);
}
#endif

/* Test cache clear */
static void test_clear(void **state)
{
	struct kr_cache *cache = (*state);
	int preempt_ret = kr_cache_clear(cache);
	int count_ret = cache->api->count(cache->db);

	assert_int_equal(preempt_ret, 0);
	assert_int_equal(count_ret, 1); /* Version record */
}

int main(void)
{
	/* Initialize */
	test_mm_ctx_init(&global_mm);
	global_env = test_tmpdir_create();

	/* Invalid input */
	const UnitTest tests_bad[] = {
		group_test_setup(test_open_fake_api),
		unit_test(test_fake_invalid),
		group_test_teardown(test_close)
	};

	const UnitTest tests[] = {
		/* Invalid input */
	        unit_test(test_invalid),
	        /* Cache persistence */
	        group_test_setup(test_open_conventional_api),
	        //unit_test(test_materialize),
	        //unit_test(test_query),
	        /* Cache aging */
	        //unit_test(test_query_aged),
	        /* Cache fill */
	        unit_test(test_clear),
	        group_test_teardown(test_close)
	};

	int ret = run_group_tests(tests_bad);
	if (ret == 0) {
		ret = run_group_tests(tests);
	}

	/* Cleanup */
	test_tmpdir_remove(global_env);
	return ret;
}
