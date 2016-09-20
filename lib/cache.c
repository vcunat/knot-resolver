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
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include <libknot/errcode.h>
#include <libknot/descriptor.h>
#include <libknot/dname.h>
#include <libknot/rrtype/rrsig.h>

#include "contrib/cleanup.h"
#include "lib/cache.h"
#include "lib/client_subnet.h"
#include "lib/cdb_lmdb.h"
#include "lib/defines.h"
#include "lib/utils.h"

/** Cache version */
#define KEY_VERSION "V\x03"
/** An upper bound on the cache key length; see cache_key() */
#define KEY_SIZE (KNOT_DNAME_MAXLEN + 3 * sizeof(uint8_t) + 2 * sizeof(uint16_t))

/* Shorthand for operations on cache backend */
#define cache_isvalid(cache) ((cache) && (cache)->api && (cache)->db)
#define cache_op(cache, op, ...) (cache)->api->op((cache)->db, ## __VA_ARGS__)


/* Memory-mapped cache entries. See struct kr_cache_entry for field meanings. */

typedef struct mmentry_normal {
	uint32_t timestamp;
	uint32_t ttl;
	uint8_t  rank;
	uint8_t  flags;
	uint8_t  data[];
} mmentry_normal_t;

typedef struct mmentry_short {
	uint32_t timestamp;
	uint32_t ttl;
	uint16_t hash; /*!< Hash of contents of the rest of mmentry_normal_t. */
} mmentry_short_t;


/** @internal Removes all records from cache. */
static inline int cache_purge(struct kr_cache *cache)
{
	cache->stats.delete += 1;
	return cache_op(cache, clear);
}

/** @internal Open cache db transaction and check internal data version. */
static int assert_right_version(struct kr_cache *cache)
{
	/* Check cache ABI version */
	knot_db_val_t key = { KEY_VERSION, 2 };
	knot_db_val_t val = { KEY_VERSION, 2 };
	int ret = cache_op(cache, read, &key, &val, 1);
	if (ret == 0) {
		ret = kr_error(EEXIST);
	} else {
		/* Version doesn't match. Recreate cache and write version key. */
		ret = cache_op(cache, count);
		if (ret != 0) { /* Non-empty cache, purge it. */
			kr_log_info("[cache] purging cache\n");
			ret = cache_purge(cache);
		}
		/* Either purged or empty. */
		if (ret == 0) {
			/* Key/Val is invalidated by cache purge, recreate it */
			key.data = KEY_VERSION;
			key.len = 2;
			val = key;
			ret = cache_op(cache, write, &key, &val, 1);
		}
	}
	kr_cache_sync(cache);
	return ret;
}

int kr_cache_open(struct kr_cache *cache, const struct kr_cdb_api *api, struct kr_cdb_opts *opts, knot_mm_t *mm)
{
	if (!cache) {
		return kr_error(EINVAL);
	}
	/* Open cache */
	if (!api) {
		api = kr_cdb_lmdb();
	}
	cache->api = api;
	int ret = cache->api->open(&cache->db, opts, mm);
	if (ret != 0) {
		return ret;
	}
	memset(&cache->stats, 0, sizeof(cache->stats));
	/* Check cache ABI version */
	(void) assert_right_version(cache);
	return 0;
}

void kr_cache_close(struct kr_cache *cache)
{
	if (cache_isvalid(cache)) {
		cache_op(cache, close);
		cache->db = NULL;
	}
}

void kr_cache_sync(struct kr_cache *cache)
{
	if (cache_isvalid(cache) && cache->api->sync) {
		cache_op(cache, sync);
	}
}

/**
 * @internal Composed key as { u8 tag, u8[1-255] name, u16 type,
 * either (u8[0-2] location) or (u8 '\0' and u16 hash) }
 * The name is lowercased and label order is reverted for easy prefix search.
 * e.g. '\x03nic\x02cz\x00' is saved as 'cz\x00nic\x00'
 */
static size_t cache_key(uint8_t *buf, uint8_t tag, const knot_dname_t *name,
			uint16_t rrtype, struct kr_client_subnet *ecs, int32_t ecs_lkey)
{
	/* Convert to lookup format */
	int ret = knot_dname_lf(buf, name, NULL);
	if (ret != 0) {
		return 0;
	}
	/* Write tag + type */
	uint8_t name_len = buf[0];
	buf[0] = tag;
	uint8_t *buf_now = buf + sizeof(uint8_t) + name_len;
	memcpy(buf_now, &rrtype, sizeof(uint16_t));
	buf_now += sizeof(uint16_t);
	if (ecs != NULL && ecs_lkey < 0) {
		memcpy(buf_now, ecs->loc, ecs->loc_len);
		buf_now += ecs->loc_len;
	}
	if (ecs_lkey >= 0) {
		uint16_t lkey = ecs_lkey;
		assert(lkey == ecs_lkey);
		*(buf_now++) = '\0';
		memcpy(buf_now, &lkey, sizeof(lkey));
		buf_now += sizeof(lkey);
	}
	assert(buf_now - buf <= KEY_SIZE);
	return buf_now - buf;
}


/** @internal Verify entry against a timestamp and replace timestamp by drift if OK;
	uint32_t time_now = *timestamp;
 *   return ESTALE otherwise. */
static int check_lifetime(mmentry_short_t *found, uint32_t *timestamp)
{
	if (!timestamp) {
		/* No time constraint. */
		return kr_ok();
	} else if (*timestamp <= found->timestamp) {
		/* John Connor record cached in the future. */
		*timestamp = 0;
		return kr_ok();
	} else {
		/* Check if the record is still valid. */
		uint32_t drift = *timestamp - found->timestamp;
		if (drift <= found->ttl) {
			*timestamp = drift;
			return kr_ok();
		}
	}
	return kr_error(ESTALE);
}

/** @internal Find a cache entry or eturn error code.
 *   It includes timestamp checking, ECS handling, etc. */
static int lookup(struct kr_cache *cache, uint8_t tag, const knot_dname_t *name,
	uint16_t type, struct kr_client_subnet *ecs, uint32_t *timestamp,
	struct kr_cache_entry *entry)
{
	bool precond = name && cache && entry && (!ecs || ecs->loc_len > 0);
	if (!precond) {
		assert(false);
		return kr_error(EINVAL);
	}

	/* Prepare lookup and return value. */
	uint8_t keybuf[KEY_SIZE];
	knot_db_val_t key = {
		.data = keybuf,
		.len = cache_key(keybuf, tag, name, type, ecs, -1),
	};
	knot_db_val_t val = { NULL, 0 };

	int ret = cache_op(cache, read, &key, &val, 1);

	bool require_scope0 = false;
	if (ecs == NULL) {
	retry_without_ecs:
		/* The non-ECS format is used. */
		if (ret != 0) {
			return kr_error(ENOENT);
		}
		if (val.len <= sizeof(mmentry_normal_t)) {
			return kr_error(EILSEQ);
		}
		mmentry_normal_t *mme = val.data;
		
		if (require_scope0 && !(mme->flags & KR_CACHE_FLAG_ECS_SCOPE0)) {
			return kr_error(ENOENT);
		}

		/* Only time can stop us now. */
		ret = check_lifetime((mmentry_short_t *)mme, timestamp);
		if (ret) {
			return ret;
		}
		/* Deserialize *mme. */
		*entry = (struct kr_cache_entry){
			.timestamp	= mme->timestamp,
			.ttl		= mme->ttl,
			.count		= val.len - sizeof(mmentry_normal_t),
			.rank		= mme->rank,
			.flags		= mme->flags,
			.data		= mme->data
		};
		return kr_ok();
	}
	/* We want ECS from now on. */

	if (ret == 0 && val.len != sizeof(mmentry_short_t)) {
		/* Bogus size found; continue as if not found, unless debugging. */
		assert(false);
		ret = kr_error(ENOENT);
	}
	mmentry_short_t *mmes = val.data;
	uint32_t timestamp_orig = timestamp ? *timestamp : -1;
	if (!ret) {
		ret = check_lifetime(mmes, timestamp);
	}
	if (!ret) {
		/* We have an OK short entry and timestamp has been updated already.
		 * Let's try to find the rest of the entry. */
		key.len = cache_key(keybuf, tag, name, type, ecs, mmes->hash);
		ret = cache_op(cache, read, &key, &val, 1);
	}

	if (ret || val.len <= 2 ) {
		assert(ret);
		/* The search failed, at some point,
		 * but we may still use the scope0 entry, if it exists. */
		key.len = cache_key(keybuf, tag, name, type, NULL, -1);
		ret = cache_op(cache, read, &key, &val, 1);
		require_scope0 = true;
		if (timestamp) { /* To be sure; maybe we haven't changed it. */
			*timestamp = timestamp_orig;
		}
		goto retry_without_ecs;
	}
	
	/* The rest of entry is OK, so fill the output. */
	uint8_t *val_data = val.data; /* not perfect approach with this variable */
	*entry = (struct kr_cache_entry){
		.timestamp	= mmes->timestamp,
		.ttl		= mmes->ttl,
		.count		= val.len - 2,
		.rank		= val_data[0],
		.flags		= val_data[1],
		.data		= val_data + 2
	};
	return kr_ok();
}

int kr_cache_peek(struct kr_cache *cache, uint8_t tag, const knot_dname_t *name,
		  uint16_t type, struct kr_client_subnet *ecs, uint32_t *timestamp,
		  struct kr_cache_entry *entry)
{
	bool precond = cache_isvalid(cache) && name && entry;
	if (!precond) {
		assert(false);
		return kr_error(EINVAL);
	}

	int err = lookup(cache, tag, name, type, ecs, timestamp, entry);
	if (!err) {
		cache->stats.hit += 1;
	}
       	if (err == kr_error(ENOENT) || err == kr_error(ESTALE)) {
		cache->stats.miss += 1;
	}
	return err;
}

int kr_cache_peek_rank(struct kr_cache *cache, uint8_t tag, const knot_dname_t *name,
			uint16_t type, struct kr_client_subnet *ecs, uint32_t timestamp)
{
	bool precond = cache_isvalid(cache) && name;
	if (!precond) {
		assert(false);
		return kr_error(EINVAL);
	}

	struct kr_cache_entry e;
	int err = lookup(cache, tag, name, type, ecs, &timestamp, &e);
	return err ? err : e.rank;
}


static void entry_write(struct kr_cache_entry *dst, struct kr_cache_entry *header, knot_db_val_t data)
{
	BARF;

	memcpy(dst, header, sizeof(*header));
	if (data.data)
		memcpy(dst->data, data.data, data.len);
}

int kr_cache_insert(struct kr_cache *cache, uint8_t tag, const knot_dname_t *name, uint16_t type,
                    struct kr_cache_entry *header, knot_db_val_t data)
{
	if (!cache_isvalid(cache) || !name || !header) {
		return kr_error(EINVAL);
	}

	/* Prepare key/value for insertion. */
	uint8_t keybuf[KEY_SIZE];
	size_t key_len = cache_key(keybuf, tag, name, type);
	if (key_len == 0) {
		return kr_error(EILSEQ);
	}
	assert(data.len != 0);
	knot_db_val_t key = { keybuf, key_len };
	knot_db_val_t entry = { NULL, sizeof(*header) + data.len };

	/* LMDB can do late write and avoid copy */
	int ret = 0;
	cache->stats.insert += 1;
	if (cache->api == kr_cdb_lmdb()) {
		ret = cache_op(cache, write, &key, &entry, 1);
		if (ret != 0) {
			return ret;
		}
		entry_write(entry.data, header, data);
		ret = cache_op(cache, sync); /* Make sure the entry is comitted. */
	} else {
		/* Other backends must prepare contiguous data first */
		auto_free char *buffer = malloc(entry.len);
		entry.data = buffer;
		entry_write(entry.data, header, data);
		ret = cache_op(cache, write, &key, &entry, 1);
	}

	return ret;
}

int kr_cache_remove(struct kr_cache *cache, uint8_t tag, const knot_dname_t *name, uint16_t type)
{
	if (!cache_isvalid(cache) || !name ) {
		return kr_error(EINVAL);
	}

	uint8_t keybuf[KEY_SIZE];
	size_t key_len = cache_key(keybuf, tag, name, type);
	if (key_len == 0) {
		return kr_error(EILSEQ);
	}ret
	knot_db_val_t key = { keybuf, key_len };
	cache->stats.delete += 1;
	return cache_op(cache, remove, &key, 1);
}

int kr_cache_clear(struct kr_cache *cache)
{
	if (!cache_isvalid(cache)) {
		return kr_error(EINVAL);
	}
	int ret = cache_purge(cache);
	if (ret == 0) {
		ret = assert_right_version(cache);
	}
	return ret;
}

int kr_cache_match(struct kr_cache *cache, uint8_t tag, const knot_dname_t *name, knot_db_val_t *val, int maxcount)
{
	if (!cache_isvalid(cache) || !name ) {
		return kr_error(EINVAL);
	}
	if (!cache->api->match) {
		return kr_error(ENOSYS);
	}

	uint8_t keybuf[KEY_SIZE];
	size_t key_len = cache_key(keybuf, tag, name, 0);
	if (key_len == 0) {
		return kr_error(EILSEQ);
	}

	/* Trim type from the search key */ 
	knot_db_val_t key = { keybuf, key_len - 2 };
	return cache_op(cache, match, &key, val, maxcount);
}

int kr_cache_peek_rr(struct kr_cache *cache, knot_rrset_t *rr, uint8_t *rank,
		     uint8_t *flags, uint32_t *timestamp, struct kr_client_subnet *ecs)
{
	if (!cache_isvalid(cache) || !rr || !timestamp) {
		return kr_error(EINVAL);
	}

	/* Check if the RRSet is in the cache. */
	struct kr_cache_entry *entry = NULL;
	int ret = kr_cache_peek(cache, KR_CACHE_RR, rr->owner, rr->type,
				&entry, timestamp, ecs);
	if (ret != 0) {
		return ret;
	}
	if (rank) {
		*rank = entry->rank;
	}
	if (flags) {
		*flags = entry->flags;
	}
	rr->rrs.rr_count = entry->count;
	rr->rrs.data = entry->data;
	return kr_ok();
}


int kr_cache_materialize(knot_rrset_t *dst, const knot_rrset_t *src, uint32_t drift, knot_mm_t *mm)
{
	if (!dst || !src || dst == src) {
		return kr_error(EINVAL);
	}

	/* Make RRSet copy */
	knot_rrset_init(dst, NULL, src->type, src->rclass);
	dst->owner = knot_dname_copy(src->owner, mm);
	if (!dst->owner) {
		return kr_error(ENOMEM);
	}

	/* Copy valid records */
	knot_rdata_t *rd = src->rrs.data;
	for (uint16_t i = 0; i < src->rrs.rr_count; ++i) {
		if (knot_rdata_ttl(rd) >= drift) {
			if (knot_rdataset_add(&dst->rrs, rd, mm) != 0) {
				knot_rrset_clear(dst, mm);
				return kr_error(ENOMEM);
			}
		}
		rd = kr_rdataset_next(rd);
	}
	/* Fixup TTL by time passed */
	rd = dst->rrs.data;
	for (uint16_t i = 0; i < dst->rrs.rr_count; ++i) {
		knot_rdata_set_ttl(rd, knot_rdata_ttl(rd) - drift);
		rd = kr_rdataset_next(rd);
	}

	return kr_ok();
}

int kr_cache_insert_rr(struct kr_cache *cache, const knot_rrset_t *rr, uint8_t rank, uint8_t flags, uint32_t timestamp)
{
	if (!cache_isvalid(cache) || !rr) {
		return kr_error(EINVAL);
	}

	/* Ignore empty records */
	if (knot_rrset_empty(rr)) {
		return kr_ok();
	}

	/* Prepare header to write */
	struct kr_cache_entry header = {
		.timestamp = timestamp,
		.ttl = 0,
		.rank = rank,
		.flags = flags,
		.count = rr->rrs.rr_count
	};
	knot_rdata_t *rd = rr->rrs.data;
	for (uint16_t i = 0; i < rr->rrs.rr_count; ++i) {
		if (knot_rdata_ttl(rd) > header.ttl) {
			header.ttl = knot_rdata_ttl(rd);
		}
		rd = kr_rdataset_next(rd);
	}

	knot_db_val_t data = { rr->rrs.data, knot_rdataset_size(&rr->rrs) };
	return kr_cache_insert(cache, KR_CACHE_RR, rr->owner, rr->type, &header, data);
}

int kr_cache_peek_rrsig(struct kr_cache *cache, knot_rrset_t *rr, uint8_t *rank, uint8_t *flags, uint32_t *timestamp)
{
	if (!cache_isvalid(cache) || !rr || !timestamp) {
		return kr_error(EINVAL);
	}

	/* Check if the RRSet is in the cache. */
	struct kr_cache_entry *entry = NULL;
	int ret = kr_cache_peek(cache, KR_CACHE_SIG, rr->owner, rr->type, &entry, timestamp);
	if (ret != 0) {
		return ret;
	}
	assert(entry);
	if (rank) {
		*rank = entry->rank;
	}
	if (flags) {
		*flags = entry->flags;
	}
	rr->type = KNOT_RRTYPE_RRSIG;
	rr->rrs.rr_count = entry->count;
	rr->rrs.data = entry->data;
	return kr_ok();
}

int kr_cache_insert_rrsig(struct kr_cache *cache, const knot_rrset_t *rr, uint8_t rank, uint8_t flags, uint32_t timestamp)
{
	if (!cache_isvalid(cache) || !rr) {
		return kr_error(EINVAL);
	}

	/* Ignore empty records */
	if (knot_rrset_empty(rr)) {
		return kr_ok();
	}

	/* Prepare header to write */
	struct kr_cache_entry header = {
		.timestamp = timestamp,
		.ttl = 0,
		.rank = rank,
		.flags = flags,
		.count = rr->rrs.rr_count
	};
	for (uint16_t i = 0; i < rr->rrs.rr_count; ++i) {
		knot_rdata_t *rd = knot_rdataset_at(&rr->rrs, i);
		if (knot_rdata_ttl(rd) > header.ttl) {
			header.ttl = knot_rdata_ttl(rd);
		}
	}

	uint16_t covered = knot_rrsig_type_covered(&rr->rrs, 0);
	knot_db_val_t data = { rr->rrs.data, knot_rdataset_size(&rr->rrs) };
	return kr_cache_insert(cache, KR_CACHE_SIG, rr->owner, covered, &header, data);
}
