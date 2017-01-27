--[[ This file is generated by ./kres-gen.sh ]] ffi.cdef[[

typedef struct knot_dump_style knot_dump_style_t;
extern const knot_dump_style_t KNOT_DUMP_STYLE_DEFAULT;

typedef struct knot_mm {
	void *ctx, *alloc, *free;
} knot_mm_t;

typedef void *(*map_alloc_f)(void *, size_t);
typedef void (*map_free_f)(void *baton, void *ptr);
typedef enum {KNOT_ANSWER, KNOT_AUTHORITY, KNOT_ADDITIONAL} knot_section_t;
typedef struct {
    uint16_t pos;
    uint16_t flags;
    uint16_t compress_ptr[16];
} knot_rrinfo_t;
typedef unsigned char knot_dname_t;
typedef unsigned char knot_rdata_t;
typedef struct knot_rdataset knot_rdataset_t;
struct knot_rdataset {
    uint16_t rr_count;
    knot_rdata_t *data;
};
typedef struct knot_rrset knot_rrset_t;
typedef struct {
    struct knot_pkt *pkt;
    uint16_t pos;
    uint16_t count;
} knot_pktsection_t;
struct knot_pkt {
    uint8_t *wire;
    size_t size;
    size_t max_size;
    size_t parsed;
    uint16_t reserved;
    uint16_t qname_size;
    uint16_t rrset_count;
    uint16_t flags;
    knot_rrset_t *opt_rr;
    knot_rrset_t *tsig_rr;
    struct {
        uint8_t *pos;
        size_t len;
    } tsig_wire;
    knot_section_t current;
    knot_pktsection_t sections[3];
    size_t rrset_allocd;
    knot_rrinfo_t *rr_info;
    knot_rrset_t *rr;
    knot_mm_t mm;
};
typedef struct knot_pkt knot_pkt_t;
typedef struct {
    void *root;
    map_alloc_f malloc;
    map_free_f free;
    void *baton;
} map_t;
typedef struct {
    knot_rrset_t **at;
    size_t len;
    size_t cap;
} rr_array_t;
struct ranked_rr_array_entry {
    uint32_t qry_uid;
    uint8_t rank;
    uint8_t revalidation_cnt;
    _Bool cached;
    _Bool yielded;
    _Bool to_wire;
    knot_rrset_t *rr;
};
typedef struct ranked_rr_array_entry ranked_rr_array_entry_t;
typedef struct {
    ranked_rr_array_entry_t **at;
    size_t len;
    size_t cap;
} ranked_rr_array_t;
struct kr_zonecut {
    knot_dname_t *name;
    knot_rrset_t *key;
    knot_rrset_t *trust_anchor;
    struct kr_zonecut *parent;
    map_t nsset;
    knot_mm_t *pool;
};
typedef struct {
    struct kr_query **at;
    size_t len;
    size_t cap;
} kr_qarray_t;
struct kr_rplan {
    kr_qarray_t pending;
    kr_qarray_t resolved;
    struct kr_request *request;
    knot_mm_t *pool;
    uint32_t next_uid;
};
struct kr_request {
    struct kr_context *ctx;
    knot_pkt_t *answer;
    struct kr_query *current_query;
    struct {
        const knot_rrset_t *key;
        const struct sockaddr *addr;
        const struct sockaddr *dst_addr;
        const knot_pkt_t *packet;
        const knot_rrset_t *opt;
    } qsource;
    struct {
        unsigned int rtt;
        const struct sockaddr *addr;
    } upstream;
    uint32_t options;
    int state;
    ranked_rr_array_t answ_selected;
    ranked_rr_array_t auth_selected;
    rr_array_t additional;
    _Bool answ_validated;
    _Bool auth_validated;
    struct kr_rplan rplan;
    int has_tls;
    knot_mm_t pool;
};
struct knot_rrset {
    knot_dname_t *_owner;
    uint16_t type;
    uint16_t rclass;
    knot_rdataset_t rrs;
    void *additional;
};
struct kr_query {
    struct kr_query *parent;
    knot_dname_t *sname;
    uint16_t stype;
    uint16_t sclass;
    uint16_t id;
    uint32_t flags;
    uint32_t secret;
    uint16_t fails;
    uint16_t reorder;
    struct timeval timestamp;
    struct kr_zonecut zone_cut;
	char _stub[];
};
struct kr_context {
    uint32_t options;
    knot_rrset_t *opt_rr;
    map_t trust_anchors;
    map_t negative_anchors;
    struct kr_zonecut root_hints;
	char _stub[];
};
struct query_flag {static const int NO_MINIMIZE = 1; static const int NO_THROTTLE = 2; static const int NO_IPV6 = 4; static const int NO_IPV4 = 8; static const int TCP = 16; static const int RESOLVED = 32; static const int AWAIT_IPV4 = 64; static const int AWAIT_IPV6 = 128; static const int AWAIT_CUT = 256; static const int SAFEMODE = 512; static const int CACHED = 1024; static const int NO_CACHE = 2048; static const int EXPIRING = 4096; static const int ALLOW_LOCAL = 8192; static const int DNSSEC_WANT = 16384; static const int DNSSEC_BOGUS = 32768; static const int DNSSEC_INSECURE = 65536; static const int STUB = 131072; static const int ALWAYS_CUT = 262144; static const int DNSSEC_WEXPAND = 524288; static const int PERMISSIVE = 1048576; static const int STRICT = 2097152; static const int BADCOOKIE_AGAIN = 4194304; static const int CNAME = 8388608; static const int REORDER_RR = 16777216; static const int TRACE = 33554432;};
int knot_dname_size(const knot_dname_t *);
knot_dname_t *knot_dname_from_str(uint8_t *, const char *, size_t);
char *knot_dname_to_str(char *, const knot_dname_t *, size_t);
uint16_t knot_rdata_rdlen(const knot_rdata_t *);
uint8_t *knot_rdata_data(const knot_rdata_t *);
knot_rdata_t *knot_rdataset_at(const knot_rdataset_t *, size_t);
uint32_t knot_rrset_ttl(const knot_rrset_t *);
int knot_rrset_txt_dump_data(const knot_rrset_t *, const size_t, char *, const size_t, const knot_dump_style_t *);
int knot_rrset_txt_dump(const knot_rrset_t *, char **, size_t *, const knot_dump_style_t *);
const knot_dname_t *knot_pkt_qname(const knot_pkt_t *);
uint16_t knot_pkt_qtype(const knot_pkt_t *);
uint16_t knot_pkt_qclass(const knot_pkt_t *);
int knot_pkt_begin(knot_pkt_t *, knot_section_t);
int knot_pkt_put_question(knot_pkt_t *, const knot_dname_t *, uint16_t, uint16_t);
const knot_rrset_t *knot_pkt_rr(const knot_pktsection_t *, uint16_t);
const knot_pktsection_t *knot_pkt_section(const knot_pkt_t *, knot_section_t);
struct kr_rplan *kr_resolve_plan(struct kr_request *);
knot_mm_t *kr_resolve_pool(struct kr_request *);
struct kr_query *kr_rplan_push(struct kr_rplan *, struct kr_query *, const knot_dname_t *, uint16_t, uint16_t);
int kr_rplan_pop(struct kr_rplan *, struct kr_query *);
struct kr_query *kr_rplan_resolved(struct kr_rplan *);
int kr_nsrep_set(struct kr_query *, size_t, uint8_t *, size_t, int);
unsigned int kr_rand_uint(unsigned int);
int kr_pkt_put(knot_pkt_t *, const knot_dname_t *, uint32_t, uint16_t, uint16_t, const uint8_t *, uint16_t);
int kr_pkt_recycle(knot_pkt_t *);
const char *kr_inaddr(const struct sockaddr *);
int kr_inaddr_family(const struct sockaddr *);
int kr_inaddr_len(const struct sockaddr *);
int kr_straddr_family(const char *);
int kr_straddr_subnet(void *, const char *);
int kr_bitcmp(const char *, const char *, int);
int kr_family_len(int);
int kr_rrarray_add(rr_array_t *, const knot_rrset_t *, knot_mm_t *);
knot_rrset_t *kr_ta_get(map_t *, const knot_dname_t *);
int kr_ta_add(map_t *, const knot_dname_t *, uint16_t, uint32_t, const uint8_t *, uint16_t);
int kr_ta_del(map_t *, const knot_dname_t *);
void kr_ta_clear(map_t *);
_Bool kr_dnssec_key_ksk(const uint8_t *);
_Bool kr_dnssec_key_revoked(const uint8_t *);
int kr_dnssec_key_tag(uint16_t, const uint8_t *, size_t);
int kr_dnssec_key_match(const uint8_t *, size_t, const uint8_t *, size_t);
]]
