
#include <math.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/time.h>
#include <unistd.h>

#include "contrib/ucw/lib.h"
#include "lib/nsrep.h"
#include "daemon/engine.h"

typedef kr_nsrep_lru_t lru_bench_t;


static int die(const char *cause)
{
	fprintf(stderr, "%s: %s\n", cause, strerror(errno));
	exit(1);
}

static void time_get(struct timeval *tv)
{
	if (gettimeofday(tv, NULL))
		die("gettimeofday");
}
static void time_print_diff(struct timeval *tv, size_t op_count)
{
	struct timeval now;
	time_get(&now);
	now.tv_sec -= tv->tv_sec;
	now.tv_usec -= tv->tv_usec;
	if (now.tv_usec < 0) {
		now.tv_sec -= 1;
		now.tv_usec += 1000000;
	}

	size_t speed = round((double)(op_count) / 1000
		/ (now.tv_sec + (double)(now.tv_usec)/1000000));
	printf("\t%ld.%06d s, \t %zd kop/s\n", now.tv_sec, (int)now.tv_usec, speed);
}

/// initialize seed for random()
static int ssrandom(char *s)
{
	if (*s == '-') { // initialize from time
		struct timeval now;
		time_get(&now);
		srandom(now.tv_sec * 1000000 + now.tv_usec);
		return 0;
	}

	// initialize from a string
	size_t len = strlen(s);
	if (len < 12)
		return(-1);
	unsigned seed = s[0] | s[1] << 8 | s[2] << 16 | s[3] << 24;
	initstate(seed, s+4, len-4);
	return 0;
}

struct key {
	size_t len;
	char *chars;
};

/// read lines from a file and reorder them randomly
static struct key * read_lines(const char *fname, size_t *count, char **pfree)
{
	// read the file at once
	int fd = open(fname, O_RDONLY);
	if (fd < 0)
		die("open");
	struct stat st;
	if (fstat(fd, &st) < 0)
		die("stat");
	size_t flen = (size_t)st.st_size;
	char *fbuf = malloc(flen + 1);
	*pfree = fbuf;
	if (fbuf == NULL)
		die("malloc");
	if (read(fd, fbuf, flen) < 0)
		die("read");
	close(fd);
	fbuf[flen] = '\0';
	
	// get pointers to individual lines
	size_t lines = 0;
	for (size_t i = 0; i < flen; ++i)
		if (fbuf[i] == '\n') {
			fbuf[i] = 0;
			++lines;
		}
	*count = lines;
	size_t avg_len = (flen + 1) / lines - 1;
	printf("%zu lines read, average length %zu\n", lines, avg_len);

	struct key *result = calloc(lines, sizeof(struct key));
	result[0].chars = fbuf;
	for (size_t l = 0; l < lines; ++l) {
		size_t i = 0;
		while (result[l].chars[i])
			++i;
		result[l].len = i;
		if (l + 1 < lines)
			result[l + 1].chars = result[l].chars + i + 1;
	}

	//return result;
	// reorder the lines randomly (via "random select-sort")
	// note: this makes their order non-sequential *in memory*
	if (RAND_MAX < lines)
		die("RAND_MAX is too small");
	for (size_t i = 0; i < lines - 1; ++i) { // swap i with random j >= i
		size_t j = i + random() % (lines - i);
		if (j != i) {
			struct key tmp = result[i];
			result[i] = result[j];
			result[j] = tmp;
		}
	}

	return result;
}

// compatibility layer for the oler lru_* names; it's more compler with lru_create
#ifndef lru_create
	#define lru_get_new lru_set
	#define lru_get_try lru_get
#endif

static void usage(const char *progname)
{
	fprintf(stderr, "usage: %s <log_count> <input> <seed> [lru_size]\n"
		"The seed must be at least 12 characters or \"-\".\n" , progname);
	exit(1);
}

int main(int argc, char ** argv)
{
	if (argc != 4 && argc != 5)
		usage(argv[0]);
	if (ssrandom(argv[3]) < 0)
		usage(argv[0]);

	size_t key_count;
	char *data_to_free = NULL;
	struct key *keys = read_lines(argv[2], &key_count, &data_to_free);
	size_t run_count;
	{
		size_t run_log = atoi(argv[1]);
		assert(run_log < 64);
		run_count = 1ULL << run_log;
		printf("test run length: 2^%zd\n", run_log);
	}

	struct timeval time;
	const int lru_size = argc > 4 ? atoi(argv[4]) : LRU_RTT_SIZE;

	lru_bench_t *lru;
	#ifdef lru_create
		lru_create(&lru, lru_size, NULL);
	#else
		lru = malloc(lru_size(lru_bench_t, lru_size));
		if (lru)
			lru_init(lru, lru_size);
	#endif
	if (!lru)
		die("malloc");
	printf("LRU size:\t%d\n", lru_size);

	size_t miss = 0;
	printf("load everything:");
	time_get(&time);
	for (size_t i = 0, ki = key_count - 1; i < run_count; ++i, --ki) {
		unsigned *r = lru_get_new(lru, keys[ki].chars, keys[ki].len);
		if (!r || *r == 0)
			++miss;
		if (r)
			*r = 1;
		if (unlikely(ki == 0))
			ki = key_count;
	}
	time_print_diff(&time, run_count);
	printf("LRU misses:\t%zd%%\n", (miss * 100 + 50) / run_count);

	unsigned accum = 0; // compute something to make sure compiler can't remove code
	printf("search everything:");
	time_get(&time);
	for (size_t i = 0, ki = key_count - 1; i < run_count; ++i, --ki) {
		unsigned *r = lru_get_try(lru, keys[ki].chars, keys[ki].len);
		if (r)
			accum += *r;
		if (unlikely(ki == 0))
			ki = key_count;
	}
	time_print_diff(&time, run_count);
	printf("ignore: %u\n", accum);

	// free memory, at least with new LRU
	#ifdef lru_create
		lru_free(lru);
	#endif
	free(keys);
	free(data_to_free);

	return 0;
}

