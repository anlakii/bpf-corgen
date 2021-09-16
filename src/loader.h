#include <linux/filter.h>
#include <linux/bpf.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include "gen.h"

struct err_summary {
	char *msg;
	size_t count;
};

size_t get_rand_map_key(struct map_info *map, int64_t *ret_key);
void dump_err_buf();
bool run_bpf_prog(struct environ *env);
bool load_bpf_maps(struct environ *env);
