#include "gen.h"
#include <linux/bpf.h>
#include <linux/filter.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

struct err_summary {
	char *msg;
	size_t count;
};

size_t get_rand_map_key(struct map_info *map, int64_t *ret_key);
void sanitizer_err_msg(char **msg);
void collect_err(char *verifier_log_buff);
int compare_err_cnt(const void *b, const void *a);
void dump_err_buf();
void sigint_handler(int signum);
int bpf(int cmd, union bpf_attr *attrs);
bool load_bpf_maps(struct environ *env);
bool run_bpf_prog(struct environ *env);
