#include "loader.h"
#include "debug.h"
#include "gen.h"
#include <arpa/inet.h>
#include <assert.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <net/if.h>
#include <regex.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

static struct err_summary errors[0x400];
static struct environ *environ = NULL;
static char *pkt_buf = NULL;

size_t get_rand_map_key(struct map_info *map, int64_t *ret_key)
{
	size_t count = 0;
	void *keys = calloc(map->map->key_size, map->map->max_entries);

	if (!keys)
		_abort("failed to alloc map key buf");

	if (map->map->key_size == 8) {
		int64_t key = rand();
		while (bpf_map_get_next_key(map->fd, &key, &((int64_t *) keys)[count]) == 0) {
			key = ((int64_t *) keys)[count];
			count++;
		}

		if (ret_key && count)
			*ret_key = ((int64_t *) keys)[rand() % count];
	} else if (map->map->key_size == 4) {
		int32_t key = rand();
		while (bpf_map_get_next_key(map->fd, &key, &((int32_t *) keys)[count]) == 0) {
			key = ((int32_t *) keys)[count];
			count++;
		}

		if (ret_key && count)
			*ret_key = ((int32_t *) keys)[rand() % count];
	}

	free(keys);
	return count;
}

void sanitizer_err_msg(char **msg)
{
	char *test = strdup(*msg);
	regex_replace(&test, "R[0-9] ", "Rx ");
	regex_replace(&test, "off=(-?)[0-9]+", "off=\1X");
	regex_replace(&test, "math between ([a-z_]+) pointer and -?[0-9]{5,}", "math between \1 pointer and BIG_X");
	regex_replace(&test, "id=[0-9]+ alloc_insn=[0-9]+", "id=X alloc_insn=Y");
	regex_replace(&test, "([+-]+)[0-9]+ ", " \1X ");
	regex_replace(&test, "([+-]+)[0-9]+ ", " \1X ");
	regex_replace(&test, "-?[0-9]{5,} ", "BIG_X ");
	*msg = test;
}

void collect_err(char *verifier_log_buff)
{
	if (!strlen(verifier_log_buff))
		return;
	verifier_log_buff[strlen(verifier_log_buff) - 1] = '\0';
	char *pos = verifier_log_buff;
	char *pos_next = verifier_log_buff;
	while ((pos = strstr(pos, "\n") + 1) && (pos_next = strstr(pos + 1, "\n") + 1)) {
		if (!strstr(pos_next + 1, "\n"))
			break;
		pos += 1;
	}
	*(pos_next - 1) = '\0';

	sanitizer_err_msg(&pos);

	size_t idx;
	size_t arr_size = sizeof(errors) / sizeof(struct err_summary);
	for (idx = 0; idx < arr_size && errors[idx].msg; idx++) {
		if (!strcmp(errors[idx].msg, pos)) {
			errors[idx].count++;
			return;
		}
	}
	if (idx >= arr_size)
		_abort("error buf filled");

	errors[idx].msg = pos;
	errors[idx].count = 1;
}

int compare_err_cnt(const void *b, const void *a)
{

	struct err_summary *summaryA = (struct err_summary *) a;
	struct err_summary *summaryB = (struct err_summary *) b;

	return (summaryB->count - summaryA->count);
}

void dump_err_buf()
{
	size_t arr_size = sizeof(errors) / sizeof(struct err_summary);
	qsort(errors, arr_size, sizeof(struct err_summary), compare_err_cnt);
	fprintf(stderr, C_CLR "\n");
	for (size_t idx = 0; idx < arr_size; idx++) {
		if (errors[idx].msg)
			_warning("%zu -- %s", errors[idx].count, errors[idx].msg);
	}
}

void sigint_handler(int signum)
{
	environ->running = false;
	usleep(10000);
	dump_err_buf();
}

int bpf(int cmd, union bpf_attr *attrs)
{
	return syscall(__NR_bpf, cmd, attrs, sizeof(*attrs));
}

bool load_bpf_maps(struct environ *env)
{
	if (!env->conf->maps_len) {
		_error("no maps defined");
		return false;
	}

	env->maps = malloc(sizeof(struct map_info) * env->conf->maps_len);
	size_t loaded = 0;

	for (size_t idx = 0; idx < env->conf->maps_len; idx++) {
		int fd = -1;
		fd = bpf_create_map(env->conf->maps[idx].type, env->conf->maps[idx].key_size, env->conf->maps[idx].value_size,
							env->conf->maps[idx].max_entries, env->conf->maps[idx].map_flags);
		if (fd < 0)
			_warning("failed to load map at idx: %zu", idx);
		else {
			_log("loaded map at idx: %zu, fd: %d", idx, fd);
			env->maps[loaded].map = &env->conf->maps[idx];
			env->maps[loaded].fd = fd;
			loaded++;
		}
	}

	env->maps_len = loaded;

	if (!loaded)
		_abort("maps defined, but none loaded");

	return true;
}

bool run_bpf_prog(struct environ *env)
{
	bool ret = false;
	int prog_fd = -1;
	char verifier_log_buff[0x200000] = {0};
	int socks[2] = {0};
	environ = env;
	struct bpf_insn *insn = env->insns;
	uint32_t cnt = env->generated_insns;

	union bpf_attr prog_attrs = {.prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
								 .insn_cnt = cnt,
								 .insns = (uint64_t) insn,
								 .license = (uint64_t) "GPL",
								 .log_level = 2,
								 .log_size = sizeof(verifier_log_buff),
								 .log_buf = (uint64_t) verifier_log_buff};

	signal(SIGINT, sigint_handler);

	if (prog_fd <= 0)
		prog_fd = bpf(BPF_PROG_LOAD, &prog_attrs);

	if (prog_fd < 0) {
		if (env->conf->debug_invalid)
			_error("\n--- VERIFIER ERROR --- \n%s", verifier_log_buff);
		collect_err(verifier_log_buff);
	} else if (env->conf->debug_valid)
		_log("\n--- VERIFIER LOG --- \n%s", verifier_log_buff);

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, socks))
		goto done;

	if (setsockopt(socks[0], SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(int)))
		goto done;

	if (!pkt_buf)
		pkt_buf = malloc(env->conf->pkt_len);

	for (size_t i = 0; i < env->conf->pkt_len; i++)
		pkt_buf[i] = (uint8_t) rand();

	if (write(socks[1], pkt_buf, env->conf->pkt_len) != env->conf->pkt_len)
		goto done;

	close(prog_fd);

	ret = true;

done:
	close(socks[0]);
	close(socks[1]);
	return ret;
}
