#ifndef __GEN_H
#define __GEN_H 1

#include <linux/bpf.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "helpers.h"
#include "bpf_insn.h"
#include "config.h"

#define INSN_STR_LEN 50
#define MAP_FD_REG_IDX 1
#define MAX_BPF_STACK 512
#define BPF_REG_SIZE 8

enum bpf_reg_type {
	NOT_INIT = 0,
	SCALAR_VALUE,
	PTR_TO_CTX,
	CONST_PTR_TO_MAP,
	PTR_TO_MAP_VALUE,
	PTR_TO_MAP_VALUE_OR_NULL,
	PTR_TO_STACK,
	PTR_TO_MEM,
	PTR_TO_MEM_OR_NULL,
	__BPF_REG_TYPE_MAX,
};

enum bpf_stack_slot_type {
	STACK_INVALID,
	STACK_SPILL,
	STACK_MISC,
	STACK_ZERO,
};

struct bpf_stack_state {
	uint8_t slot_type[BPF_REG_SIZE];
};

struct bpf_reg {
	uint8_t idx;
	bool enable;
	bool mutable;
	uint8_t reg_type;
	bool is_known;

	struct bpf_map_def *map;
};

struct map_ops {
	size_t update_elem;
	size_t lookup_elem;
	size_t delete_elem;
};

struct map_info {
	struct bpf_map_def *map;
	struct map_ops ops;
	struct map_ops ops_enabled;
	int fd;
};

struct environ {
	size_t generated_insns;
	int64_t total_insns;

	struct map_info *maps;
	size_t maps_len;

	struct bpf_reg regs[11];
	char *insns_str;
	struct bpf_insn *insns;
	struct bpf_stack_state stack[MAX_BPF_STACK / 8];

	bool running;
	bool privileged;
	struct config *conf;
};

struct map_info *get_map_from_fd(struct environ *env, int map_fd);
size_t get_rand_op(struct environ *env);
size_t get_rand_op_ptr(struct environ *env);
struct bpf_reg *get_rand_reg(struct environ *env, ...);
bool is_arithmetic_allowed(struct environ *env, struct bpf_reg *dst, struct bpf_reg *src, uint8_t op);
bool should_min_bound(struct environ *env, struct bpf_reg *reg);
uint8_t get_count_ptr_reg_init_mutable(struct environ *env);
uint8_t get_reg_mutable_count_of_type(struct environ *env, uint8_t type);
bool generate_rand_bind(struct environ *env);
bool generate_rand_alu_reg(struct environ *env);
bool generate_rand_alu_imm(struct environ *env);
bool generate_rand_alu(struct environ *env);
bool generate_rand_mov_reg(struct environ *env);
bool generate_rand_mov_imm(struct environ *env);
bool generate_rand_ld_imm64(struct environ *env);
bool generate_rand_mem_ld(struct environ *env);
bool generate_rand_mov(struct environ *env);
bool generate_rand_map_op(struct environ *env);
bool prep_bpf_map_load(struct environ *env, int map_fd);
bool prep_map_lookup_elem(struct environ *env, int map_fd);
bool prep_map_update_elem(struct environ *env, int map_fd);
bool generate_rand_ptr_stx(struct environ *env);
bool generate_rand_reg_spill(struct environ *env);
bool generate_rand_helper_call(struct environ *env);
bool generate_rand_zext_reg(struct environ *env);
bool gen_map_atomic_op(struct environ *env);
bool prep_rand_map_op(struct environ *env, int map_fd);
int generate(struct environ *env);
void prepare_prog_header(struct environ *env);
void setup(struct environ *env);

#endif
