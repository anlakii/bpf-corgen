#ifndef __GEN_H
#define __GEN_H 1

#include "bpf_insn.h"
#include "config.h"
#include "helpers.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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
	uint32_t mem_range;

	struct bpf_map_def *map;
};

struct map_ops {
	size_t update_elem;
	size_t lookup_elem;
	size_t delete_elem;
};

struct map_info {
	int fd;
	struct bpf_map_def *map;
	struct map_ops ops;
	bool ringbuf_reserved;
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

bool is_not_known(struct bpf_reg *reg);
bool is_init(struct bpf_reg *reg);
bool is_ptr_to_map_value(struct bpf_reg *reg);
bool is_not_ptr_to_mem(struct bpf_reg *reg);
bool is_not_ptr_to_map_value(struct bpf_reg *reg);
bool is_not_ptr_to_ctx(struct bpf_reg *reg);
bool is_not_const_ptr_to_map(struct bpf_reg *reg);
bool is_ptr(struct bpf_reg *reg);
bool is_scalar(struct bpf_reg *reg);
bool is_enabled(struct bpf_reg *reg);
bool is_mutable(struct bpf_reg *reg);
bool vcheck_reg(struct bpf_reg *reg, va_list va);
bool check_reg(struct bpf_reg *reg, ...);
struct bpf_reg *get_rand_reg(struct environ *env, ...);
bool generate_rand_reg_bounds(struct environ *env);
bool generate_rand_alu_reg(struct environ *env);
bool generate_rand_alu_imm(struct environ *env);
bool generate_rand_alu(struct environ *env);
bool generate_rand_mov_reg(struct environ *env);
bool generate_rand_mov_imm(struct environ *env);
bool generate_rand_ld_imm64(struct environ *env);
bool generate_rand_skb_ld_abs(struct environ *env);
bool generate_rand_mov(struct environ *env);
bool generate_rand_map_op(struct environ *env);
bool generate_rand_ptr_ldx(struct environ *env);
bool generate_rand_ptr_stx(struct environ *env);
bool generate_rand_reg_spill(struct environ *env);
bool generate_rand_helper_call(struct environ *env);
bool generate_rand_zext_reg(struct environ *env);
bool generate_map_update_elem(struct environ *env, struct map_info *map);
bool generate_map_lookup_elem(struct environ *env, struct map_info *map);
bool generate_map_delete_elem(struct environ *env, struct map_info *map);
bool generate_ringbuf_reserve(struct environ *env, struct map_info *map);
bool generate_ringbuf_discard(struct environ *env, struct map_info *map);
bool generate_rand_map_atomic_op(struct environ *env);
void generate_prog_footer(struct environ *env);
int generate(struct environ *env);
void generate_prog_header(struct environ *env);
void setup(struct environ *env);
size_t get_rand_op(struct environ *env);
size_t get_rand_op_ptr(struct environ *env);
uint8_t get_req_footer_space(struct environ *env);
bool has_insn_space(struct environ *env, uint16_t insns);

#endif
