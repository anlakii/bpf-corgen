#include <linux/filter.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <time.h>
#include <stdint.h>
#include <stdio.h>
#include "gen.h"
#include "helpers.h"
#include "debug.h"
#include "insn_handlers.h"
#include "init_structs.h"
#include "loader.h"

struct map_info *get_map_from_fd(struct environ *env, int map_fd)
{
	if (map_fd < 0)
		_abort("invalid map fd");

	for (size_t idx = 0; idx < env->maps_len; idx++) {
		if (env->maps[idx].fd == map_fd)
			return &env->maps[idx];
	}

	return NULL;
}

size_t get_rand_op(struct environ *env)
{
	return env->conf->alu_scal_ops[rand() % env->conf->alu_scal_ops_len];
}

size_t get_rand_op_ptr(struct environ *env)
{
	return (rand() % 2 ? BPF_ADD : BPF_SUB);
}

bool is_not_known(struct bpf_reg *reg)
{
	return reg->is_known == false;
}

bool is_init(struct bpf_reg *reg)
{
	return reg->reg_type != NOT_INIT;
}

bool is_ptr_to_map_value(struct bpf_reg *reg)
{
	return reg->reg_type == PTR_TO_MAP_VALUE;
}

bool is_not_ptr_to_map_value(struct bpf_reg *reg)
{
	return reg->reg_type != PTR_TO_MAP_VALUE;
}

bool is_not_ptr_to_ctx(struct bpf_reg *reg)
{
	return reg->reg_type != PTR_TO_CTX;
}

bool is_not_const_ptr_to_map(struct bpf_reg *reg)
{
	return reg->reg_type != CONST_PTR_TO_MAP;
}

bool is_ptr(struct bpf_reg *reg)
{
	return reg->reg_type != SCALAR_VALUE && reg->reg_type != NOT_INIT;
}

bool is_scalar(struct bpf_reg *reg)
{
	return reg->reg_type == SCALAR_VALUE;
}

bool is_enabled(struct bpf_reg *reg)
{
	return reg->enable;
}

bool is_mutable(struct bpf_reg *reg)
{
	return reg->mutable;
}

struct bpf_reg *get_rand_reg(struct environ *env, ...)
{
	va_list valist;
	va_start(valist, env);
	bool (*requirements[16])(struct bpf_reg * reg) = {0};
	bool (*requirement)(struct bpf_reg * reg);
	uint8_t idx_va = 0;

	do {
		requirement = va_arg(valist, bool (*)(struct bpf_reg * reg));
		requirements[idx_va] = requirement;
		idx_va++;
	} while (idx_va < 16 && requirement);

	uint8_t regs_matched = 0;
	struct bpf_reg *regs[__MAX_BPF_REG];

	for (uint8_t idx_reg = 0; idx_reg < __MAX_BPF_REG; idx_reg++) {
		bool matched = true;
		for (uint8_t idx_callback = 0; idx_callback < idx_va - 1; idx_callback++) {
			if (!requirements[idx_callback])
				continue;
			if (!requirements[idx_callback](&env->regs[idx_reg])) {
				matched = false;
				break;
			}
		}
		if (matched) {
			regs[regs_matched] = &env->regs[idx_reg];
			regs_matched++;
		}
	}

	va_end(valist);

	if (!regs_matched)
		return NULL;

	return regs[rand() % regs_matched];
}

bool is_arithmetic_allowed(struct environ *env, struct bpf_reg *dst, struct bpf_reg *src, uint8_t op)
{
	if ((dst->reg_type == PTR_TO_CTX || src->reg_type == PTR_TO_CTX) && !env->privileged)
		return false;

	if (dst->reg_type != SCALAR_VALUE && src->reg_type != SCALAR_VALUE)
		return false;

	if ((op != BPF_ADD && op != BPF_SUB) && (dst->reg_type != SCALAR_VALUE || src->reg_type != SCALAR_VALUE))
		return false;

	if (op == BPF_SUB && src->reg_type != SCALAR_VALUE && dst->reg_type == SCALAR_VALUE)
		return false;

	return true;
}

bool should_s64min_bound(struct environ *env, struct bpf_reg *reg)
{
	if (reg->reg_type == PTR_TO_MAP_VALUE)
		return true;

	return false;
}

bool should_s64max_bound(struct environ *env, struct bpf_reg *reg)
{
	if (reg->reg_type == PTR_TO_MAP_VALUE)
		return true;

	return false;
}

uint8_t get_count_ptr_reg_init_mutable(struct environ *env)
{

	uint8_t ptr_regs = 0;
	for (uint8_t idx = 0; idx < LEN(bpf_regs); idx++) {
		if (env->regs[idx].reg_type != SCALAR_VALUE &&
			env->regs[idx].reg_type != NOT_INIT &&
			env->regs[idx].mutable && env->regs[idx].enable)
			ptr_regs++;
	}
	return ptr_regs;
}

uint8_t get_reg_mutable_count_of_type(struct environ *env, uint8_t type)
{
	uint8_t count = 0;

	for (uint8_t idx = 0; idx < LEN(bpf_regs); idx++) {
		if (env->regs[idx].reg_type == type &&
			env->regs[idx].mutable &&
			env->regs[idx].enable)
			count++;
	}
	return count;
}

bool generate_rand_bind(struct environ *env)
{
	struct bpf_reg *src;
	/* pointer comparison prohibited */
	if (env->conf->chaos_mode)
		src = get_rand_reg(env, is_init, is_enabled, NULL);
	else
		src = get_rand_reg(env, is_not_known, is_scalar, is_enabled, NULL);

	if (!src)
		return false;

	if (env->generated_insns + 6 > env->total_insns)
		return false;

	int32_t min = env->conf->imm32_min;
	int32_t max = env->conf->imm32_max;

	switch (rand() % 4) {
		case 0:
			gen_bpf_jmp_imm(env, BPF_JSLT, src, rand_between(min, max), env->total_insns - env->generated_insns - 3);
		case 1:
			gen_bpf_jmp_imm(env, BPF_JSGT, src, rand_between(min, max), env->total_insns - env->generated_insns - 3);
		case 2:
			gen_bpf_jmp_imm(env, BPF_JGE, src, rand() % max, env->total_insns - env->generated_insns - 3);
		case 3:
			gen_bpf_jmp_imm(env, BPF_JLE, src, rand() % max, env->total_insns - env->generated_insns - 3);
	}
	return true;
}
bool generate_rand_alu_reg(struct environ *env)
{
	if (!env->conf->alu_reg_insns_len)
		return false;

	struct bpf_reg *dst = get_rand_reg(env, is_mutable, is_init, is_enabled, is_not_const_ptr_to_map, NULL);
	struct bpf_reg *src = get_rand_reg(env, is_init, is_enabled, NULL);
	uint8_t rand_op = get_rand_op(env);

	if (!dst || !src)
		return false;

	if (get_reg_mutable_count_of_type(env, SCALAR_VALUE) < 1) {
		return false;
	}

	while (!is_arithmetic_allowed(env, dst, src, rand_op)) {
		rand_op = get_rand_op(env);
		dst = get_rand_reg(env, is_mutable, is_init, is_enabled, is_not_const_ptr_to_map, NULL);
		src = get_rand_reg(env, is_init, is_enabled, NULL);
	}

	if (should_s64min_bound(env, dst) && !src->is_known) {
		if (env->generated_insns >= env->total_insns - 3)
			return false;
		gen_bpf_jmp_imm(env, BPF_JSGT, src, rand() % 64, env->total_insns - env->generated_insns - 3);
	} else if (should_s64min_bound(env, src) && !dst->is_known) {
		if (env->generated_insns >= env->total_insns - 3)
			return false;
		gen_bpf_jmp_imm(env, BPF_JSGT, dst, rand() % 64, env->total_insns - env->generated_insns - 3);
	}

	env->conf->alu_reg_insns[rand() % env->conf->alu_reg_insns_len](
		env,
		rand_op,
		dst,
		src);

	return true;
}

bool generate_rand_alu_imm(struct environ *env)
{
	if (!env->conf->alu_imm_insns_len)
		return false;

	void (*alu_op)(struct environ *, uint8_t, struct bpf_reg *, int32_t) =
		env->conf->alu_imm_insns[rand() % env->conf->alu_imm_insns_len];

	struct bpf_reg *reg;
	uint8_t op;

	if (env->conf->chaos_mode) {
		reg = get_rand_reg(env, is_mutable, is_init, is_enabled, NULL);
		op = get_rand_op(env);
	} else {
		reg = get_rand_reg(env, is_mutable, is_enabled, is_init, is_not_const_ptr_to_map, NULL);

		if (!reg)
			return false;

		if (alu_op == gen_bpf_alu32_imm) {
			reg = get_rand_reg(env, is_scalar, is_mutable, is_enabled, NULL);
			if (!reg)
				return false;
		}

		op = (reg->reg_type == SCALAR_VALUE ? get_rand_op(env) : get_rand_op_ptr(env));
	}

	int32_t imm = 0;

	switch (op) {
		case BPF_LSH:
		case BPF_RSH:
			imm = rand_between(1, 31);
			break;
		default:
			do {
				imm = rand_between(env->conf->imm32_min, env->conf->imm32_max);
			} while (imm == 0);
	}
	if (reg->reg_type == PTR_TO_MAP_VALUE)
		imm = 0;

	alu_op(
		env,
		op,
		reg,
		imm);

	return true;
}

bool generate_rand_alu(struct environ *env)
{
	if (rand() % 2)
		return generate_rand_alu_reg(env);
	else
		return generate_rand_alu_imm(env);
}

bool generate_rand_mov_reg(struct environ *env)
{
	if (!env->conf->mov_reg_insns_len)
		return false;

	struct bpf_reg *dst = get_rand_reg(env, is_mutable, is_enabled, NULL);
	struct bpf_reg *src = get_rand_reg(env, is_init, is_enabled, NULL);

	if (!dst || !src)
		return false;

	env->conf->mov_reg_insns[rand() % env->conf->mov_reg_insns_len](
		env,
		dst,
		src);
	return true;
}

bool generate_rand_mov_imm(struct environ *env)
{
	if (!env->conf->mov_imm_insns_len)
		return false;

	struct bpf_reg *dst = get_rand_reg(env, is_mutable, is_enabled, NULL);
	int32_t imm = rand_between(env->conf->imm32_min, env->conf->imm32_max);

	if (!dst)
		return false;

	env->conf->mov_imm_insns[rand() % env->conf->mov_imm_insns_len](
		env,
		dst,
		imm);
	return true;
}

bool generate_rand_ld_imm64(struct environ *env)
{
	if (env->generated_insns + 4 > env->total_insns)
		return false;

	gen_bpf_ld_imm64(env, get_rand_reg(env, is_enabled, is_mutable, 0), rand64());
	return true;
}

bool generate_rand_mem_ld(struct environ *env)
{
	uint8_t size = rand() % LEN(bpf_mem_size);

	if (env->generated_insns >= env->total_insns - 3) {
		return false;
	}

	gen_bpf_mov64_reg(env, &env->regs[BPF_REG_6], &env->regs[BPF_REG_9]);
	gen_bpf_ld_abs(env, bpf_mem_size[size], rand() % env->conf->pkt_len);
	return true;
}

bool generate_rand_mov(struct environ *env)
{
	if (rand() % 2)
		return generate_rand_mov_reg(env);
	else
		return generate_rand_mov_imm(env);
}

bool generate_rand_map_op(struct environ *env)
{
	int map_fd = env->maps[rand() % env->maps_len].fd;

	return prep_rand_map_op(env, map_fd);
}

bool prep_bpf_map_load(struct environ *env, int map_fd)
{
	if (!env->maps_len) {
		_error("no map defined");
		return false;
	}

	if (map_fd < 0) {
		_error("map fd invalid value");
		return false;
	}

	gen_bpf_ld_map_fd(env, &env->regs[MAP_FD_REG_IDX], map_fd);
	return true;
}

bool prep_map_lookup_elem(struct environ *env, int map_fd)
{
	if ((int64_t) env->generated_insns > env->total_insns - 15)
		return false;

	struct map_info *map = get_map_from_fd(env, map_fd);
	if (!map)
		_abort("map fd not found");

	if (map->ops.lookup_elem)
		return false;

	int16_t key_off;
	if (env->conf->stack_align)
		key_off = -((rand() % env->conf->stack_size) + 8) & ~(8 - 1);
	else
		key_off = -((rand() % env->conf->stack_size) + 8);

	prep_bpf_map_load(env, map_fd);
	gen_bpf_mov64_imm(env, &env->regs[BPF_REG_8], rand() % 64);
	gen_bpf_stx_mem(env, BPF_DW, &env->regs[BPF_REG_10], &env->regs[BPF_REG_8], key_off);
	gen_bpf_mov64_reg(env, &env->regs[BPF_REG_2], &env->regs[BPF_REG_10]);
	gen_bpf_alu64_imm(env, BPF_ADD, &env->regs[BPF_REG_2], key_off);
	gen_bpf_call_map_lookup_elem(env);
	gen_bpf_jmp_imm(env, BPF_JEQ, &env->regs[BPF_REG_0], 0, env->total_insns - env->generated_insns - 2);

	env->regs[BPF_REG_0].map = map->map;
	map->ops.lookup_elem = env->generated_insns;
	return true;
}

bool prep_map_delete_elem(struct environ *env, int map_fd)
{
	if ((int64_t) env->generated_insns > env->total_insns - 14)
		return false;

	struct map_info *map = get_map_from_fd(env, map_fd);
	if (!map)
		_abort("map fd not found");

	if (map->ops.delete_elem)
		return false;

	int16_t key_off;
	if (env->conf->stack_align)
		key_off = (-rand_between(1, env->conf->stack_size)) & ~(8 - 1);
	else
		key_off = -rand_between(1, env->conf->stack_size);

	int64_t rand_key;

	size_t count = get_rand_map_key(map, &rand_key);
	if (count < map->map->max_entries / 2)
		return false;

	prep_bpf_map_load(env, map_fd);
	gen_bpf_ld_imm64(env, &env->regs[BPF_REG_8], rand_key);
	gen_bpf_stx_mem(env, BPF_DW, &env->regs[BPF_REG_10], &env->regs[BPF_REG_8], key_off);
	gen_bpf_mov64_reg(env, &env->regs[BPF_REG_2], &env->regs[BPF_REG_10]);
	gen_bpf_alu64_imm(env, BPF_ADD, &env->regs[BPF_REG_2], key_off);
	gen_bpf_call_map_delete_elem(env);
	map->ops.delete_elem = env->generated_insns;
	return true;
}

int write_stack(struct environ *env, void *data, size_t data_len, struct bpf_reg *dst_reg)
{
	size_t chunk = 0;

	if (data_len > env->conf->stack_size)
		_abort("trying to write past env->conf->stack_size, %zu > %d", data_len, env->conf->stack_size);

	int16_t offset;

	if (env->conf->stack_align)
		offset = (-rand_between(data_len, env->conf->stack_size)) & ~(8 - 1);
	else
		offset = (-rand_between(data_len, env->conf->stack_size));

	for (chunk = 0; chunk < data_len; chunk += 8) {
		gen_bpf_ld_imm64(env, &env->regs[BPF_REG_8], ((uint64_t *) data)[chunk / 8]);
		gen_bpf_stx_mem(env, BPF_DW, &env->regs[BPF_REG_10], &env->regs[BPF_REG_8], offset + chunk);
	}

	if (!dst_reg)
		return offset;

	gen_bpf_mov64_reg(env, dst_reg, &env->regs[BPF_REG_10]);
	gen_bpf_alu64_imm(env, BPF_ADD, dst_reg, offset);
	return offset;
}

bool prep_map_update_elem(struct environ *env, int map_fd)
{
	struct map_info *map = get_map_from_fd(env, map_fd);
	if (!map)
		_abort("map fd not found");

	int16_t key_off;

	if (env->conf->stack_align)
		key_off = -((rand() % env->conf->stack_size) + 8) & ~(8 - 1);
	else
		key_off = -((rand() % env->conf->stack_size) + 8);

	if ((int64_t) env->generated_insns > env->total_insns - (15 + 3 * (map->map->value_size / 8)))
		return false;

	if (map->ops.update_elem)
		return false;

	prep_bpf_map_load(env, map_fd);
	int64_t rand_key;

	size_t count = get_rand_map_key(map, &rand_key);

	if (count == map->map->max_entries) {

		gen_bpf_mov64_imm(env, &env->regs[BPF_REG_8], rand_key);
		gen_bpf_stx_mem(env, BPF_DW, &env->regs[BPF_REG_10], &env->regs[BPF_REG_8], key_off);

	} else {
		struct bpf_reg *reg = get_rand_reg(env, is_init, is_enabled, is_scalar, NULL);
		if (!reg)
			return false;

		gen_bpf_stx_mem(env, BPF_DW, &env->regs[BPF_REG_10], reg, key_off);
	}

	gen_bpf_mov64_reg(env, &env->regs[BPF_REG_2], &env->regs[BPF_REG_10]);
	gen_bpf_alu64_imm(env, BPF_ADD, &env->regs[BPF_REG_2], key_off);

	uint8_t data[map->map->value_size];
	for (size_t idx = 0; idx < map->map->value_size; idx++)
		data[idx] = rand() % 255;

	write_stack(env, data, sizeof(data), &env->regs[BPF_REG_3]);

	gen_bpf_mov64_imm(env, &env->regs[BPF_REG_4], BPF_ANY);

	gen_bpf_call_map_update_elem(env);

	map->ops.update_elem = env->generated_insns;
	return true;
}

bool generate_rand_ptr_stx(struct environ *env)
{
	struct bpf_reg *dst = get_rand_reg(env, is_ptr, is_not_ptr_to_ctx, is_enabled, NULL);
	struct bpf_reg *src = get_rand_reg(env, is_init, is_enabled, NULL);

	if (!env->conf->try_leak_into_map) {
		if (dst && dst->reg_type == PTR_TO_MAP_VALUE)
			src = get_rand_reg(env, is_init, is_enabled, is_scalar, NULL);

	} else if (!env->conf->try_leak_into_mem) {
		if (dst && dst->reg_type == PTR_TO_STACK)
			src = get_rand_reg(env, is_init, is_enabled, is_scalar, NULL);
	}
	if (env->conf->chaos_mode)
		dst = get_rand_reg(env, is_init, is_enabled, NULL);

	if (!dst || !src)
		return false;

	uint8_t size = rand();
	int32_t off = rand();

	if (dst->reg_type == PTR_TO_MAP_VALUE)
		off = 0;

	if (!get_count_ptr_reg_init_mutable(env))
		return false;

	gen_bpf_stx_mem(env, size, dst, src, off);
	return true;
}

bool generate_rand_reg_spill(struct environ *env)
{
	struct bpf_reg *reg_spill = get_rand_reg(env, is_init, is_enabled, NULL);
	uint8_t size = bpf_mem_size[rand() % LEN(bpf_mem_size)];

	if (!reg_spill)
		return false;

	if (reg_spill->reg_type != SCALAR_VALUE && !env->conf->chaos_mode)
		size = BPF_DW;

	int16_t off;
	if (env->conf->stack_align)
		off = (-rand_between(1, env->conf->stack_size)) & ~(8 - 1);
	else
		off = (-rand_between(1, env->conf->stack_size));

	gen_bpf_stx_mem(env, size, &env->regs[BPF_REG_10], reg_spill, off);

	return true;
}

bool generate_rand_helper_call(struct environ *env)
{
	gen_bpf_call_get_prandom_u32(env);
	return true;
}

bool generate_rand_zext_reg(struct environ *env)
{
  struct bpf_reg *reg = get_rand_reg(env, is_enabled, is_init, is_mutable, NULL);
  if (!reg)
    return false;

  gen_bpf_zext_reg(env, reg);
  return true;
}

bool gen_map_atomic_op(struct environ *env)
{
	if (!env->conf->try_leak_into_mem)
		return false;

	if (!env->conf->alu_atomic_ops_len)
		return false;

	struct bpf_reg *dst = get_rand_reg(env, is_enabled, is_ptr_to_map_value, NULL);
	struct bpf_reg *src = get_rand_reg(env, is_enabled, is_init, NULL);

	if (!dst || !src)
		return false;

	int32_t atomic_op = env->conf->alu_atomic_ops[rand() % env->conf->alu_scal_ops_len];

	gen_bpf_atomic_op(env, (rand() % 2 ? BPF_W : BPF_DW), atomic_op, dst, src, rand_between(env->conf->imm32_min, env->conf->imm32_max));
	return true;
}

bool prep_rand_map_op(struct environ *env, int map_fd)
{
	if (!env->maps_len) {
		_error("no map defined");
		return false;
	}

	switch (rand() % 4) {
		case 0:
			return prep_map_update_elem(env, map_fd);
		case 1:
			return prep_map_lookup_elem(env, map_fd);
		case 2:
			return prep_map_delete_elem(env, map_fd);
		case 3:
			return gen_map_atomic_op(env);
	}

	return prep_map_update_elem(env, map_fd);
}

int generate(struct environ *env)
{
	setup(env);

	env->total_insns = rand_between(env->conf->min_insns, env->conf->max_insns);
	env->insns = malloc(sizeof(struct bpf_insn) * (env->total_insns + 1));

	prepare_prog_header(env);

	do {
		gen_rand_insn_type[rand() % LEN(gen_rand_insn_type)](env);
	} while (env->generated_insns < env->total_insns - 2);

	gen_bpf_mov64_imm(env, &env->regs[BPF_REG_0], 0);
	gen_bpf_exit_insn(env);

	return env->generated_insns;
}

void prepare_prog_header(struct environ *env)
{
	/* mov r1 ctx to r9, used later for BPF_LD_ABS skb data loading */
	gen_bpf_mov64_reg(env, &env->regs[BPF_REG_9], &env->regs[BPF_REG_1]);
	/* r9 is not mutable anymore, can't lose context */
	env->regs[BPF_REG_9].mutable = false;
}

void setup(struct environ *env)
{
	if (env->conf->min_insns > env->conf->max_insns)
		_abort("min_insns > max_insns");

	if (env->conf->max_insns < 10)
		_abort("max number of instructions too low");

	if (env->conf->max_insns < 10)
		_abort("min number of instructions too low");

	for (size_t idx = 0; idx < LEN(bpf_regs); idx++) {
		env->regs[idx] = bpf_regs[idx];
		env->regs[idx].is_known = false;
	}

	for (size_t idx = 0; idx < env->maps_len; idx++)
		memset(&env->maps[idx].ops, 0, sizeof(struct map_ops));
}
