#include "gen.h"
#include "debug.h"
#include "helpers.h"
#include "init_structs.h"
#include "insn_handlers.h"
#include "loader.h"
#include <assert.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* START REG FILTERING */

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

bool is_not_ptr_to_mem(struct bpf_reg *reg)
{
	return reg->reg_type != PTR_TO_MEM;
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
bool vcheck_reg(struct bpf_reg *reg, va_list va) {

  va_list valist;
  va_copy(valist, va);
	bool (*requirements[16])(struct bpf_reg * reg) = {0};
	bool (*requirement)(struct bpf_reg * reg);
	uint8_t idx_va = 0;

	do {
		requirement = va_arg(valist, bool (*)(struct bpf_reg * reg));
		requirements[idx_va] = requirement;
		idx_va++;
	} while (idx_va < 16 && requirement);

  bool matched = true;
  for (uint8_t idx_callback = 0; idx_callback < idx_va - 1; idx_callback++) {
    if (!requirements[idx_callback])
      continue;
    if (!requirements[idx_callback](reg)) {
      matched = false;
      break;
    }
  }

	va_end(valist);
	return matched;
}

bool check_reg(struct bpf_reg *reg, ...) {
	va_list valist;
	va_start(valist, reg);

  bool match = vcheck_reg(reg, valist);

  va_end(valist);

  return match;
}


struct bpf_reg *get_rand_reg(struct environ *env, ...)
{
	va_list valist;
	va_start(valist, env);

	uint8_t regs_matched = 0;
	struct bpf_reg *regs[__MAX_BPF_REG];

	for (uint8_t idx_reg = 0; idx_reg < __MAX_BPF_REG; idx_reg++) {
		if (vcheck_reg(&env->regs[idx_reg], valist)) {
			regs[regs_matched] = &env->regs[idx_reg];
			regs_matched++;
		}
	}

	va_end(valist);

	if (!regs_matched)
		return NULL;

	return regs[rand() % regs_matched];
}

/* STOP REG FILTERING */

bool is_arithmetic_allowed(struct environ *env, struct bpf_reg *dst, struct bpf_reg *src, uint8_t op,
						   void (*alu_reg_insn)(struct environ *, uint8_t, struct bpf_reg *, struct bpf_reg *))
{
	if (env->conf->chaos_mode)
		return true;

	if (!env->privileged) {

		if ((dst->reg_type == PTR_TO_CTX || src->reg_type == PTR_TO_CTX))
			return false;

		if ((dst->reg_type == CONST_PTR_TO_MAP || src->reg_type == CONST_PTR_TO_MAP))
			return false;

		if ((dst->reg_type == PTR_TO_MEM || src->reg_type == PTR_TO_MEM))
			return false;
	}

  if (dst->reg_type != SCALAR_VALUE && src->reg_type != SCALAR_VALUE)
    return false;

	if ((dst->reg_type != SCALAR_VALUE || src->reg_type != SCALAR_VALUE)) {

		if (alu_reg_insn == gen_bpf_alu32_reg)
			return false;

		if (op != BPF_ADD && op != BPF_SUB)
			return false;
	}

	if (dst->reg_type == PTR_TO_MAP_VALUE && src->is_known)
		return false;

	if (src->reg_type == PTR_TO_STACK && !dst->is_known)
		return false;

	return true;
}

bool generate_rand_reg_bounds(struct environ *env)
{
	struct bpf_reg *src = get_rand_reg(env, is_not_known, is_scalar, is_enabled, NULL);

	if (!src)
		return false;

	int32_t min = env->conf->imm32_min;
	int32_t max = env->conf->imm32_max;
	int32_t jmp_off = env->total_insns - env->generated_insns - get_req_footer_space(env) - 1;

	if (env->conf->chaos_mode) {
		src = get_rand_reg(env, is_init, is_enabled, NULL);
		jmp_off = rand() % (env->total_insns - env->generated_insns - get_req_footer_space(env));
	}

	switch (rand() % 4) {
		case 0:
			gen_bpf_jmp_imm(env, BPF_JSLT, src, rand_between(min, max), jmp_off);
			break;
		case 1:
			gen_bpf_jmp_imm(env, BPF_JSGT, src, rand_between(min, max), jmp_off);
			break;
		case 2:
			gen_bpf_jmp_imm(env, BPF_JGE, src, rand() % max, jmp_off);
			break;
		case 3:
			gen_bpf_jmp_imm(env, BPF_JLE, src, rand() % max, jmp_off);
			break;
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

	if (!get_rand_reg(env, is_enabled, is_mutable, is_scalar, NULL)) {
		return false;
	}
	void (*alu_reg_insn)(struct environ *, uint8_t, struct bpf_reg *, struct bpf_reg *) =
		env->conf->alu_reg_insns[rand() % env->conf->alu_reg_insns_len];

	while (!is_arithmetic_allowed(env, dst, src, rand_op, alu_reg_insn)) {
		alu_reg_insn = env->conf->alu_reg_insns[rand() % env->conf->alu_reg_insns_len];
		rand_op = get_rand_op(env);
		dst = get_rand_reg(env, is_mutable, is_init, is_enabled, is_not_const_ptr_to_map, NULL);
		src = get_rand_reg(env, is_init, is_enabled, NULL);
	}

	alu_reg_insn(env, rand_op, dst, src);

	return true;
}

bool generate_rand_alu_imm(struct environ *env)
{
	if (!env->conf->alu_imm_insns_len)
		return false;

	void (*alu_op)(struct environ *, uint8_t, struct bpf_reg *, int32_t) = env->conf->alu_imm_insns[rand() % env->conf->alu_imm_insns_len];

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

	alu_op(env, op, reg, imm);

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

	env->conf->mov_reg_insns[rand() % env->conf->mov_reg_insns_len](env, dst, src);
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

	env->conf->mov_imm_insns[rand() % env->conf->mov_imm_insns_len](env, dst, imm);
	return true;
}

bool generate_rand_ld_imm64(struct environ *env)
{
	if (!has_insn_space(env, 2))
		return false;

	gen_bpf_ld_imm64(env, get_rand_reg(env, is_enabled, is_mutable, NULL), rand64());
	return true;
}

bool generate_rand_skb_ld_abs(struct environ *env)
{
	uint8_t size = rand() % (LEN(bpf_mem_size) - 1);

	if (!has_insn_space(env, 2))
		return false;

	gen_bpf_mov64_reg(env, &env->regs[BPF_REG_6], &env->regs[BPF_REG_9]);
	gen_bpf_ld_abs(env, size, rand() % env->conf->pkt_len);
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

	struct map_info *map = &env->maps[rand() % env->maps_len];
	if (!env->maps_len) {
		_error("no map defined");
		return false;
	}

	if (map->map->type == BPF_MAP_TYPE_RINGBUF)
		return generate_ringbuf_reserve(env, map);

	switch (rand() % 4) {
		case 0:
			return generate_map_update_elem(env, map);
		case 1:
			return generate_map_lookup_elem(env, map);
		case 2:
			return generate_map_delete_elem(env, map);
		case 3:
			return generate_rand_map_atomic_op(env);
	}
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
		if (chunk + 8 <= data_len)
			gen_bpf_ld_imm64(env, &env->regs[BPF_REG_8], ((uint64_t *) data)[chunk / 8]);
		else if (chunk + 4 <= data_len)
			gen_bpf_mov64_imm(env, &env->regs[BPF_REG_8], ((uint32_t *) data)[(chunk / 8) * 2]);

		gen_bpf_stx_mem(env, BPF_DW, &env->regs[BPF_REG_10], &env->regs[BPF_REG_8], offset + chunk);
	}

	if (!dst_reg)
		return offset;

	gen_bpf_mov64_reg(env, dst_reg, &env->regs[BPF_REG_10]);
	gen_bpf_alu64_imm(env, BPF_ADD, dst_reg, offset);
	return offset;
}

int16_t get_stack_chunk(struct environ *env, uint16_t size) {
  int16_t offset = 0;
  uint16_t count = 0;
  uint8_t byte_size;
  switch (size) {
    case BPF_B:
      byte_size = 1;
      break;
    case BPF_H:
      byte_size = 2;
      break;
    case BPF_W:
      byte_size = 4;
      break;
    case BPF_DW:
      byte_size = 8;
      break;
  }

  for (int16_t idx = 0; idx < MAX_BPF_STACK - 1; idx++) {
    if (env->stack[idx / 8].slot_type[idx % 8] == STACK_INVALID) {
      offset = 0;
      count = 0;
      continue;
    }

    offset = idx;
    if (count >= byte_size)
      return idx - count;
    count++;
    
  }
  return 0;
  
}

bool generate_rand_ptr_ldx(struct environ *env)
{
	struct bpf_reg *dst = get_rand_reg(env, is_init, is_mutable, is_enabled, NULL);
	struct bpf_reg *src = get_rand_reg(env, is_ptr, is_enabled, is_not_ptr_to_ctx, NULL);

	if (!dst || !src)
		return false;

	uint8_t size = BPF_DW;
	int32_t off = rand() % env->conf->imm32_max;

  if (src->reg_type == PTR_TO_STACK) {
		off = - get_stack_chunk(env, size);
    if (!off)
      return false;
    /* do not restore state if reg spill */
  }

  if (dst->reg_type == PTR_TO_MAP_VALUE) {
    off = 0;
  }

	gen_bpf_ldx_mem(env, size, dst, src, off);
	return true;
}

bool generate_rand_ptr_stx(struct environ *env)
{
	struct bpf_reg *dst;
	struct bpf_reg *src;
	uint8_t size = bpf_mem_size[rand() % LEN(bpf_mem_size)];
	int32_t off = rand() % env->conf->imm32_max;

  if (env->privileged)
		dst = get_rand_reg(env, is_ptr, is_mutable, is_enabled, is_not_ptr_to_ctx, NULL);
	else
		dst = get_rand_reg(env, is_ptr, is_mutable, is_enabled, is_not_ptr_to_ctx, is_not_const_ptr_to_map, NULL);

	src = get_rand_reg(env, is_init, is_enabled, NULL);

	if (!dst)
		return false;

	if (!env->conf->try_leak_into_map && dst->reg_type == PTR_TO_MAP_VALUE && src->reg_type != SCALAR_VALUE)
		src = get_rand_reg(env, is_init, is_enabled, is_scalar, NULL);

	if (!env->conf->try_leak_into_mem && (dst->reg_type == PTR_TO_MEM) && src->reg_type != SCALAR_VALUE)
		src = get_rand_reg(env, is_init, is_enabled, is_scalar, NULL);

	if (env->conf->chaos_mode)
		dst = get_rand_reg(env, is_init, is_enabled, NULL);

	if (!dst)
		return false;

  if (dst->reg_type == PTR_TO_STACK) {
    src = get_rand_reg(env, is_init, is_enabled, is_scalar, NULL);
    if (env->conf->stack_align)
      off = (-rand_between(1, env->conf->stack_size)) & ~(8 - 1);
    else
      off = (-rand_between(1, env->conf->stack_size));
  }

	if (!src)
		return false;

	if (dst->reg_type == PTR_TO_MEM)
		off = (dst->mem_range ? rand() % dst->mem_range : rand());

	if (dst->reg_type == PTR_TO_MAP_VALUE)
		off = 0;

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

bool generate_map_update_elem(struct environ *env, struct map_info *map)
{
	int16_t key_off;

	if (env->conf->stack_align)
		key_off = -((rand() % env->conf->stack_size) + 8) & ~(8 - 1);
	else
		key_off = -((rand() % env->conf->stack_size) + 8);

	if (!has_insn_space(env, (10 + 3 * (map->map->value_size / 8))))
		return false;

	if (map->ops.update_elem)
		return false;

	gen_bpf_ld_map_fd(env, &env->regs[MAP_FD_REG_IDX], map->fd);
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

bool generate_map_lookup_elem(struct environ *env, struct map_info *map)
{
	if (!has_insn_space(env, 13))
		return false;

	int16_t key_off;
	if (env->conf->stack_align)
		key_off = -((rand() % env->conf->stack_size) + 8) & ~(8 - 1);
	else
		key_off = -((rand() % env->conf->stack_size) + 8);

	int64_t rand_key;
	size_t count = get_rand_map_key(map, &rand_key);
	if (!count)
		rand_key = (int32_t) rand_between(env->conf->imm32_min, env->conf->imm32_max);

	gen_bpf_ld_map_fd(env, &env->regs[MAP_FD_REG_IDX], map->fd);
	gen_bpf_mov64_imm(env, &env->regs[BPF_REG_8], rand_key);
	gen_bpf_stx_mem(env, BPF_DW, &env->regs[BPF_REG_10], &env->regs[BPF_REG_8], key_off);
	gen_bpf_mov64_reg(env, &env->regs[BPF_REG_2], &env->regs[BPF_REG_10]);
	gen_bpf_alu64_imm(env, BPF_ADD, &env->regs[BPF_REG_2], key_off);
	gen_bpf_call_map_lookup_elem(env);
	gen_bpf_jmp_imm(env, BPF_JEQ, &env->regs[BPF_REG_0], 0, env->total_insns - env->generated_insns - get_req_footer_space(env) - 1);

	env->regs[BPF_REG_0].map = map->map;
	if (env->regs[BPF_REG_0].reg_type != PTR_TO_MAP_VALUE)
		_abort("remove_me AAAA");
	map->ops.lookup_elem = env->generated_insns;
	return true;
}

bool generate_map_delete_elem(struct environ *env, struct map_info *map)
{
	if (!has_insn_space(env, 12))
		return false;

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

	gen_bpf_ld_map_fd(env, &env->regs[MAP_FD_REG_IDX], map->fd);
	gen_bpf_ld_imm64(env, &env->regs[BPF_REG_8], rand_key);
	gen_bpf_stx_mem(env, BPF_DW, &env->regs[BPF_REG_10], &env->regs[BPF_REG_8], key_off);
	gen_bpf_mov64_reg(env, &env->regs[BPF_REG_2], &env->regs[BPF_REG_10]);
	gen_bpf_alu64_imm(env, BPF_ADD, &env->regs[BPF_REG_2], key_off);
	gen_bpf_call_map_delete_elem(env);
	map->ops.delete_elem = env->generated_insns;
	return true;
}

bool generate_ringbuf_reserve(struct environ *env, struct map_info *map)
{
	if (!has_insn_space(env, 6))
		return false;

	if (map->ringbuf_reserved)
		return false;

	if (env->generated_insns + 6 > env->total_insns / 2)
		return false;

	uint32_t size = rand() % env->conf->imm32_min;
	gen_bpf_ld_map_fd(env, &env->regs[MAP_FD_REG_IDX], map->fd);
	gen_bpf_mov64_imm(env, &env->regs[BPF_REG_2], size);
	gen_bpf_mov64_imm(env, &env->regs[BPF_REG_3], 0);
	gen_bpf_call_ringbuf_reserve(env);
	gen_bpf_jmp_imm(env, BPF_JEQ, &env->regs[BPF_REG_0], 0, env->total_insns - env->generated_insns - 2);

	env->regs[BPF_REG_0].mem_range = size;
	env->regs[BPF_REG_0].map = map->map;

	gen_bpf_mov64_reg(env, &env->regs[BPF_REG_7], &env->regs[BPF_REG_0]);

	env->regs[BPF_REG_7].mutable = false;
	map->ringbuf_reserved = true;

	return true;
}

bool generate_ringbuf_discard(struct environ *env, struct map_info *map)
{
	if (!map->ringbuf_reserved)
		return false;

	gen_bpf_mov64_reg(env, &env->regs[BPF_REG_1], &env->regs[BPF_REG_7]);
	gen_bpf_mov64_imm(env, &env->regs[BPF_REG_2], 0);
	gen_bpf_call_ringbuf_discard(env);

	env->regs[BPF_REG_7].mutable = true;
	map->ringbuf_reserved = false;

	return true;
}

bool generate_rand_map_atomic_op(struct environ *env)
{
	if (!env->conf->try_leak_into_mem)
		return false;

	if (!env->conf->alu_atomic_ops_len)
		return false;

	struct bpf_reg *dst = get_rand_reg(env, is_enabled, is_init, is_not_ptr_to_ctx, NULL);
	struct bpf_reg *src = get_rand_reg(env, is_enabled, is_init, NULL);

	if (!dst || !src)
		return false;

	int32_t atomic_op = env->conf->alu_atomic_ops[rand() % env->conf->alu_atomic_ops_len];

	/* possibly align */
	if (env->conf->stack_align)
		gen_bpf_atomic_op(env, (rand() % 2 ? BPF_W : BPF_DW), atomic_op, dst, src, rand_between(env->conf->imm32_min, env->conf->imm32_max));

	return true;
}

void generate_prog_footer(struct environ *env)
{
	for (size_t idx = 0; idx < env->maps_len; idx++) {
		if (env->maps[idx].ringbuf_reserved)
			generate_ringbuf_discard(env, &env->maps[idx]);
	}

	gen_bpf_mov64_imm(env, &env->regs[BPF_REG_0], 0);
	gen_bpf_exit_insn(env);
}

void generate_prog_header(struct environ *env)
{
	/* mov r1 ctx to r9, used later for BPF_LD_ABS skb data loading */
	gen_bpf_mov64_reg(env, &env->regs[BPF_REG_9], &env->regs[BPF_REG_1]);
	/* r9 is not mutable anymore, can't lose context */
	env->regs[BPF_REG_9].mutable = false;
}

int generate(struct environ *env)
{
	setup(env);

	env->total_insns = rand_between(env->conf->min_insns, env->conf->max_insns);
	env->insns = malloc(sizeof(struct bpf_insn) * (env->total_insns + 1));

	generate_prog_header(env);

	do {
		env->conf->insns_types[rand() % env->conf->insns_types_len](env);
	} while (env->generated_insns < env->total_insns - get_req_footer_space(env));

	generate_prog_footer(env);

	return env->generated_insns;
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

	for (size_t idx = 0; idx < env->maps_len; idx++) {
		memset(&env->maps[idx].ops, 0, sizeof(struct map_ops));
		env->maps[idx].ringbuf_reserved = false;
	}

  for (size_t idx = 0; idx < MAX_BPF_STACK; idx++) {
    env->stack[idx / 8].slot_type[idx % 8] = STACK_INVALID;
  }
}

size_t get_rand_op(struct environ *env)
{
	return env->conf->alu_scal_ops[rand() % env->conf->alu_scal_ops_len];
}

size_t get_rand_op_ptr(struct environ *env)
{
	return (rand() % 2 ? BPF_ADD : BPF_SUB);
}

uint8_t get_req_footer_space(struct environ *env)
{
	/* mov and exit */
	uint8_t required_space = 2;

	for (uint8_t idx = 0; idx < env->maps_len; idx++) {
		struct map_info *map = &env->maps[idx];
		if (map->ringbuf_reserved)
			required_space += 3;
	}

	return required_space;
}

bool has_insn_space(struct environ *env, uint16_t insns)
{
	return ((int64_t) env->generated_insns < env->total_insns - get_req_footer_space(env) - insns);
}
