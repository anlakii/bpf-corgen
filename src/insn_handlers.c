#include <linux/filter.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include "linux/bpf.h"
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

/* BEGIN INSN HANDLERS */

void mark_regs_not_init_call(struct environ *env)
{
	env->regs[BPF_REG_1].reg_type = NOT_INIT;
	env->regs[BPF_REG_2].reg_type = NOT_INIT;
	env->regs[BPF_REG_3].reg_type = NOT_INIT;
	env->regs[BPF_REG_4].reg_type = NOT_INIT;
	env->regs[BPF_REG_5].reg_type = NOT_INIT;
}

void __mark_reg_unknown(struct environ *env, struct bpf_reg *reg)
{
	reg->reg_type = SCALAR_VALUE;
	reg->is_known = false;
}

void gen_bpf_exit_insn(struct environ *env)
{
	if (env->generated_insns + 1 > env->total_insns)
		_abort("BPF_EXIT_INSN overflows insn buf");

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns,
			 INSN_STR_LEN,
			 "BPF_EXIT_INSN()");

	env->insns[env->generated_insns++] = BPF_EXIT_INSN();
}

void gen_bpf_alu64_reg(struct environ *env, uint8_t op, struct bpf_reg *dst, struct bpf_reg *src)
{
	if (env->generated_insns + 1 > env->total_insns)
		_abort("BPF_ALU64_REG overflows insn buf");

	if (src->reg_type == NOT_INIT)
		_abort("BPF_ALU64_REG src %d not readable", src->idx);

	if (!dst->mutable)
		_abort("BPF_ALU64_REG dst %d not mutable", dst->idx);

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns,
			 INSN_STR_LEN,
			 "BPF_ALU64_REG(%hhx, %hhx, %hhx)",
			 op, dst->idx, src->idx);

	dst->is_known = (dst->is_known && src->is_known);
	env->insns[env->generated_insns++] = BPF_ALU64_REG(op, dst->idx, src->idx);
}

void gen_bpf_alu32_reg(struct environ *env, uint8_t op, struct bpf_reg *dst, struct bpf_reg *src)
{
	if (env->generated_insns + 1 > env->total_insns)
		_abort("BPF_ALU32_REG overflows insn buf");

	if (src->reg_type == NOT_INIT)
		_abort("BPF_ALU32_REG src %d not readable", src->idx);

	if (!dst->mutable)
		_abort("BPF_ALU32_REG dst %d not mutable", dst->idx);

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns,
			 INSN_STR_LEN,
			 "BPF_ALU32_REG(%hhx, %hhx, %hhx)",
			 op, dst->idx, src->idx);

	dst->is_known = (dst->is_known && src->is_known);
	env->insns[env->generated_insns++] = BPF_ALU32_REG(op, dst->idx, src->idx);
}

void gen_bpf_alu64_imm(struct environ *env, uint8_t op, struct bpf_reg *dst, int32_t imm)
{
	if (env->generated_insns + 1 > env->total_insns)
		_abort("BPF_ALU64_IMM overflows insn buf");

	if (!dst->mutable)
		_abort("BPF_ALU64_IMM dst %d not mutable", dst->idx);

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns,
			 INSN_STR_LEN,
			 "BPF_ALU64_IMM(%hhx, %hhx, %d)",
			 op, dst->idx, imm);

	env->insns[env->generated_insns++] = BPF_ALU64_IMM(op, dst->idx, imm);
}

void gen_bpf_alu32_imm(struct environ *env, uint8_t op, struct bpf_reg *dst, int32_t imm)
{
	if (env->generated_insns + 1 > env->total_insns)
		_abort("BPF_ALU32_IMM overflows insn buf");

	if (!dst->mutable)
		_abort("BPF_ALU32_IMM dst %d not mutable", dst->idx);

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns,
			 INSN_STR_LEN,
			 "BPF_ALU32_IMM(%hhx, %hhx, %d)",
			 op, dst->idx, imm);

	env->insns[env->generated_insns++] = BPF_ALU32_IMM(op, dst->idx, imm);
}

void gen_bpf_endian(struct environ *env, uint8_t type, struct bpf_reg *dst, int32_t len)
{
	if (env->generated_insns + 1 > env->total_insns)
		_abort("BPF_ENDIAN overflows insn buf");

	env->insns[env->generated_insns++] = BPF_ENDIAN(type, dst->idx, len);
}

void gen_bpf_mov64_reg(struct environ *env, struct bpf_reg *dst, struct bpf_reg *src)
{
	if (env->generated_insns + 1 > env->total_insns)
		_abort("BPF_MOV64_REG overflows insn buf");

	if (src->reg_type == NOT_INIT)
		_abort("BPF_MOV64_REG src %d not readable", src->idx);

	if (!dst->mutable)
		_abort("BPF_MOV64_REG dst %d not mutable", dst->idx);

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns,
			 INSN_STR_LEN,
			 "BPF_MOV64_REG(%hhx, %hhx)",
			 dst->idx, src->idx);

	dst->reg_type = src->reg_type;
	dst->is_known = src->is_known;
	env->insns[env->generated_insns++] = BPF_MOV64_REG(dst->idx, src->idx);
}
void gen_bpf_mov32_reg(struct environ *env, struct bpf_reg *dst, struct bpf_reg *src)
{
	if (env->generated_insns + 1 > env->total_insns)
		_abort("BPF_MOV32_REG overflows insn buf");

	if (src->reg_type == NOT_INIT)
		_abort("BPF_MOV64_REG src %d not readable", src->idx);

	if (!dst->mutable)
		_abort("BPF_MOV64_REG dst %d not mutable", dst->idx);

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns,
			 INSN_STR_LEN,
			 "BPF_MOV32_REG(%hhx, %hhx)",
			 dst->idx, src->idx);

	dst->reg_type = src->reg_type;
	dst->is_known = src->is_known;
	env->insns[env->generated_insns++] = BPF_MOV64_REG(dst->idx, src->idx);
}
void gen_bpf_mov64_imm(struct environ *env, struct bpf_reg *dst, int32_t imm)
{
	if (env->generated_insns + 1 > env->total_insns)
		_abort("BPF_MOV64_IMM overflows insn buf");

	if (!dst->mutable)
		_abort("BPF_MOV64_REG dst %d not mutable", dst->idx);

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns,
			 INSN_STR_LEN,
			 "BPF_MOV64_IMM(%hhx, %d)",
			 dst->idx, imm);

	dst->reg_type = SCALAR_VALUE;
	dst->is_known = true;
	env->insns[env->generated_insns++] = BPF_MOV64_IMM(dst->idx, imm);
}
void gen_bpf_mov32_imm(struct environ *env, struct bpf_reg *dst, int32_t imm)
{
	if (env->generated_insns + 1 > env->total_insns)
		_abort("BPF_MOV32_IMM overflows insn buf");

	if (!dst->mutable)
		_abort("BPF_MOV64_REG dst %d not mutable", dst->idx);

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns,
			 INSN_STR_LEN,
			 "BPF_MOV32_IMM(%hhx, %d)",
			 dst->idx, imm);

	dst->reg_type = SCALAR_VALUE;
	env->insns[env->generated_insns++] = BPF_MOV32_IMM(dst->idx, imm);
}

void gen_bpf_zext_reg(struct environ *env, struct bpf_reg *dst)
{
	if (env->generated_insns + 1 > env->total_insns)
		_abort("BPF_ZEXT_REG overflows insn buf");

	if (!dst->mutable)
		_abort("BPF_ZEXT_REG dst %d not mutable", dst->idx);

	if (dst->reg_type == NOT_INIT)
		_abort("BPF_ZEXT_REG dst %d not readable", dst->idx);

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns,
			 INSN_STR_LEN,
			 "BPF_ZEXT_REG(%hhx)",
			 dst->idx);

	env->insns[env->generated_insns++] = BPF_ZEXT_REG(dst->idx);
}

void gen_bpf_ld_abs(struct environ *env, uint8_t size, int32_t imm)
{
	if (env->generated_insns + 1 > env->total_insns)
		_abort("BPF_LD_ABS overflows insn buf");

	if (imm > env->conf->pkt_len) // FIXME
		_abort("invalid read from __sk_buff (%d > %u)", imm, env->conf->pkt_len);

	__mark_reg_unknown(env, &env->regs[BPF_REG_0]);
	mark_regs_not_init_call(env);

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns,
			 INSN_STR_LEN,
			 "BPF_LD_ABS(%hhx, %dd)",
			 size, imm);

	env->insns[env->generated_insns++] = BPF_LD_ABS(size, imm);
}

void gen_bpf_ld_imm64_raw(struct environ *env, struct bpf_reg *dst, struct bpf_reg *src, int64_t imm)
{
	if (env->generated_insns + 2 > env->total_insns)
		_abort("BPF_LD_IMM64_RAW overflows insn buf");

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns,
			 INSN_STR_LEN,
			 "BPF_LD_IMM64_RAW(%hhx, %hhx, %ld)",
			 dst->idx, src->idx, imm);

	env->insns[env->generated_insns++] = BPF_LD_IMM64_RAW(dst->idx, src->idx, imm);
	env->insns[env->generated_insns++] = (struct bpf_insn){0, 0, 0, 0, ((uint64_t) imm) >> 32};
}
void gen_bpf_ld_imm64(struct environ *env, struct bpf_reg *dst, int64_t imm)
{
	gen_bpf_ld_imm64_raw(env, dst, &env->regs[0], imm);
	dst->reg_type = SCALAR_VALUE;
	dst->is_known = true;
}
void gen_bpf_ld_map_fd(struct environ *env, struct bpf_reg *dst, int32_t fd)
{
	gen_bpf_ld_imm64_raw(env, dst, &env->regs[BPF_PSEUDO_MAP_FD], fd);
	__mark_reg_unknown(env, dst);
	env->regs[BPF_PSEUDO_MAP_FD].reg_type = CONST_PTR_TO_MAP;
}

void gen_bpf_jmp_imm(struct environ *env, uint8_t op, struct bpf_reg *dst, int32_t imm, int32_t off)
{
	if (env->generated_insns + 1 > env->total_insns)
		_abort("BPF_JMP_IMM overflows insn buf");

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns,
			 INSN_STR_LEN,
			 "BPF_JMP_IMM(%hhx, %hhx, %d, %d)",
			 op, dst->idx, imm, off);
	env->insns[env->generated_insns++] = BPF_JMP_IMM(op, dst->idx, imm, off);
}

void gen_bpf_stx_mem(struct environ *env, uint8_t size, struct bpf_reg *dst, struct bpf_reg *src, int32_t off)
{
	if (env->generated_insns + 1 > env->total_insns)
		_abort("BPF_STX_MEM overflows insn buf");

	if (dst->reg_type == PTR_TO_STACK) {
		uint8_t slot_type = src->reg_type == SCALAR_VALUE ? STACK_MISC : STACK_SPILL;
		for (size_t i = 0; i < size; i++) {
			if ((-off + i) / 8 >= 64) {
				continue;
			}
			env->stack[(-off + i) / 8].slot_type[i % 8] = slot_type;
		}
	}

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns,
			 INSN_STR_LEN,
			 "BPF_STX_MEM(%hhx, %hhx, %hhx, %d)",
			 size, dst->idx, src->idx, off);
	env->insns[env->generated_insns++] = BPF_STX_MEM(size, dst->idx, src->idx, off);
}

void gen_bpf_call_map_update_elem(struct environ *env)
{
	if (env->generated_insns + 1 > env->total_insns)
		_abort("call to map_update_elem overflows insn buf");

	env->insns[env->generated_insns++] = BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_update_elem);
	__mark_reg_unknown(env, &env->regs[BPF_REG_0]);
	mark_regs_not_init_call(env);

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns,
			 INSN_STR_LEN,
			 "call map_update_elem");
}

void gen_bpf_call_map_lookup_elem(struct environ *env)
{
	if (env->generated_insns + 1 > env->total_insns)
		_abort("call to map_lookup_elem overflows insn buf");

	env->regs[BPF_REG_0].reg_type = PTR_TO_MAP_VALUE;
	mark_regs_not_init_call(env);

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns,
			 INSN_STR_LEN,
			 "call map_lookup_elem");
	env->insns[env->generated_insns++] = BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem);
}

void gen_bpf_call_map_delete_elem(struct environ *env)
{
	if (env->generated_insns + 1 > env->total_insns)
		_abort("call to map_delete_elem overflows insn buf");

	__mark_reg_unknown(env, &env->regs[BPF_REG_0]);
	mark_regs_not_init_call(env);

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns,
			 INSN_STR_LEN,
			 "call map_delete_elem");
	env->insns[env->generated_insns++] = BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_delete_elem);
}

void gen_bpf_call_get_prandom_u32(struct environ *env)
{
	if (env->generated_insns + 1 > env->total_insns)
		_abort("call to get_prandom_u32 overflows insn buf");

	env->regs[BPF_REG_0].reg_type = SCALAR_VALUE;
	__mark_reg_unknown(env, &env->regs[BPF_REG_0]);
	mark_regs_not_init_call(env);

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns,
			 INSN_STR_LEN,
			 "call get_prandom_u32");
	env->insns[env->generated_insns++] = BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_get_prandom_u32);
}

void gen_bpf_atomic_op(struct environ *env, uint8_t size, uint8_t op, struct bpf_reg *dst, struct bpf_reg *src, int32_t off)
{
	if (env->generated_insns + 1 > env->total_insns)
		_abort("BPF_ATOMIC_OP overflows insn buf");

	if (dst->reg_type == NOT_INIT)
		_abort("BPF_ATOMIC_OP dst %d not readable", dst->idx);

	if (src->reg_type == NOT_INIT)
		_abort("BPF_ATOMIC_OP src %d not readable", src->idx);

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns,
			 INSN_STR_LEN,
			 "BPF_ATOMIC_OP(%hhx, %hhx, %hhx, %hhx, %d)",
			 size, op, dst->idx, src->idx, off);

	dst->is_known = (dst->is_known && src->is_known);
	env->insns[env->generated_insns++] = BPF_ATOMIC_OP(size, op, dst->idx, src->idx, off);
}

/* END INSN HANDLERS */
