#include "debug.h"
#include "gen.h"
#include "helpers.h"
#include "linux/bpf.h"
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

/* BEGIN INSN HANDLERS */
void check_insn_buf(struct environ *env, const char *insn)
{
	if (env->generated_insns + 1 > env->total_insns)
		_abort("%s overflows insn buf", insn);
}

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
	check_insn_buf(env, "BPF_EXIT_INSN");

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns, INSN_STR_LEN, "BPF_EXIT_INSN()");
	env->insns[env->generated_insns++] = BPF_EXIT_INSN();
}

void gen_bpf_alu64_reg(struct environ *env, uint8_t op, struct bpf_reg *dst, struct bpf_reg *src)
{
	check_insn_buf(env, "BPF_ALU64_REG");

	if (!check_reg(src, is_init, is_enabled, NULL))
		_abort("BPF_ALU64_REG src reg %d invalid", src->idx);

	if (!check_reg(dst, is_init, is_enabled, is_mutable, NULL))
		_abort("BPF_ALU64_REG dst reg %d invalid", dst->idx);

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns, INSN_STR_LEN, "BPF_ALU64_REG(0x%hhx, 0x%hhx, 0x%hhx)", op, dst->idx,
			 src->idx);

	dst->is_known = (dst->is_known && src->is_known);
	env->insns[env->generated_insns++] = BPF_ALU64_REG(op, dst->idx, src->idx);
}

void gen_bpf_alu32_reg(struct environ *env, uint8_t op, struct bpf_reg *dst, struct bpf_reg *src)
{
	check_insn_buf(env, "BPF_ALU32_REG");

	if (!check_reg(src, is_init, is_enabled, NULL))
		_abort("BPF_ALU32_REG src reg %d invalid", src->idx);

	if (!check_reg(dst, is_init, is_enabled, is_mutable, NULL))
		_abort("BPF_ALU32_REG dst reg %d invalid", dst->idx);

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns, INSN_STR_LEN, "BPF_ALU32_REG(0x%hhx, 0x%hhx, 0x%hhx)", op, dst->idx,
			 src->idx);

	dst->is_known = (dst->is_known && src->is_known);
	env->insns[env->generated_insns++] = BPF_ALU32_REG(op, dst->idx, src->idx);
}

void gen_bpf_alu64_imm(struct environ *env, uint8_t op, struct bpf_reg *dst, int32_t imm)
{
	check_insn_buf(env, "BPF_ALU64_IMM");

	if (!check_reg(dst, is_init, is_enabled, is_mutable, NULL))
		_abort("BPF_ALU64_IMM dst reg %d invalid", dst->idx);

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns, INSN_STR_LEN, "BPF_ALU64_IMM(0x%hhx, 0x%hhx, 0x%x)", op, dst->idx, imm);
	env->insns[env->generated_insns++] = BPF_ALU64_IMM(op, dst->idx, imm);
}

void gen_bpf_alu32_imm(struct environ *env, uint8_t op, struct bpf_reg *dst, int32_t imm)
{
	check_insn_buf(env, "BPF_ALU32_IMM");

	if (!check_reg(dst, is_init, is_enabled, is_mutable, NULL))
		_abort("BPF_ALU32_IMM dst reg %d invalid", dst->idx);

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns, INSN_STR_LEN, "BPF_ALU32_IMM(0x%hhx, 0x%hhx, 0x%x)", op, dst->idx, imm);
	env->insns[env->generated_insns++] = BPF_ALU32_IMM(op, dst->idx, imm);
}

void gen_bpf_endian(struct environ *env, uint8_t type, struct bpf_reg *dst, int32_t len)
{
	check_insn_buf(env, "BPF_ENDIAN");

	if (!check_reg(dst, is_init, is_enabled, is_mutable, NULL))
		_abort("BPF_ENDIAN dst reg %d invalid", dst->idx);

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns, INSN_STR_LEN, "BPF_ENDIAN(0x%hhx, 0x%x)", dst->idx, len);
	env->insns[env->generated_insns++] = BPF_ENDIAN(type, dst->idx, len);
}

void gen_bpf_mov64_reg(struct environ *env, struct bpf_reg *dst, struct bpf_reg *src)
{
	check_insn_buf(env, "BPF_MOV64_REG");

	if (!check_reg(src, is_init, is_enabled, NULL))
		_abort("BPF_MOV64_REG src reg %d invalid", src->idx);

	if (!check_reg(dst, is_enabled, is_mutable, NULL))
		_abort("BPF_MOV64_REG dst reg %d invalid", dst->idx);

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns, INSN_STR_LEN, "BPF_MOV64_REG(0x%hhx, 0x%hhx)", dst->idx, src->idx);

	dst->reg_type = src->reg_type;
	dst->is_known = src->is_known;
	dst->mem_range = src->mem_range;
	dst->map = src->map;
	env->insns[env->generated_insns++] = BPF_MOV64_REG(dst->idx, src->idx);
}
void gen_bpf_mov32_reg(struct environ *env, struct bpf_reg *dst, struct bpf_reg *src)
{
	check_insn_buf(env, "BPF_MOV32_REG");

	if (!check_reg(src, is_init, is_enabled, NULL))
		_abort("BPF_MOV32_REG src reg %d invalid", src->idx);

	if (!check_reg(dst, is_enabled, is_mutable, NULL))
		_abort("BPF_MOV32_REG dst reg %d invalid", dst->idx);

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns, INSN_STR_LEN, "BPF_MOV32_REG(0x%hhx, 0x%hhx)", dst->idx, src->idx);

	dst->reg_type = src->reg_type;
	dst->is_known = src->is_known;
	dst->mem_range = src->mem_range;
	dst->map = src->map;
	env->insns[env->generated_insns++] = BPF_MOV64_REG(dst->idx, src->idx);
}
void gen_bpf_mov64_imm(struct environ *env, struct bpf_reg *dst, int32_t imm)
{
	check_insn_buf(env, "BPF_MOV64_IMM");

	if (!check_reg(dst, is_enabled, is_mutable, NULL))
		_abort("BPF_MOV64_IMM dst reg %d invalid", dst->idx);

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns, INSN_STR_LEN, "BPF_MOV64_IMM(0x%hhx, 0x%x)", dst->idx, imm);

	dst->reg_type = SCALAR_VALUE;
	dst->is_known = true;
	env->insns[env->generated_insns++] = BPF_MOV64_IMM(dst->idx, imm);
}
void gen_bpf_mov32_imm(struct environ *env, struct bpf_reg *dst, int32_t imm)
{
	check_insn_buf(env, "BPF_MOV32_IMM");

	if (!check_reg(dst, is_enabled, is_mutable, NULL))
		_abort("BPF_MOV32_IMM dst reg %d invalid", dst->idx);

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns, INSN_STR_LEN, "BPF_MOV32_IMM(0x%hhx, 0x%x)", dst->idx, imm);

	dst->reg_type = SCALAR_VALUE;
	dst->is_known = true;
	env->insns[env->generated_insns++] = BPF_MOV32_IMM(dst->idx, imm);
}

/* Special form of mov32, used for doing explicit zero extension on dst. */
void gen_bpf_zext_reg(struct environ *env, struct bpf_reg *dst)
{
	check_insn_buf(env, "BPF_ZEXT_REG");

	if (!check_reg(dst, is_init, is_enabled, is_mutable, NULL))
		_abort("BPF_ZEXT_REG dst reg %d invalid", dst->idx);

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns, INSN_STR_LEN, "BPF_ZEXT_REG(0x%hhx)", dst->idx);

	env->insns[env->generated_insns++] = BPF_ZEXT_REG(dst->idx);
}

/* Direct packet access, R0 = *(uint *) (skb->data + imm32) */
void gen_bpf_ld_abs(struct environ *env, uint8_t size, int32_t imm)
{
	check_insn_buf(env, "BPF_LD_ABS");

	if (imm > env->conf->pkt_len)
		_abort("invalid read from __sk_buff (%d > %u)", imm, env->conf->pkt_len);

	__mark_reg_unknown(env, &env->regs[BPF_REG_0]);
	mark_regs_not_init_call(env);

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns, INSN_STR_LEN, "BPF_LD_ABS(0x%hhx, 0x%x)", size, imm);

	env->insns[env->generated_insns++] = BPF_LD_ABS(size, imm);
}

void gen_bpf_ld_imm64_raw(struct environ *env, struct bpf_reg *dst, struct bpf_reg *src, int64_t imm)
{
	check_insn_buf(env, "BPF_LD_IMM64_RAW");

	if (!check_reg(dst, is_enabled, is_mutable, NULL))
		_abort("BPF_LD_IMM64_RAW dst reg %d invalid", dst->idx);

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns, INSN_STR_LEN, "BPF_LD_IMM64_RAW(0x%hhx, 0x%hhx, 0x%lx)", dst->idx,
			 src->idx, imm);

	env->insns[env->generated_insns++] = BPF_LD_IMM64_RAW(dst->idx, src->idx, imm);

	check_insn_buf(env, "BPF_LD_IMM64_RAW (ext)");
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

/* Conditional jumps against immediates, if (dst_reg 'op' imm32) goto pc + off16 */
void gen_bpf_jmp_imm(struct environ *env, uint8_t op, struct bpf_reg *dst, int32_t imm, int32_t off)
{
	check_insn_buf(env, "BPF_JMP_IMM");

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns, INSN_STR_LEN, "BPF_JMP_IMM(0x%hhx, 0x%hhx, 0x%x, 0x%x)", op, dst->idx,
			 imm, off);
	env->insns[env->generated_insns++] = BPF_JMP_IMM(op, dst->idx, imm, off);
}

/* Memory store, *(uint *) (dst_reg + off16) = src_reg */
void gen_bpf_stx_mem(struct environ *env, uint8_t size, struct bpf_reg *dst, struct bpf_reg *src, int32_t off)
{
	check_insn_buf(env, "BPF_STX_MEM");

	if (!check_reg(src, is_init, is_enabled, NULL))
		_abort("BPF_STX_MEM src reg %d invalid", src->idx);

	if (!check_reg(dst, is_init, is_enabled, NULL))
		_abort("BPF_STX_MEM dst reg %d invalid", dst->idx);

	if (dst->reg_type == PTR_TO_STACK) {

		uint8_t slot_type = src->reg_type == SCALAR_VALUE ? STACK_MISC : STACK_SPILL;
		int slot = -off - 1;
		int spi = slot / BPF_REG_SIZE;
		for (size_t i = 0; i < (size_t) byte_size(size); i++) {
			env->stack[spi].slot_type[(slot - i) % BPF_REG_SIZE] = slot_type;
		}
	}

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns, INSN_STR_LEN, "BPF_STX_MEM(0x%hhx, 0x%hhx, 0x%hhx, 0x%x)", size, dst->idx,
			 src->idx, off);
	env->insns[env->generated_insns++] = BPF_STX_MEM(size, dst->idx, src->idx, off);
}

/* Memory load, dst_reg = *(uint *) (src_reg + off16) */
void gen_bpf_ldx_mem(struct environ *env, uint8_t size, struct bpf_reg *dst, struct bpf_reg *src, int32_t off)
{
	check_insn_buf(env, "BPF_LDX_MEM");

	if (!check_reg(src, is_init, is_enabled, NULL))
		_abort("BPF_LDX_MEM src reg %d invalid", src->idx);

	if (!check_reg(src, is_init, is_enabled, NULL))
		_abort("BPF_LDX_MEM dst reg %d invalid", dst->idx);

	__mark_reg_unknown(env, dst);

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns, INSN_STR_LEN, "BPF_LDX_MEM(0x%hhx, 0x%hhx, 0x%hhx, 0x%x)", size, dst->idx,
			 src->idx, off);
	env->insns[env->generated_insns++] = BPF_LDX_MEM(size, dst->idx, src->idx, off);
}

void gen_bpf_call_map_update_elem(struct environ *env)
{
	check_insn_buf(env, "call to map_update_elem");

	__mark_reg_unknown(env, &env->regs[BPF_REG_0]);
	mark_regs_not_init_call(env);

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns, INSN_STR_LEN, "call map_update_elem");
	env->insns[env->generated_insns++] = BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_update_elem);
}

void gen_bpf_call_map_lookup_elem(struct environ *env)
{
	check_insn_buf(env, "call to map_lookup_elem");

	env->regs[BPF_REG_0].reg_type = PTR_TO_MAP_VALUE;
	mark_regs_not_init_call(env);

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns, INSN_STR_LEN, "call map_lookup_elem");
	env->insns[env->generated_insns++] = BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem);
}

void gen_bpf_call_map_delete_elem(struct environ *env)
{
	check_insn_buf(env, "call to map_delete_elem");

	__mark_reg_unknown(env, &env->regs[BPF_REG_0]);
	mark_regs_not_init_call(env);

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns, INSN_STR_LEN, "call map_delete_elem");
	env->insns[env->generated_insns++] = BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_delete_elem);
}

void gen_bpf_call_get_prandom_u32(struct environ *env)
{
	check_insn_buf(env, "call to get_prandom_u32");

	__mark_reg_unknown(env, &env->regs[BPF_REG_0]);
	mark_regs_not_init_call(env);

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns, INSN_STR_LEN, "call get_prandom_u32");
	env->insns[env->generated_insns++] = BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_get_prandom_u32);
}

void gen_bpf_call_ringbuf_reserve(struct environ *env)
{
	check_insn_buf(env, "call to bpf_ringbuf_reserve");

	__mark_reg_unknown(env, &env->regs[BPF_REG_0]);
	env->regs[BPF_REG_0].reg_type = PTR_TO_MEM;
	mark_regs_not_init_call(env);

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns, INSN_STR_LEN, "call bpf_ringbuf_reserve");
	env->insns[env->generated_insns++] = BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_ringbuf_reserve);
}

void gen_bpf_call_ringbuf_output(struct environ *env)
{
	check_insn_buf(env, "call to bpf_ringbuf_output");

	__mark_reg_unknown(env, &env->regs[BPF_REG_0]);
	mark_regs_not_init_call(env);

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns, INSN_STR_LEN, "call bpf_ringbuf_output");
	env->insns[env->generated_insns++] = BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_ringbuf_output);
}

void gen_bpf_call_ringbuf_submit(struct environ *env)
{
	check_insn_buf(env, "call to bpf_ringbuf_submit");

	__mark_reg_unknown(env, &env->regs[BPF_REG_0]);
	mark_regs_not_init_call(env);

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns, INSN_STR_LEN, "call bpf_ringbuf_submit");
	env->insns[env->generated_insns++] = BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_ringbuf_submit);
}

void gen_bpf_call_ringbuf_discard(struct environ *env)
{
	check_insn_buf(env, "call to bpf_ringbuf_discard");

	__mark_reg_unknown(env, &env->regs[BPF_REG_0]);
	for (uint8_t idx = 0; idx < __MAX_BPF_REG; idx++)
		env->regs[idx].reg_type = NOT_INIT;

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns, INSN_STR_LEN, "call bpf_ringbuf_discard");
	env->insns[env->generated_insns++] = BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_ringbuf_discard);
}

void gen_bpf_atomic_op(struct environ *env, uint8_t size, uint8_t op, struct bpf_reg *dst, struct bpf_reg *src, int32_t off)
{
	check_insn_buf(env, "BPF_ATOMIC_OP");

	if (!check_reg(src, is_init, is_enabled, NULL))
		_abort("BPF_ATOMIC_OP dst reg %d invalid", dst->idx);

	if (!check_reg(dst, is_init, is_enabled, NULL))
		_abort("BPF_ATOMIC_OP dst reg %d invalid", dst->idx);

	snprintf((char *) env->insns_str + INSN_STR_LEN * env->generated_insns, INSN_STR_LEN, "BPF_ATOMIC_OP(0x%hhx, 0x%hhx, 0x%hhx, 0x%hhx, 0x%x)", size,
			 op, dst->idx, src->idx, off);

	dst->is_known = (dst->is_known && src->is_known);
	env->insns[env->generated_insns++] = BPF_ATOMIC_OP(size, op, dst->idx, src->idx, off);
}

/* END INSN HANDLERS */
