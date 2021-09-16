#ifndef __INSN_HANDLERS_H
#define __INSN_HANDLERS_H
#include "gen.h"

void gen_bpf_exit_insn(struct environ *env);
void gen_bpf_alu64_reg(struct environ *env, uint8_t op, struct bpf_reg *dst, struct bpf_reg *src);
void gen_bpf_alu32_reg(struct environ *env, uint8_t op, struct bpf_reg *dst, struct bpf_reg *src);
void gen_bpf_alu64_imm(struct environ *env, uint8_t op, struct bpf_reg *dst, int32_t imm);
void gen_bpf_alu32_imm(struct environ *env, uint8_t op, struct bpf_reg *dst, int32_t imm);
void gen_bpf_endian(struct environ *env, uint8_t type, struct bpf_reg *dst, int32_t len);
void gen_bpf_mov64_reg(struct environ *env, struct bpf_reg *dst, struct bpf_reg *src);
void gen_bpf_mov32_reg(struct environ *env, struct bpf_reg *dst, struct bpf_reg *src);
void gen_bpf_mov64_imm(struct environ *env, struct bpf_reg *dst, int32_t imm);
void gen_bpf_mov32_imm(struct environ *env, struct bpf_reg *dst, int32_t imm);
void gen_bpf_zext_reg(struct environ *env, struct bpf_reg *dst);
void gen_bpf_ld_abs(struct environ *env, uint8_t size, int32_t imm);
void gen_bpf_ld_imm64_raw(struct environ *env, struct bpf_reg *dst, struct bpf_reg *src, int64_t imm);
void gen_bpf_ld_imm64(struct environ *env, struct bpf_reg *dst, int64_t imm);
void gen_bpf_ld_map_fd(struct environ *env, struct bpf_reg *dst, int32_t fd);
void gen_bpf_jmp_imm(struct environ *env, uint8_t op, struct bpf_reg *dst, int32_t imm, int32_t off);
void gen_bpf_stx_mem(struct environ *env, uint8_t size, struct bpf_reg *dst, struct bpf_reg *src, int32_t off);
void gen_bpf_call_map_update_elem(struct environ *env);
void gen_bpf_call_map_lookup_elem(struct environ *env);
void gen_bpf_call_map_delete_elem(struct environ *env);
void gen_bpf_call_get_prandom_u32(struct environ *env);
void gen_bpf_atomic_op(struct environ *env, uint8_t size, int32_t op, struct bpf_reg *dst, struct bpf_reg *src, int32_t off);

#endif
