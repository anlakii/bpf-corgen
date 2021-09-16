#ifndef __CONFIG_H
#define __CONFIG_H

#include <linux/filter.h>
#include <linux/bpf.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
/* uhh fix */
struct environ;
struct bpf_reg;

struct config {
	size_t min_insns;
	size_t max_insns;

	struct bpf_map_def *maps;
	size_t maps_len;

	uint8_t *alu_scal_ops;
	uint8_t alu_scal_ops_len;

	uint16_t *alu_atomic_ops;
	uint16_t alu_atomic_ops_len;

	bool debug_valid;
	bool debug_invalid;
	bool try_leak_into_map;
	bool try_leak_into_mem;
	bool chaos_mode;
	bool stack_align;
	uint32_t reg_bind_range;
	uint32_t pkt_len;
	int32_t imm32_min;
	int32_t imm32_max;
	uint16_t stack_size;

	void (**alu_reg_insns)(struct environ *, uint8_t, struct bpf_reg *, struct bpf_reg *);
	uint8_t alu_reg_insns_len;
	void (**alu_imm_insns)(struct environ *, uint8_t, struct bpf_reg *, int32_t);
	uint8_t alu_imm_insns_len;
	void (**mov_reg_insns)(struct environ *, struct bpf_reg *, struct bpf_reg *);
	uint8_t mov_reg_insns_len;
	void (**mov_imm_insns)(struct environ *, struct bpf_reg *, int32_t);
	uint8_t mov_imm_insns_len;
};

void parse_config(char *, struct config *);

#endif
