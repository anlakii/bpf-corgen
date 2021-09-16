#ifndef __INIT_STRUCTS_H
#define __INIT_STRUCTS_H
#include "gen.h"
#include "linux/bpf.h"
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct bpf_reg bpf_regs[] = {
	(struct bpf_reg){
		.idx = BPF_REG_0,
		.mutable = true,
		.enable = true,
		.reg_type = NOT_INIT,
	},
	(struct bpf_reg){
		.idx = BPF_REG_1,
		.mutable = true,
		.enable = true,
		.reg_type = PTR_TO_CTX,
	},
	(struct bpf_reg){
		.idx = BPF_REG_2,
		.mutable = true,
		.enable = true,
		.reg_type = NOT_INIT,
	},
	(struct bpf_reg){
		.idx = BPF_REG_3,
		.mutable = true,
		.enable = true,
		.reg_type = NOT_INIT,
	},
	(struct bpf_reg){
		.idx = BPF_REG_4,
		.mutable = true,
		.enable = true,
		.reg_type = NOT_INIT,
	},
	(struct bpf_reg){
		.idx = BPF_REG_5,
		.mutable = true,
		.enable = true,
		.reg_type = NOT_INIT,
	},
	(struct bpf_reg){
		.idx = BPF_REG_6,
		.mutable = true,
		.enable = true,
		.reg_type = NOT_INIT,
	},
	(struct bpf_reg){
		.idx = BPF_REG_7,
		.mutable = true,
		.enable = true,
		.reg_type = NOT_INIT,
	},
	(struct bpf_reg){
		.idx = BPF_REG_8,
		.mutable = true,
		.enable = true,
		.reg_type = NOT_INIT,
	},
	(struct bpf_reg){
		.idx = BPF_REG_9,
		.mutable = true,
		.enable = true,
		.reg_type = NOT_INIT,
	},
	(struct bpf_reg){
		.idx = BPF_REG_10,
		.mutable = false,
		.enable = false,
		.reg_type = PTR_TO_STACK,
	},
};

uint8_t bpf_mem_size[] = {BPF_B, BPF_H, BPF_W, BPF_DW};

#endif
