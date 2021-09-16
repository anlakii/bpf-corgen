#ifndef __HELPERS_H
#define __HELPERS_H 1

#include <linux/filter.h>
#include <linux/bpf.h>
#include <stddef.h>
#include <stdint.h>

#define LEN(x) sizeof(x) / sizeof(x[0])

void disas_insn(struct bpf_insn insn);
int64_t rand64();
int64_t rand_between(int64_t min, int64_t max);

int regex_replace(char **str, const char *pattern, const char *replace);

#endif
