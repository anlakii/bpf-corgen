#include "debug.h"
#include <linux/bpf.h>
#include <linux/filter.h>
#include <regex.h>
#include <stddef.h>
#include <stdio.h>

void disas_insn(struct bpf_insn insn)
{
	_log("code: %02x, dst: %02x, src: %02x, off: %04x, imm: %08x", insn.code, insn.dst_reg, insn.src_reg, insn.off, insn.imm);
}

int64_t rand_between(int64_t min, int64_t max)
{
	return rand() % (max - min + 1) + min;
}

int64_t rand64()
{
	return ((int64_t) rand() << 32) | ((int64_t) rand());
}

// Taken from:
// https://stackoverflow.com/questions/8044081/how-to-do-regex-string-replacements-in-pure-c
int regex_replace(char **str, const char *pattern, const char *replace)
{
	// replaces regex in pattern with replacement observing capture groups
	// *str MUST be free-able, i.e. obtained by strdup, malloc, ...
	// back references are indicated by char codes 1-31 and none of those chars
	// can be used in the replacement string such as a tab. will not search for
	// matches within replaced text, this will begin searching for the next match
	// after the end of prev match returns:
	//   -1 if pattern cannot be compiled
	//   -2 if count of back references and capture groups don't match
	//   otherwise returns number of matches that were found and replaced
	//
	regex_t reg;
	unsigned int replacements = 0;
	if (!regcomp(&reg, pattern, REG_EXTENDED)) {
		size_t nmatch = reg.re_nsub;
		regmatch_t m[nmatch + 1];
		const char *rpl, *p;
		int br = 0;
		p = replace;
		while (1) {
			while (*++p > 31)
				;
			if (*p)
				br++;
			else
				break;
		}
		if (br != nmatch) {
			regfree(&reg);
			return -2;
		}
		char *new;
		char *search_start = *str;
		while (!regexec(&reg, search_start, nmatch + 1, m, REG_NOTBOL)) {
			new = (char *) malloc(strlen(*str) + strlen(replace));
			if (!new)
				exit(EXIT_FAILURE);
			*new = '\0';
			strncat(new, *str, search_start - *str);
			p = rpl = replace;
			int c;
			strncat(new, search_start, m[0].rm_so); // test before pattern
			for (int k = 0; k < nmatch; k++) {
				while (*++p > 31)
					;
				c = *p;
				strncat(new, rpl, p - rpl);

				strncat(new, search_start + m[c].rm_so, m[c].rm_eo - m[c].rm_so);
				rpl = p++;
			}
			strcat(new, p); // trailing of rpl
			unsigned int new_start_offset = strlen(new);
			strcat(new, search_start + m[0].rm_eo); // trailing text in *str
			free(*str);
			*str = (char *) malloc(strlen(new) + 1);
			strcpy(*str, new);
			search_start = *str + new_start_offset;
			free(new);
			replacements++;
		}
		regfree(&reg);
		// ajust size
		*str = (char *) realloc(*str, strlen(*str) + 1);
		return replacements;
	} else {
		return -1;
	}
}
