#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/capability.h>
#include "gen.h"
#include "helpers.h"
#include "loader.h"
#include "debug.h"
#include "config.h"

struct opts {
	char *config_file;
	bool debug_valid;
	bool debug_invalid;
};

void print_help(char **argv)
{
	printf(
		"Usage:\n %s [options] \n\n"
		"Options:\n"
		"  -c, --config	<file>           JSON config to use\n"
		"  -g, --debug   <valid|invalid>  debug switch\n"
		"\n"
		"  -h, --help                   display this help and "
		"exit\n",
		argv[0]);
}

struct opts parse_opts(int argc, char **argv)
{
	struct option long_opts[] = {{"config", required_argument, NULL, 'c'},
								 {0, 0, 0, 0}};
	struct opts opts = {0};

	int opt;
	int lopt_index = 0;
	while ((opt = getopt_long(argc, argv, "c:g:", long_opts, &lopt_index)) != -1) {
		switch (opt) {
			case 'c':
				opts.config_file = strdup(optarg);
				break;
			case 'g':
				if (!strcmp(optarg, "valid"))
					opts.debug_valid = true;
				else if (!strcmp(optarg, "invalid"))
					opts.debug_invalid = true;
				else
					_abort("unknown debug option");
				_error("%s", optarg);
				break;
			case 'h':
				print_help(argv);
				exit(EXIT_SUCCESS);
				break;
			default:
				print_help(argv);
				exit(EXIT_SUCCESS);
				break;
		}
	}
	return opts;
}

void setup_env(struct environ *env, int argc, char **argv)
{

	struct opts opts = parse_opts(argc, argv);
	if (!opts.config_file) {
		print_help(argv);
		exit(EXIT_SUCCESS);
	} else
		_log("using config -- %s", opts.config_file);

	struct config *conf = calloc(1, sizeof(struct config));
	parse_config(opts.config_file, conf);

	env->conf = conf;
	load_bpf_maps(env);
	env->running = true;
	env->conf->debug_valid = opts.debug_valid;
	env->conf->debug_invalid = opts.debug_invalid;

	cap_t cap = cap_get_proc();
	cap_flag_value_t cap_sys_admin = 0;
	cap_flag_value_t cap_perfmon = 0;
	cap_get_flag(cap, CAP_SYS_ADMIN, CAP_EFFECTIVE, &cap_sys_admin);
	cap_get_flag(cap, CAP_PERFMON, CAP_EFFECTIVE, &cap_perfmon);
	env->privileged = cap_sys_admin | cap_perfmon;
}

int main(int argc, char **argv)
{
	size_t seed = time(0) ^ getpid();
	srand(seed);
	size_t success = 0;
	float avg_insn = 0;
	size_t max_insn = 0,
		   total_insns = 0,
		   prog_num = 1;

	struct timeval stop, start;

	struct environ env = {0};
	setup_env(&env, argc, argv);

	_log("starting fuzzer (%s) -- min insns %zu, max insns: %zu // seed: %zu",
		 env.privileged ? "privileged" : "unprivileged",
		 env.conf->min_insns,
		 env.conf->max_insns,
		 seed);
	gettimeofday(&start, NULL);
	while (env.running) {

		env.insns_str = malloc(env.conf->max_insns * (INSN_STR_LEN + 1) * sizeof(char));
		if (!env.insns_str)
			_abort("failed to alloc insns str buf");

		generate(&env);

		if (run_bpf_prog(&env)) {
			success++;
			if (env.generated_insns > max_insn)
				max_insn = env.generated_insns;

			total_insns += env.generated_insns;

			avg_insn = (float) total_insns / success;
			gettimeofday(&stop, NULL);
			_progress("%.2f%% (avg: %zu, max: %zu) %zu/sec -- total %zu // valid %zu -- %zu insn",
					  ((float) success / prog_num) * 100,
					  (size_t) avg_insn,
					  max_insn,
					  (size_t) ((float) prog_num / (((stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec)) * 1000000),
					  prog_num,
					  success,
					  env.generated_insns);

			if (env.conf->debug_valid) {
				for (int i = 0; i < env.generated_insns; i++) {
					disas_insn(env.insns[i]);
					_log("%s", env.insns_str + INSN_STR_LEN * i);
				}
			}
		} else if (env.conf->debug_invalid) {
			for (int i = 0; i < env.generated_insns; i++) {
				disas_insn(env.insns[i]);
				_log("%s", env.insns_str + INSN_STR_LEN * i);
			}
		}

		prog_num++;
		free(env.insns_str);
		env.insns_str = NULL;
		free(env.insns);
		env.insns = NULL;
		env.generated_insns = 0;
	}
	return 0;
}
