#include "config.h"
#include "debug.h"
#include "gen.h"
#include "insn_handlers.h"
#include <json-c/json.h>
#include <stdbool.h>
#include <stdint.h>

void parse_json(char *json_str, struct config *conf)
{
	json_object *root_jobj;
	json_object *min_insns_jobj;
	json_object *max_insns_jobj;

	root_jobj = json_tokener_parse(json_str);

	if (!root_jobj)
		_abort("input data is not valid JSON");

	if (!json_object_object_get_ex(root_jobj, "min_insns", &min_insns_jobj))
		_abort("key \"min_insns\" not set");

	if (json_object_get_type(min_insns_jobj) != json_type_int)
		_abort("object \"min_insns\" not of int type");

	conf->min_insns = json_object_get_int64(min_insns_jobj);

	if (!json_object_object_get_ex(root_jobj, "max_insns", &max_insns_jobj))
		_abort("key \"max_insns\" not set");

	if (json_object_get_type(max_insns_jobj) != json_type_int)
		_abort("object \"max_insns\" not of int type");

	conf->max_insns = json_object_get_int64(max_insns_jobj);

	parse_alu_scal_ops_json(root_jobj, conf);
	parse_alu_atomic_ops_json(root_jobj, conf);
	parse_maps_json(root_jobj, conf);
	parse_try_leaks(root_jobj, conf);
	parse_alu_insns(root_jobj, conf);
	parse_mov_insns(root_jobj, conf);
	parse_insns_types(root_jobj, conf);
	parse_pkt_len(root_jobj, conf);
	parse_chaos_mode(root_jobj, conf);
	parse_stack_align(root_jobj, conf);
	parse_stack_size(root_jobj, conf);
	parse_imm32_limits(root_jobj, conf);
}

void set_defaults(struct config *conf)
{
	conf->try_leak_into_mem = true;
	conf->try_leak_into_map = true;
	conf->pkt_len = 0x1000;
	conf->chaos_mode = false;
	conf->stack_align = true;
	conf->reg_bind_range = 64;
	conf->stack_size = 128;
	conf->imm32_min = -128;
	conf->imm32_max = 128;
}

void parse_maps_json(json_object *root_jobj, struct config *conf)
{
	json_object *maps_jobj;
	json_object *maps_elem_jobj;
	json_object *maps_elem_map_type_jobj;
	json_object *maps_elem_key_size_jobj;
	json_object *maps_elem_value_size_jobj;
	json_object *maps_elem_max_entries_jobj;
	json_object *maps_elem_bpf_flags_jobj;
	json_object *maps_bpf_flags_elem_jobj;

	if (!json_object_object_get_ex(root_jobj, "maps", &maps_jobj))
		_abort("key \"maps\" not set");

	if (json_object_get_type(maps_jobj) != json_type_array)
		_abort("object \"maps_jobj\": not of array type");

	conf->maps_len = json_object_array_length(maps_jobj);
	if (!conf->maps_len)
		_abort("object \"maps\": array of size zero");

	conf->maps = calloc(conf->maps_len, sizeof(struct bpf_map_def));

	for (size_t idx = 0; idx < conf->maps_len; idx++) {
		maps_elem_jobj = json_object_array_get_idx(maps_jobj, idx);
		if (json_object_get_type(maps_elem_jobj) != json_type_object)
			_abort("object \"maps\": elem not of object type");

		if (!json_object_object_get_ex(maps_elem_jobj, "map_type", &maps_elem_map_type_jobj))
			_abort("object \"maps\": key \"map_type\" not set");

		if (json_object_get_type(maps_elem_map_type_jobj) != json_type_string)
			_abort("object \"maps\": object \"map_type\" not of string type");

		const char *map_type = json_object_get_string(maps_elem_map_type_jobj);

		if (!strcmp(map_type, "BPF_MAP_TYPE_UNSPEC"))
			conf->maps[idx].type = BPF_MAP_TYPE_UNSPEC;
		else if (!strcmp(map_type, "BPF_MAP_TYPE_HASH"))
			conf->maps[idx].type = BPF_MAP_TYPE_HASH;
		else if (!strcmp(map_type, "BPF_MAP_TYPE_ARRAY"))
			conf->maps[idx].type = BPF_MAP_TYPE_ARRAY;
		else if (!strcmp(map_type, "BPF_MAP_TYPE_PROG_ARRAY"))
			conf->maps[idx].type = BPF_MAP_TYPE_PROG_ARRAY;
		else if (!strcmp(map_type, "BPF_MAP_TYPE_PERF_EVENT_ARRAY"))
			conf->maps[idx].type = BPF_MAP_TYPE_PERF_EVENT_ARRAY;
		else if (!strcmp(map_type, "BPF_MAP_TYPE_PERCPU_HASH"))
			conf->maps[idx].type = BPF_MAP_TYPE_PERCPU_HASH;
		else if (!strcmp(map_type, "BPF_MAP_TYPE_PERCPU_ARRAY"))
			conf->maps[idx].type = BPF_MAP_TYPE_PERCPU_ARRAY;
		else if (!strcmp(map_type, "BPF_MAP_TYPE_STACK_TRACE"))
			conf->maps[idx].type = BPF_MAP_TYPE_STACK_TRACE;
		else if (!strcmp(map_type, "BPF_MAP_TYPE_CGROUP_ARRAY"))
			conf->maps[idx].type = BPF_MAP_TYPE_CGROUP_ARRAY;
		else if (!strcmp(map_type, "BPF_MAP_TYPE_LRU_HASH"))
			conf->maps[idx].type = BPF_MAP_TYPE_LRU_HASH;
		else if (!strcmp(map_type, "BPF_MAP_TYPE_LRU_PERCPU_HASH"))
			conf->maps[idx].type = BPF_MAP_TYPE_LRU_PERCPU_HASH;
		else if (!strcmp(map_type, "BPF_MAP_TYPE_LPM_TRIE"))
			conf->maps[idx].type = BPF_MAP_TYPE_LPM_TRIE;
		else if (!strcmp(map_type, "BPF_MAP_TYPE_ARRAY_OF_MAPS"))
			conf->maps[idx].type = BPF_MAP_TYPE_ARRAY_OF_MAPS;
		else if (!strcmp(map_type, "BPF_MAP_TYPE_HASH_OF_MAPS"))
			conf->maps[idx].type = BPF_MAP_TYPE_HASH_OF_MAPS;
		else if (!strcmp(map_type, "BPF_MAP_TYPE_DEVMAP"))
			conf->maps[idx].type = BPF_MAP_TYPE_DEVMAP;
		else if (!strcmp(map_type, "BPF_MAP_TYPE_SOCKMAP"))
			conf->maps[idx].type = BPF_MAP_TYPE_SOCKMAP;
		else if (!strcmp(map_type, "BPF_MAP_TYPE_CPUMAP"))
			conf->maps[idx].type = BPF_MAP_TYPE_CPUMAP;
		else if (!strcmp(map_type, "BPF_MAP_TYPE_XSKMAP"))
			conf->maps[idx].type = BPF_MAP_TYPE_XSKMAP;
		else if (!strcmp(map_type, "BPF_MAP_TYPE_SOCKHASH"))
			conf->maps[idx].type = BPF_MAP_TYPE_SOCKHASH;
		else if (!strcmp(map_type, "BPF_MAP_TYPE_CGROUP_STORAGE"))
			conf->maps[idx].type = BPF_MAP_TYPE_CGROUP_STORAGE;
		else if (!strcmp(map_type, "BPF_MAP_TYPE_REUSEPORT_SOCKARRAY"))
			conf->maps[idx].type = BPF_MAP_TYPE_REUSEPORT_SOCKARRAY;
		else if (!strcmp(map_type, "BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE"))
			conf->maps[idx].type = BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE;
		else if (!strcmp(map_type, "BPF_MAP_TYPE_QUEUE"))
			conf->maps[idx].type = BPF_MAP_TYPE_QUEUE;
		else if (!strcmp(map_type, "BPF_MAP_TYPE_STACK"))
			conf->maps[idx].type = BPF_MAP_TYPE_STACK;
		else if (!strcmp(map_type, "BPF_MAP_TYPE_SK_STORAGE"))
			conf->maps[idx].type = BPF_MAP_TYPE_SK_STORAGE;
		else if (!strcmp(map_type, "BPF_MAP_TYPE_DEVMAP_HASH"))
			conf->maps[idx].type = BPF_MAP_TYPE_DEVMAP_HASH;
		else if (!strcmp(map_type, "BPF_MAP_TYPE_STRUCT_OPS"))
			conf->maps[idx].type = BPF_MAP_TYPE_STRUCT_OPS;
		else if (!strcmp(map_type, "BPF_MAP_TYPE_RINGBUF"))
			conf->maps[idx].type = BPF_MAP_TYPE_RINGBUF;
		else if (!strcmp(map_type, "BPF_MAP_TYPE_INODE_STORAGE"))
			conf->maps[idx].type = BPF_MAP_TYPE_INODE_STORAGE;
		else if (!strcmp(map_type, "BPF_MAP_TYPE_TASK_STORAGE"))
			conf->maps[idx].type = BPF_MAP_TYPE_TASK_STORAGE;
		else
			_abort("object \"maps\": type \"%s\" unsupported", map_type);

		if (!json_object_object_get_ex(maps_elem_jobj, "key_size", &maps_elem_key_size_jobj))
			_abort("object \"maps\": key \"key_size\" not set");

		if (json_object_get_type(maps_elem_key_size_jobj) != json_type_int)
			_abort("object \"maps\": object \"key_size\" not of int type");

		conf->maps[idx].key_size = json_object_get_uint64(maps_elem_key_size_jobj);

		if (!json_object_object_get_ex(maps_elem_jobj, "value_size", &maps_elem_value_size_jobj))
			_abort("object \"maps\": key \"value_size\" not set");

		if (json_object_get_type(maps_elem_value_size_jobj) != json_type_int)
			_abort("object \"maps\": object \"value_size\" not of int type");

		conf->maps[idx].value_size = json_object_get_uint64(maps_elem_value_size_jobj);

		if (!json_object_object_get_ex(maps_elem_jobj, "max_entries", &maps_elem_max_entries_jobj))
			_abort("object \"maps\": key \"max_entries\" not set");

		if (json_object_get_type(maps_elem_max_entries_jobj) != json_type_int)
			_abort("object \"maps\": object \"max_entries\" not of int type");

		conf->maps[idx].max_entries = json_object_get_uint64(maps_elem_max_entries_jobj);

		if (!json_object_object_get_ex(maps_elem_jobj, "map_flags", &maps_elem_bpf_flags_jobj))
			_abort("object \"maps\": key \"map_flags\" not set");

		if (json_object_get_type(maps_elem_bpf_flags_jobj) != json_type_array)
			_abort("object \"maps\": object \"map_flags\" not of array type");

		size_t map_flags_len = json_object_array_length(maps_elem_bpf_flags_jobj);
		conf->maps[idx].map_flags = 0;

		for (size_t j = 0; j < map_flags_len; j++) {
			maps_bpf_flags_elem_jobj = json_object_array_get_idx(maps_elem_bpf_flags_jobj, j);
			if (json_object_get_type(maps_bpf_flags_elem_jobj) != json_type_string)
				_abort("object \"maps\": object \"bpf_flags\": elem not of string type");

			const char *flag = json_object_get_string(maps_bpf_flags_elem_jobj);

			if (!strcmp(flag, "BPF_F_NO_PREALLOC"))
				conf->maps[idx].map_flags |= BPF_F_NO_PREALLOC;
			else if (!strcmp(flag, "BPF_F_NO_PREALLOC"))
				conf->maps[idx].map_flags |= BPF_F_NO_PREALLOC;
			else if (!strcmp(flag, "BPF_F_NO_COMMON_LRU"))
				conf->maps[idx].map_flags |= BPF_F_NO_COMMON_LRU;
			else if (!strcmp(flag, "BPF_F_NUMA_NODE"))
				conf->maps[idx].map_flags |= BPF_F_NUMA_NODE;
			else if (!strcmp(flag, "BPF_F_RDONLY"))
				conf->maps[idx].map_flags |= BPF_F_RDONLY;
			else if (!strcmp(flag, "BPF_F_WRONLY"))
				conf->maps[idx].map_flags |= BPF_F_WRONLY;
			else if (!strcmp(flag, "BPF_F_STACK_BUILD_ID"))
				conf->maps[idx].map_flags |= BPF_F_STACK_BUILD_ID;
			else if (!strcmp(flag, "BPF_F_ZERO_SEED"))
				conf->maps[idx].map_flags |= BPF_F_ZERO_SEED;
			else if (!strcmp(flag, "BPF_F_RDONLY_PROG"))
				conf->maps[idx].map_flags |= BPF_F_RDONLY_PROG;
			else if (!strcmp(flag, "BPF_F_WRONLY_PROG"))
				conf->maps[idx].map_flags |= BPF_F_WRONLY_PROG;
			else if (!strcmp(flag, "BPF_F_CLONE"))
				conf->maps[idx].map_flags |= BPF_F_CLONE;
			else if (!strcmp(flag, "BPF_F_MMAPABLE"))
				conf->maps[idx].map_flags |= BPF_F_MMAPABLE;
			else if (!strcmp(flag, "BPF_F_PRESERVE_ELEMS"))
				conf->maps[idx].map_flags |= BPF_F_PRESERVE_ELEMS;
			else if (!strcmp(flag, "BPF_F_INNER_MAP"))
				conf->maps[idx].map_flags |= BPF_F_INNER_MAP;
			else
				_abort("object \"maps\": object \"map_flags\": flag \"%s\" unsupported", flag);
		}
	}
}

void parse_alu_scal_ops_json(json_object *root_jobj, struct config *conf)
{
	json_object *alu_scal_ops_jobj;
	json_object *alu_scal_ops_elem_jobj;

	if (!json_object_object_get_ex(root_jobj, "alu_scal_ops", &alu_scal_ops_jobj))
		_abort("key \"alu_scal_ops\" not set");

	if (json_object_get_type(alu_scal_ops_jobj) != json_type_array)
		_abort("object \"alu_scal_ops\": not of array type");

	conf->alu_scal_ops_len = json_object_array_length(alu_scal_ops_jobj);
	if (!conf->alu_scal_ops_len)
		_abort("object \"alu_scal_ops\": array of size zero");

	conf->alu_scal_ops = calloc(conf->alu_scal_ops_len, sizeof(uint8_t));

	for (size_t idx = 0; idx < conf->alu_scal_ops_len; idx++) {
		alu_scal_ops_elem_jobj = json_object_array_get_idx(alu_scal_ops_jobj, idx);
		if (json_object_get_type(alu_scal_ops_elem_jobj) != json_type_string)
			_abort("object \"alu_scal_ops\": elem not of string type");

		const char *type = json_object_get_string(alu_scal_ops_elem_jobj);

		if (!strcmp(type, "BPF_ADD"))
			conf->alu_scal_ops[idx] = BPF_ADD;
		else if (!strcmp(type, "BPF_SUB"))
			conf->alu_scal_ops[idx] = BPF_SUB;
		else if (!strcmp(type, "BPF_MUL"))
			conf->alu_scal_ops[idx] = BPF_MUL;
		else if (!strcmp(type, "BPF_DIV"))
			conf->alu_scal_ops[idx] = BPF_DIV;
		else if (!strcmp(type, "BPF_OR"))
			conf->alu_scal_ops[idx] = BPF_OR;
		else if (!strcmp(type, "BPF_AND"))
			conf->alu_scal_ops[idx] = BPF_AND;
		else if (!strcmp(type, "BPF_LSH"))
			conf->alu_scal_ops[idx] = BPF_LSH;
		else if (!strcmp(type, "BPF_RSH"))
			conf->alu_scal_ops[idx] = BPF_RSH;
		else if (!strcmp(type, "BPF_NEG"))
			conf->alu_scal_ops[idx] = BPF_NEG;
		else if (!strcmp(type, "BPF_MOD"))
			conf->alu_scal_ops[idx] = BPF_MOD;
		else if (!strcmp(type, "BPF_XOR"))
			conf->alu_scal_ops[idx] = BPF_XOR;
		else
			_abort("object \"alu_scal_ops\": operation \"%s\" unsupported", type);
	}
}

void parse_alu_atomic_ops_json(json_object *root_jobj, struct config *conf)
{
	json_object *alu_atomic_ops_jobj;
	json_object *alu_atomic_ops_elem_jobj;

	if (!json_object_object_get_ex(root_jobj, "alu_atomic_ops", &alu_atomic_ops_jobj))
		_abort("key \"alu_atomic_ops\" not set");

	if (json_object_get_type(alu_atomic_ops_jobj) != json_type_array)
		_abort("object \"alu_atomic_ops\": not of array type");

	conf->alu_atomic_ops_len = json_object_array_length(alu_atomic_ops_jobj);
	if (!conf->alu_atomic_ops_len)
		_abort("object \"alu_atomic_ops\": array of size zero");

	conf->alu_atomic_ops = calloc(conf->alu_atomic_ops_len, sizeof(uint16_t));

	for (size_t idx = 0; idx < conf->alu_atomic_ops_len; idx++) {
		alu_atomic_ops_elem_jobj = json_object_array_get_idx(alu_atomic_ops_jobj, idx);
		if (json_object_get_type(alu_atomic_ops_elem_jobj) != json_type_string)
			_abort("object \"alu_atomic_ops\": elem not of string type");

		const char *type = json_object_get_string(alu_atomic_ops_elem_jobj);

		char *or_sep = strstr(type, "|");
		bool or_fetch = false;
		char *or_op = or_sep;

		if (or_op && or_op + 1) {
			or_op++;
			while (*or_op == ' ')
				or_op++;
			if (!or_op || strcmp(or_op, "BPF_FETCH"))
				_abort("object \"alu_atomic_ops\": wrong or in elem");
			or_fetch = true;
			*or_sep = '\0';
			while (--or_sep >= type && or_sep) {
				if (*or_sep == ' ')
					*or_sep = '\0';
			}
		}

		if (!strcmp(type, "BPF_ADD"))
			conf->alu_atomic_ops[idx] = BPF_ADD;
		else if (!strcmp(type, "BPF_SUB"))
			conf->alu_atomic_ops[idx] = BPF_SUB;
		else if (!strcmp(type, "BPF_MUL"))
			conf->alu_atomic_ops[idx] = BPF_MUL;
		else if (!strcmp(type, "BPF_DIV"))
			conf->alu_atomic_ops[idx] = BPF_DIV;
		else if (!strcmp(type, "BPF_OR"))
			conf->alu_atomic_ops[idx] = BPF_OR;
		else if (!strcmp(type, "BPF_AND"))
			conf->alu_atomic_ops[idx] = BPF_AND;
		else if (!strcmp(type, "BPF_LSH"))
			conf->alu_atomic_ops[idx] = BPF_LSH;
		else if (!strcmp(type, "BPF_RSH"))
			conf->alu_atomic_ops[idx] = BPF_RSH;
		else if (!strcmp(type, "BPF_NEG"))
			conf->alu_atomic_ops[idx] = BPF_NEG;
		else if (!strcmp(type, "BPF_MOD"))
			conf->alu_atomic_ops[idx] = BPF_MOD;
		else if (!strcmp(type, "BPF_XOR"))
			conf->alu_atomic_ops[idx] = BPF_XOR;
		else if (!strcmp(type, "BPF_XCHG"))
			conf->alu_atomic_ops[idx] = BPF_XCHG;
		else if (!strcmp(type, "BPF_CMPXCHG"))
			conf->alu_atomic_ops[idx] = BPF_CMPXCHG;
		else
			_abort("object \"alu_atomic_ops\": operation \"%s\" unsupported", type);

		if (or_fetch)
			conf->alu_atomic_ops[idx] |= BPF_FETCH;
	}
}

void parse_try_leaks(json_object *root_jobj, struct config *conf)
{
	json_object *try_leak_into_mem_jobj;
	json_object *try_leak_into_map_jobj;

	if (json_object_object_get_ex(root_jobj, "try_leak_into_mem", &try_leak_into_mem_jobj)) {
		if (json_object_get_type(try_leak_into_mem_jobj) != json_type_boolean)
			_abort("object \"alu_scal_ops\": not of boolean type");

		conf->try_leak_into_mem = json_object_get_boolean(try_leak_into_mem_jobj);
	}

	if (json_object_object_get_ex(root_jobj, "try_leak_into_map", &try_leak_into_map_jobj)) {
		if (json_object_get_type(try_leak_into_map_jobj) != json_type_boolean)
			_abort("object \"alu_scal_ops\": not of boolean type");

		conf->try_leak_into_map = json_object_get_boolean(try_leak_into_map_jobj);
	}
}

void parse_pkt_len(json_object *root_jobj, struct config *conf)
{
	json_object *pkt_len_jobj;
	int64_t pkt_len;

	if (!json_object_object_get_ex(root_jobj, "pkt_len", &pkt_len_jobj))
		return;
	if (json_object_get_type(pkt_len_jobj) != json_type_int)
		_abort("object \"pkt_len\": not of int type");

	pkt_len = json_object_get_int64(pkt_len_jobj);

	if (pkt_len <= 0)
		_abort("object \"pkt_len\": should be > 0");

	conf->pkt_len = (uint32_t) pkt_len;
}

void parse_alu_insns(json_object *root_jobj, struct config *conf)
{
	json_object *alu_insns_jobj;
	json_object *alu_insns_elem_jobj;
	if (!json_object_object_get_ex(root_jobj, "alu_insns", &alu_insns_jobj))
		return;

	if (json_object_get_type(alu_insns_jobj) != json_type_array)
		_abort("object \"alu_insns\": not of array type");

	size_t alu_insns_len = json_object_array_length(alu_insns_jobj);
	if (!alu_insns_len)
		_abort("object \"alu_insns\": array of size zero");

	for (size_t idx = 0; idx < alu_insns_len; idx++) {
		alu_insns_elem_jobj = json_object_array_get_idx(alu_insns_jobj, idx);
		if (json_object_get_type(alu_insns_elem_jobj) != json_type_string)
			_abort("object \"alu_insns\": elem not of string type");

		const char *type = json_object_get_string(alu_insns_elem_jobj);

		if (!strcmp(type, "BPF_ALU64_REG")) {
			conf->alu_reg_insns_len++;
			conf->alu_reg_insns = reallocarray(conf->alu_reg_insns, conf->alu_reg_insns_len,
											   sizeof(bool (*)(struct environ *, uint8_t, struct bpf_reg *, struct bpf_reg *)));
			conf->alu_reg_insns[conf->alu_reg_insns_len - 1] = gen_bpf_alu64_reg;
		} else if (!strcmp(type, "BPF_ALU64_IMM")) {
			conf->alu_imm_insns_len++;
			conf->alu_imm_insns =
				reallocarray(conf->alu_imm_insns, conf->alu_imm_insns_len, sizeof(bool (*)(struct environ *, uint8_t, struct bpf_reg *, int32_t)));
			conf->alu_imm_insns[conf->alu_imm_insns_len - 1] = gen_bpf_alu64_imm;
		} else if (!strcmp(type, "BPF_ALU32_REG")) {
			conf->alu_reg_insns_len++;
			conf->alu_reg_insns = reallocarray(conf->alu_reg_insns, conf->alu_reg_insns_len,
											   sizeof(bool (*)(struct environ *, uint8_t, struct bpf_reg *, struct bpf_reg *)));
			conf->alu_reg_insns[conf->alu_reg_insns_len - 1] = gen_bpf_alu32_reg;
		} else if (!strcmp(type, "BPF_ALU32_IMM")) {
			conf->alu_imm_insns_len++;
			conf->alu_imm_insns =
				reallocarray(conf->alu_imm_insns, conf->alu_imm_insns_len, sizeof(bool (*)(struct environ *, uint8_t, struct bpf_reg *, int32_t)));
			conf->alu_imm_insns[conf->alu_imm_insns_len - 1] = gen_bpf_alu32_imm;
		} else
			_abort("object \"alu_insns\": elem type unsupported");
	}
}

void parse_mov_insns(json_object *root_jobj, struct config *conf)
{
	json_object *mov_insns_jobj;
	json_object *mov_insns_elem_jobj;
	if (!json_object_object_get_ex(root_jobj, "mov_insns", &mov_insns_jobj))
		return;

	if (json_object_get_type(mov_insns_jobj) != json_type_array)
		_abort("object \"mov_insns\": not of array type");

	size_t mov_insns_len = json_object_array_length(mov_insns_jobj);
	if (!mov_insns_len)
		_abort("object \"mov_insns\": array of size zero");

	for (size_t idx = 0; idx < mov_insns_len; idx++) {
		mov_insns_elem_jobj = json_object_array_get_idx(mov_insns_jobj, idx);
		if (json_object_get_type(mov_insns_elem_jobj) != json_type_string)
			_abort("object \"mov_insns\": elem not of string type");

		const char *type = json_object_get_string(mov_insns_elem_jobj);

		if (!strcmp(type, "BPF_MOV64_REG")) {
			conf->mov_reg_insns_len++;
			conf->mov_reg_insns = reallocarray(conf->mov_reg_insns, conf->mov_reg_insns_len,
											   sizeof(bool (*)(struct environ *, uint8_t, struct bpf_reg *, struct bpf_reg *)));
			conf->mov_reg_insns[conf->mov_reg_insns_len - 1] = gen_bpf_mov64_reg;
		} else if (!strcmp(type, "BPF_MOV64_IMM")) {
			conf->mov_imm_insns_len++;
			conf->mov_imm_insns =
				reallocarray(conf->mov_imm_insns, conf->mov_imm_insns_len, sizeof(bool (*)(struct environ *, struct bpf_reg *, int32_t)));
			conf->mov_imm_insns[conf->mov_imm_insns_len - 1] = gen_bpf_mov64_imm;
		} else if (!strcmp(type, "BPF_MOV32_REG")) {
			conf->mov_reg_insns_len++;
			conf->mov_reg_insns = reallocarray(conf->mov_reg_insns, conf->mov_reg_insns_len,
											   sizeof(bool (*)(struct environ *, uint8_t, struct bpf_reg *, struct bpf_reg *)));
			conf->mov_reg_insns[conf->mov_reg_insns_len - 1] = gen_bpf_mov32_reg;
		} else if (!strcmp(type, "BPF_MOV32_IMM")) {
			conf->mov_imm_insns_len++;
			conf->mov_imm_insns =
				reallocarray(conf->mov_imm_insns, conf->mov_imm_insns_len, sizeof(bool (*)(struct environ *, struct bpf_reg *, int32_t)));
			conf->mov_imm_insns[conf->mov_imm_insns_len - 1] = gen_bpf_mov32_imm;
		} else
			_abort("object \"mov_insns\": elem type unsupported");
	}
}

void parse_insns_types(json_object *root_jobj, struct config *conf)
{
	json_object *insns_types_jobj;
	json_object *insns_types_elem_jobj;
	if (!json_object_object_get_ex(root_jobj, "insns_types", &insns_types_jobj))
		_abort("object \"insns_types\": not set");

	if (json_object_get_type(insns_types_jobj) != json_type_array)
		_abort("object \"insns_types\": not of array type");

	size_t insns_types_len = json_object_array_length(insns_types_jobj);
	if (!insns_types_len)
		_abort("object \"insns_types\": array of size zero");

	for (size_t idx = 0; idx < insns_types_len; idx++) {
		insns_types_elem_jobj = json_object_array_get_idx(insns_types_jobj, idx);
		if (json_object_get_type(insns_types_elem_jobj) != json_type_string)
			_abort("object \"insns_types\": elem not of string type");

		const char *type = json_object_get_string(insns_types_elem_jobj);

		conf->insns_types_len++;
		conf->insns_types = reallocarray(conf->insns_types, conf->insns_types_len, sizeof(bool (*)(struct environ * env)));

		if (!strcmp(type, "MOV"))
			conf->insns_types[conf->insns_types_len - 1] = generate_rand_mov;
		else if (!strcmp(type, "ALU"))
			conf->insns_types[conf->insns_types_len - 1] = generate_rand_alu;
		else if (!strcmp(type, "LD_IMM64"))
			conf->insns_types[conf->insns_types_len - 1] = generate_rand_ld_imm64;
		else if (!strcmp(type, "MEM_LD"))
			conf->insns_types[conf->insns_types_len - 1] = generate_rand_mem_ld;
		else if (!strcmp(type, "MAP_OP"))
			conf->insns_types[conf->insns_types_len - 1] = generate_rand_map_op;
		else if (!strcmp(type, "PTR_STX"))
			conf->insns_types[conf->insns_types_len - 1] = generate_rand_ptr_stx;
		else if (!strcmp(type, "PTR_LDX"))
			conf->insns_types[conf->insns_types_len - 1] = generate_rand_ptr_ldx;
		else if (!strcmp(type, "REG_SPILL"))
			conf->insns_types[conf->insns_types_len - 1] = generate_rand_reg_spill;
		else if (!strcmp(type, "REG_BOUNDS"))
			conf->insns_types[conf->insns_types_len - 1] = generate_rand_reg_bounds;
		else if (!strcmp(type, "HELPER_CALL"))
			conf->insns_types[conf->insns_types_len - 1] = generate_rand_helper_call;
		else if (!strcmp(type, "ZEXT_REG"))
			conf->insns_types[conf->insns_types_len - 1] = generate_rand_zext_reg;
		else
			_abort("object \"insns_types\": elem type unsupported");
	}
}

void parse_chaos_mode(json_object *root_jobj, struct config *conf)
{
	json_object *chaos_mode_jobj;

	if (!json_object_object_get_ex(root_jobj, "chaos_mode", &chaos_mode_jobj))
		return;

	if (json_object_get_type(chaos_mode_jobj) != json_type_boolean)
		_abort("object \"chaos_mode\": not of boolean type");

	conf->chaos_mode = json_object_get_boolean(chaos_mode_jobj);
}

void parse_stack_align(json_object *root_jobj, struct config *conf)
{
	json_object *stack_align_jobj;

	if (!json_object_object_get_ex(root_jobj, "stack_align", &stack_align_jobj))
		return;

	if (json_object_get_type(stack_align_jobj) != json_type_boolean)
		_abort("object \"stack_align_jobj\": not of boolean type");

	conf->stack_align = json_object_get_boolean(stack_align_jobj);
}

void parse_stack_size(json_object *root_jobj, struct config *conf)
{
	json_object *stack_size_jobj;

	if (!json_object_object_get_ex(root_jobj, "stack_size", &stack_size_jobj))
		return;

	if (json_object_get_type(stack_size_jobj) != json_type_int)
		_abort("object \"stack_size_jobj\": not of int type");

	conf->stack_size = json_object_get_int(stack_size_jobj);
	if (conf->stack_size > 512)
		_abort("stack size over 512 bytes");
}

void parse_imm32_limits(json_object *root_jobj, struct config *conf)
{
	json_object *imm32_min_jobj;
	json_object *imm32_max_jobj;

	if (json_object_object_get_ex(root_jobj, "imm32_min", &imm32_min_jobj)) {
		if (json_object_get_type(imm32_min_jobj) != json_type_int)
			_abort("object \"imm32_min_jobj\": not of int type");

		conf->imm32_min = json_object_get_int(imm32_min_jobj);
	}

	if (json_object_object_get_ex(root_jobj, "imm32_max", &imm32_max_jobj)) {
		if (json_object_get_type(imm32_max_jobj) != json_type_int)
			_abort("object \"imm32_max_jobj\": not of int type");

		conf->imm32_max = json_object_get_int(imm32_max_jobj);
	}
}

void parse_config(char *conf_file, struct config *conf)
{
	char *json = NULL;
	int fsize = 0;
	FILE *fp;

	fp = fopen(conf_file, "r");
	if (fp) {
		fseek(fp, 0, SEEK_END);
		fsize = ftell(fp);
		rewind(fp);

		json = calloc(sizeof(char) * fsize + 1, sizeof(char));
		fread(json, 1, fsize, fp);
		fclose(fp);
	} else
		_abort("file not found");
	set_defaults(conf);

	parse_json(json, conf);
}
