// Copyright (c) 2021-2022 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include <io.h>

#define _MSC_VER
#define bpf_insn ebpf_inst

#ifdef __MINGW64__
// Disable SAL 2.0d
#define _Outptr_result_buffer_maybenull_(size)
#define _In_opt_count_(size)
#define _Post_invalid_
#define _Post_ptr_invalid_
#endif 

#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "ebpf_api.h"

static void set_errno(int ret) {
	errno = ret >= 0 ? ret : -ret;
}

struct bpf_object* bpf_obj_open(char *filename) {
    struct bpf_object_open_opts opts = {0};
    struct bpf_object* obj = bpf_object__open_file(filename, &opts);
	int err = libbpf_get_error(obj);
	if (err) {
		obj = NULL;
	}
	set_errno(err);
	return obj;
}

void bpf_obj_load(struct bpf_object *obj) {
	set_errno(bpf_object__load(obj));
}

int bpf_link_destroy(struct bpf_link *link) {
	return bpf_link__destroy(link);
}

int bpf_map_set_pin_path(struct bpf_map* map, const char* path) {
    return bpf_map__pin(map, path);
}

#define ENOENT	3025
int bpf_update_jump_map(struct bpf_object *obj, char* mapName, char *progName, int progIndex) {
	struct bpf_program *prog_name = bpf_object__find_program_by_name(obj, progName);
	if (prog_name == NULL) {
		errno = ENOENT;
		return -1;
	}
	int prog_fd = bpf_program__fd(prog_name);
	if (prog_fd < 0) {
		errno = -prog_fd;
		return prog_fd;
	}
	int map_fd = bpf_object__find_map_fd_by_name(obj, mapName);
	if (map_fd < 0) {
		errno = -map_fd;
		return map_fd;
	}
	return bpf_map_update_elem(map_fd, &progIndex, &prog_fd, 0);
}

int num_possible_cpu()
{
    return libbpf_num_possible_cpus();
}

// The following code should be exposed by ebpfapi.dll
int bpf_map__set_max_entries(struct bpf_map *map, __u32 max_entries)
{
    // TODO
	return 0;
}

bool bpf_map__is_internal(const struct bpf_map *map)
{
    // TODO
    return false;
	// return map->libbpf_type != LIBBPF_MAP_UNSPEC;
}