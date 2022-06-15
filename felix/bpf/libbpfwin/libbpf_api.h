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
#include <stdlib.h>

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

// The following is the function for syscall_windows
// The following is the function for syscall_windows
void bpf_map__get_info(uint32_t map_fd, struct bpf_map_info *p_map_info) { 
    uint32_t map_info_size = sizeof(*p_map_info);
    int err = bpf_obj_get_info_by_fd(map_fd, p_map_info, &map_info_size);
	set_errno(err);
    return;
}

uint32_t bpf_map__get_map_fd_by_id(uint32_t id) {
    // Verify that the map still exists.
    int map_fd = bpf_map_get_fd_by_id(id);
    if (map_fd <= 0) {
        set_errno(ENOENT);
		return -1;
    }
    return map_fd;
}

int bpf_map__create(enum bpf_map_type map_type, int key_size, int value_size, int max_entries, uint32_t map_flags) {
    // Create a map.
    int map_fd = bpf_create_map(map_type, key_size, value_size, max_entries, map_flags);
    if (map_fd <= 0) {
        fprintf(stderr, "Failed to create map for prog array: %d\n", errno);
        return -1;
    }

    struct bpf_map_info map_info;
    uint32_t map_info_size = sizeof(map_info);
    if (bpf_obj_get_info_by_fd(map_fd, &map_info, &map_info_size) < 0) {
        return -1;
    }

    fprintf(stdout, "Created map : {name: %s, type: %d, fd: %d}\n", map_info.name, map_info.type, map_fd);
    return map_fd;
}

uint32_t
bpf_program__load_bytecode(
    enum bpf_prog_type type,
    void *insns,
    size_t insns_cnt,
    char* license,
    __u32 kern_version,
    void* log_buf,
    size_t log_buf_sz)
{
    uint32_t program_fd = bpf_load_program(type, (struct ebpf_inst*)insns, insns_cnt, license, kern_version, log_buf, log_buf_sz);
    fprintf(stdout, "Load program with fd: %d\n", program_fd);
    if (program_fd <= 0) {
        set_errno(ENOENT);
		return -1;
    }
     // Now query the program info and verify it matches what we set.
    struct bpf_prog_info program_info;
    uint32_t program_info_size = sizeof(program_info);
    if (bpf_obj_get_info_by_fd(program_fd, &program_info, &program_info_size) < 0) {
        fprintf(stderr, "Failed to call bpf_obj_get_info_by fd: %d\n", errno);
        return -1;
    }

    // TODO(issue #223): change below to BPF_PROG_TYPE_XDP.
    // REQUIRE(program_info.type == BPF_PROG_TYPE_UNSPEC);
    fprintf(stdout, "bpf_prog_info { name: %s, type: %d }\n", program_info.name, program_info.type);
    return program_fd;
}

void bpf_map__lookup_elem(uint32_t fd, const void *key, const void *value) {
    int error = bpf_map_lookup_elem(fd, key, value);
    if (error != 0) {
        fprintf(stderr, "Failed to get entry map: %d\n", errno);
        set_errno(error);
    }
    return;
}

void bpf_map__delete_elem(uint32_t fd, const void *key) {
    int error = bpf_map_delete_elem(fd, key);
    if (error != 0) {
        fprintf(stderr, "Failed to delete entry map: %d\n", errno);
        set_errno(error);
    }
    return;
}

void bpf_map__update_elem(uint32_t fd, const void *key, const void *value, __u64 flags) {
    int error = bpf_map_update_elem(fd, key, value, flags);
    if (error != 0) {
        fprintf(stderr, "Failed to update map: %d\n", errno);
        set_errno(error);
    }
    return;
}

//--------------------------------------

// The following is for ebpfwin functions
// The following is from external/ebpf-verifier/src/ebpf_vm_isa.hpp
struct ebpf_inst {
    uint8_t opcode;
    uint8_t dst : 4; //< Destination register
    uint8_t src : 4; //< Source register
    int16_t offset;
    int32_t imm;     //< Immediate constant
};

enum {
    INST_CLS_MASK = 0x07,

    INST_CLS_LD = 0x00,
    INST_CLS_LDX = 0x01,
    INST_CLS_ST = 0x02,
    INST_CLS_STX = 0x03,
    INST_CLS_ALU = 0x04,
    INST_CLS_JMP = 0x05,
    INST_CLS_JMP32 = 0x06,
    INST_CLS_ALU64 = 0x07,

    INST_SRC_IMM = 0x00,
    INST_SRC_REG = 0x08,

    INST_SIZE_W = 0x00,
    INST_SIZE_H = 0x08,
    INST_SIZE_B = 0x10,
    INST_SIZE_DW = 0x18,

    INST_SIZE_MASK = 0x18,

    INST_MODE_MASK = 0xe0,

    INST_ABS = 1,
    INST_IND = 2,
    INST_MEM = 3,
    INST_LEN = 4,
    INST_MSH = 5,
    INST_XADD = 6,
    INST_MEM_UNUSED = 7,

    INST_OP_LDDW_IMM = (INST_CLS_LD | INST_SRC_IMM | INST_SIZE_DW), // Special

    INST_OP_JA = (INST_CLS_JMP | 0x00),
    INST_OP_CALL = (INST_CLS_JMP | 0x80),
    INST_OP_EXIT = (INST_CLS_JMP | 0x90),
    INST_ALU_OP_MASK = 0xf0
};

enum {
    R0_RETURN_VALUE = 0,
    R1_ARG = 1,
    R2_ARG = 2,
    R3_ARG = 3,
    R4_ARG = 4,
    R5_ARG = 5,
    R6 = 6,
    R7 = 7,
    R8 = 8,
    R9 = 9,
    R10_STACK_POINTER = 10
};

// define nullptr
void *nullptr = NULL;

// The following is just for demo of ebpfwin.exe
int run_load_program() {
	// Try with a valid set of instructions.
    struct ebpf_inst instructions[] = {
        {0xb7, R0_RETURN_VALUE, 0}, // r0 = 0
        {INST_OP_EXIT},             // return r0
    };

    // Load and verify the eBPF program.
    int program_fd = bpf_load_program(BPF_PROG_TYPE_XDP, instructions, _countof(instructions), nullptr, 0, nullptr, 0);
    fprintf(stderr, "Song 03: Load program with fd: %d\n", program_fd);

    // Now query the program info and verify it matches what we set.
    struct bpf_prog_info program_info;
    uint32_t program_info_size = sizeof(program_info);
    if (bpf_obj_get_info_by_fd(program_fd, &program_info, &program_info_size) < 0) {
        fprintf(stderr, "Failed to call bpf_obj_get_info_by fd: %d\n", errno);
        return -1;
    }

    // TODO(issue #223): change below to BPF_PROG_TYPE_XDP.
    // REQUIRE(program_info.type == BPF_PROG_TYPE_UNSPEC);
    fprintf(stderr, "bpf_prog_info { name: %s, type: %d }\n", program_info.name, program_info.type);

    // Create a map.
    // int map_fd = bpf_create_map(BPF_MAP_TYPE_PROG_ARRAY, sizeof(uint32_t), sizeof(uint32_t), 2, 0);
    int map_fd = bpf_create_map(BPF_MAP_TYPE_LPM_TRIE, sizeof(uint32_t) * 2, sizeof(uint64_t), 10, 0);
    if (map_fd <= 0) {
        fprintf(stderr, "Failed to create map for prog array: %d\n", errno);
        return -1;
    }

    struct bpf_map_info map_info;
    uint32_t map_info_size = sizeof(map_info);
    if (bpf_obj_get_info_by_fd(map_fd, &map_info, &map_info_size) < 0) {
        return -1;
    }

    fprintf(stderr, "Created map : {name: %s, type: %d, fd: %d}\n", map_info.name, map_info.type, map_fd);

    // Since the map is not yet associated with a program, the first program fd
    // we add will become the PROG_ARRAY's program type.
    int index = 0;
    int error = bpf_map_update_elem(map_fd, (uint8_t*)&index, (uint8_t*)&program_fd, 0);
    if (error != 0) {
        fprintf(stderr, "Failed to update prog array: %d\n", errno);
        return -1;
    }

    fprintf(stderr, "Done!All good.\n");

    close(map_fd);
    close(program_fd);
    return program_fd;
}

enum xdp_action {
	XDP_ABORTED = 0,
	XDP_DROP,
	XDP_PASS,
	XDP_TX,
	XDP_REDIRECT,
};

/* Register numbers */
enum {
	BPF_REG_0 = 0,
	BPF_REG_1,
	BPF_REG_2,
	BPF_REG_3,
	BPF_REG_4,
	BPF_REG_5,
	BPF_REG_6,
	BPF_REG_7,
	BPF_REG_8,
	BPF_REG_9,
	BPF_REG_10,
	__MAX_BPF_REG,
};

int xsk_prog_load() {
	struct bpf_load_program_attr prog_attr;
	struct bpf_create_map_attr map_attr;
	__u32 size_out, retval, duration;
	char data_in = 0, data_out;
	struct bpf_insn insns[] = {
        {0xb7, R0_RETURN_VALUE, 0}, // r0 = 0
        {INST_OP_EXIT},             // return r0
	};
	int prog_fd, map_fd, ret;

	memset(&map_attr, 0, sizeof(map_attr));
	map_attr.map_type = BPF_MAP_TYPE_ARRAY;
	map_attr.key_size = sizeof(int);
	map_attr.value_size = sizeof(int);
	map_attr.max_entries = 1;

    fprintf(stderr, "Start create map\n");

	map_fd = bpf_create_map_xattr(&map_attr);
	if (map_fd < 0)
        fprintf(stderr, "Failed to create map: %d\n", errno);
		return -1;

     fprintf(stderr, "Start create map done\n");
	//insns[0].imm = map_fd;

	memset(&prog_attr, 0, sizeof(prog_attr));
	prog_attr.prog_type = BPF_PROG_TYPE_XDP;
	prog_attr.insns = insns;
	prog_attr.insns_cnt = sizeof(insns)/sizeof(insns[0]);
	prog_attr.license = "GPL";

    fprintf(stderr, "Start load program\n");

	prog_fd = bpf_load_program_xattr(&prog_attr, NULL, 0);
	if (prog_fd < 0) {
        fprintf(stderr, "Failed to load program: %d\n", errno);
		close(map_fd);
		return -1;
	}

    fprintf(stderr, "Done!All good. %d, %d\n", prog_fd, map_fd);

	close(prog_fd);
	close(map_fd);
	return 0;
}
