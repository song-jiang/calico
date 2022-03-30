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

// https://chromium.googlesource.com/external/p3/regal/+/1ba938a5f091bc02725e912a5cf25d6e4bf03939/src/apitrace/dispatch/compat.h

#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "ebpf_api.h"
//#include "catch_wrapper.hpp"
//#include "ebpf_vm_isa.hpp"
//#include "helpers.h"
//#include "platform.h"
//#include "program_helper.h"
//#include "test_helper.hpp"

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

// libbpf.h uses enum types and generates the
// following warning whenever an enum type is used below:
// "The enum type 'bpf_attach_type' is unscoped.
// Prefer 'enum class' over 'enum'"
#pragma warning(disable : 26812)

int run_load_program() {
	// Try with a valid set of instructions.
    struct ebpf_inst instructions[] = {
        {0xb7, R0_RETURN_VALUE, 0}, // r0 = 0
        {INST_OP_EXIT},             // return r0
    };



    /*
    const char* trace_map = "calico_xdp::trace_map";

    const char* error_message = NULL;
    ebpf_result_t result;
    struct bpf_object* object = nullptr;
    fd_t program_fd;

    result = ebpf_program_load(
        "xdp.o", nullptr, nullptr, EBPF_EXECUTION_JIT, &object, &program_fd, &error_message);
    if (result != EBPF_SUCCESS) {
        fprintf(stderr, "Failed to load calico xdp eBPF program\n");
        fprintf(stderr, "%s", error_message);
        ebpf_free_string(error_message);
        return 1;
    }

    fd_t trace_map_fd = bpf_object__find_map_fd_by_name(object, "trace_map");
    if (trace_map_fd <= 0) {
        fprintf(stderr, "Failed to find eBPF map : %s\n", trace_map);
        return 1;
    }

    if (bpf_obj_pin(trace_map_fd, trace_map) < 0) {
        fprintf(stderr, "Failed to pin eBPF program: %d\n", errno);
        return 1;
    }
    */

    // Load and verify the eBPF program.
    int size = sizeof(instructions)/sizeof(instructions[0]);
    int program_fd = bpf_load_program(BPF_PROG_TYPE_XDP, instructions, size, nullptr, 0, nullptr, 0);
    fprintf(stdout, "Load program with fd: %d\n", program_fd);

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

    // Create a map.
    int map_fd = bpf_create_map(BPF_MAP_TYPE_PROG_ARRAY, sizeof(uint32_t), sizeof(uint32_t), 2, 0);
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

    // Since the map is not yet associated with a program, the first program fd
    // we add will become the PROG_ARRAY's program type.
    int index = 0;
    int error = bpf_map_update_elem(map_fd, (uint8_t*)&index, (uint8_t*)&program_fd, 0);
    if (error != 0) {
        fprintf(stderr, "Failed to update prog array: %d\n", errno);
        return -1;
    }

    fprintf(stdout, "Done!All good.\n");

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
    int detected = 0;
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

	map_fd = bpf_create_map_xattr(&map_attr);
	if (map_fd < 0)
        fprintf(stdout, "Failed to create map: %d\n", errno);
		return detected;

	//insns[0].imm = map_fd;

	memset(&prog_attr, 0, sizeof(prog_attr));
	prog_attr.prog_type = BPF_PROG_TYPE_XDP;
	prog_attr.insns = insns;
	prog_attr.insns_cnt = sizeof(insns)/sizeof(insns[0]);
	prog_attr.license = "GPL";

	prog_fd = bpf_load_program_xattr(&prog_attr, NULL, 0);
	if (prog_fd < 0) {
        fprintf(stdout, "Failed to load program: %d\n", errno);
		close(map_fd);
		return detected;
	}

    fprintf(stdout, "Done!All good. %d, %d\n", prog_fd, map_fd);

	close(prog_fd);
	close(map_fd);
	return detected;
}

static void set_errno(int ret) {
	errno = ret >= 0 ? ret : -ret;
}