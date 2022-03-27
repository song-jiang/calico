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

#define bpf_insn ebpf_inst
#include "bpf/bpf.h"
#include "bpf/libbpf.h"

// The following is from external/ebpf-verifier/src/ebpf_vm_isa.hpp
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

// libbpf.h uses enum types and generates the
// following warning whenever an enum type is used below:
// "The enum type 'bpf_attach_type' is unscoped.
// Prefer 'enum class' over 'enum'"
#pragma warning(disable : 26812)

int run_load_program() {
	// Try with a valid set of instructions.
    struct bpf_insn instructions[] = {
        {0xb7, R0_RETURN_VALUE, 0}, // r0 = 0
        {INST_OP_EXIT},             // return r0
    };

    // Load and verify the eBPF program.
    int program_fd = bpf_load_program(BPF_PROG_TYPE_XDP, instructions, _countof(instructions), nullptr, 0, nullptr, 0);
    return program_fd;
}

static void set_errno(int ret) {
	errno = ret >= 0 ? ret : -ret;
}