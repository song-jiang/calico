// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.
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

#include <stdlib.h>
#include <unistd.h>

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

#define ENOENT	3025

#define syscall(SYS_bpf, cmd, ...) \
	bpf(cmd, ## __VA_ARGS__)

int bpf_map_load_multi(__u32 map_fd,
                       void *current_key,
                       int max_num,
                       int key_stride,
                       void *keys_out,
                       int value_stride,
                       void *values_out) {
   int count = 0;
   union bpf_attr attr = {};
   __u64 last_good_key = (__u64)(unsigned long)current_key;
   attr.map_fd = map_fd;
   attr.key = last_good_key;
   for (int i = 0; i < max_num; i++) {
     // Load the next key from the map.
   get_next_key:
     attr.value = (__u64)(unsigned long)keys_out;
     int rc = syscall(SYS_bpf, BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
     if (rc != 0) {
       if (errno == ENOENT) {
         return count; // Reached end of map.
       }
       return -errno;
     }
     // Load the corresponding value.
     attr.key = (__u64)(unsigned long)keys_out;
     attr.value = (__u64)(unsigned long)values_out;

     rc = syscall(SYS_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
     if (rc != 0) {
       if (errno == ENOENT) {
         // Expected next entry has just been deleted.  We need
         // to BPF_MAP_GET_NEXT_KEY again from the previous key.
         attr.key = last_good_key;
         goto get_next_key;
       }
       return -errno;
     }
     last_good_key = attr.key;

     keys_out+=key_stride;
     values_out+=value_stride;
     count++;
   }
   return count;
}