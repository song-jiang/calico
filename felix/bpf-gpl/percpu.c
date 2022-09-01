#include "bpf_helpers.h"

SEC("maps")
struct bpf_map_def outer_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint32_t),
    .max_entries = 1}; // (uint32_t)&inner_map

#pragma clang section data = "maps"
ebpf_map_definition_in_file_t trace_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint32_t),  //dest ip as key
    .value_size = sizeof(uint32_t),
    .max_entries = 1024};

SEC("maps")
struct bpf_map jump_map = {BPF_MAP_TYPE_PROG_ARRAY, sizeof(uint32_t), sizeof(uint32_t), 10};

SEC("maps") struct bpf_map canary = {BPF_MAP_TYPE_ARRAY, sizeof(uint32_t), sizeof(uint32_t), 1};

SEC("xdp_prog") int caller(struct xdp_md* ctx)
{
    uint32_t key = 0;
    uint32_t value = 11;
    int result = 0;

    uint32_t key_hash = 2;
    uint32_t value_hash = 1;

    //result = bpf_map_update_elem(&outer_map, &key, &value, 0);
    //if (result < 0) {
        //value_hash = 7;
    //}
    uint32_t* percpu_value = bpf_map_lookup_elem(&outer_map, &key);
    if (percpu_value) {
          value_hash = 5;
          key_hash = *percpu_value;
          *percpu_value = 8;
    } else {
          key_hash = 9;
    }

    uint32_t* percpu_value_two = bpf_map_lookup_elem(&outer_map, &key);
    if (percpu_value_two) {
          value_hash = 50;
          key_hash = *percpu_value_two;
    } else {
          key_hash = 90;
    }

    bpf_map_update_elem(&trace_map, &key_hash, &value_hash, 0);


    bpf_tail_call(ctx, &jump_map, 0);

    // If we get to here it means bpf_tail_call failed.
    uint32_t *canary_value = bpf_map_lookup_elem(&canary, &key);
    if (canary_value) {
        *canary_value = 1;
    }
    
    return XDP_PASS;
}


SEC("xdp_prog/0") int callee(struct xdp_md* ctx) { 
    uint32_t key = 0;

    uint32_t key_hash = 0;
    uint32_t value_hash = 1;

    uint32_t* percpu_value = bpf_map_lookup_elem(&outer_map, &key);
    if (percpu_value) {
          value_hash = 60;
          key_hash = *percpu_value + 8;
    } else {
          key_hash = 90;
    }

    bpf_map_update_elem(&trace_map, &key_hash, &value_hash, 0);

   return XDP_PASS;
}