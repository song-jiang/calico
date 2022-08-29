#include "bpf_helpers.h"

SEC("maps")
struct bpf_map map =
    {sizeof(struct bpf_map), BPF_MAP_TYPE_PERCPU_ARRAY, 2, 4, 512};

#define DECLARE_MAP(TYPE)                              \
    SEC("maps")                                        \
    struct _ebpf_map_definition_in_file TYPE##_map = { \
        .type = BPF_MAP_TYPE_##TYPE,                   \
        .key_size = sizeof(uint32_t),                  \
        .value_size = sizeof(uint32_t),                \
        .max_entries = 10,                             \
    };

DECLARE_MAP(PERCPU_ARRAY);


SEC("xdp_prog") int test_maps(struct xdp_md* ctx)
{
    uint32_t key = 0;
    uint32_t value = 1;
    uint32_t* return_value = NULL;
    int result = 0;

    return_value = bpf_map_lookup_elem(&PERCPU_ARRAY_map, &key);
    if (return_value == NULL) {
        //bpf_printk("bpf_map_lookup_elem returned NULL");
        return -1;
    }

    return 0;
}