#include "bpf_helpers.h"

SEC("maps")
struct bpf_map map =
    {sizeof(struct bpf_map), BPF_MAP_TYPE_PERCPU_ARRAY, 2, 4, 512};

SEC("myprog")
int func()
{
    return 0;
}