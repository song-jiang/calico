rm percpu.o -ErrorAction ignore

clang -target bpf -O2 -Werror -c percpu.c -o percpu.o -I c:\src\ebpf-for-windows\include -I c:\src\ebpf-for-windows\include\linux -I c:\src\ebpf-for-windows\external\libbpf\uapi\linux -I c:\src\ebpf-for-windows\tests/sample -I ./include/libbpf/src -I ./include/libbpf/include/uapils
