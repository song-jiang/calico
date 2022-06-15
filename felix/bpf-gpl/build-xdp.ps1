rm xdp.o -ErrorAction ignore

clang -target bpf -O2 -Werror -c xdp.c -o xdp.o -I c:\src\ebpf-for-windows\include -I c:\src\ebpf-for-windows\include\linux -I c:\src\ebpf-for-windows\external\libbpf\uapi\linux -I c:\src\ebpf-for-windows\tests/sample -I ./include/libbpf/src -I ./include/libbpf/include/uapils
