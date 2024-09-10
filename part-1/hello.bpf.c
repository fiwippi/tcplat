//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("kprobe/sys_execve")
int hello(void *ctx) {
    bpf_printk("Hello World!");
    return 0;
}

char LICENSE[] SEC("license") = "GPL v2";
