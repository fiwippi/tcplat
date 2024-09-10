compile:
	clang -Wall -O2 -target bpf -c skb_pull_vis.bpf.c -o skb_pull_vis.bpf.o

load:
	sudo tc qdisc add dev enp0s1 clsact
	sudo tc filter add dev enp0s1 ingress bpf direct-action obj skb_pull_vis.bpf.o sec tc
	sudo tc filter add dev enp0s1 egress bpf direct-action obj skb_pull_vis.bpf.o sec tc

unload:
	sudo tc qdisc del dev enp0s1 clsact

log:
	sudo cat /sys/kernel/debug/tracing/trace_pipe
