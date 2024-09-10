compile:
	clang -Wall -O2 -target bpf -c hello.bpf.c -o hello.bpf.o -v

load:
	sudo bpftool prog load hello.bpf.o /sys/fs/bpf/hello

unload:
	sudo rm /sys/fs/bpf/hello
	

