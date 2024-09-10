package main

import (
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go probe hello.bpf.c -- -O2 -Wall

func main() {
	objs := probeObjects{}
	if err := loadProbeObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	kp, err := link.Kprobe("sys_execve", objs.Hello, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	tracePipe, err := os.Open("/sys/kernel/debug/tracing/trace_pipe")
	if err != nil {
		log.Fatal(err)
	}
	defer tracePipe.Close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		tracePipe.Close()
	}()

	io.Copy(os.Stdout, tracePipe)
}
