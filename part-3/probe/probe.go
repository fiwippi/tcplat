package probe

import (
	"log/slog"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go probe tcplat.bpf.c -- -O2 -Wall

type Probe struct {
	Samples <-chan []byte

	bpfObjects  probeObjects
	ingressLink link.Link
	egressLink  link.Link
	ringbuf     *ringbuf.Reader
}

func AttachProbe(ifaceName string) (*Probe, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, err
	}
	objs := probeObjects{}
	if err := loadProbeObjects(&objs, nil); err != nil {
		return nil, err
	}

	ingressLink, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.Tcplat,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		objs.Close()
		return nil, err
	}

	egressLink, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.Tcplat,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		objs.Close()
		ingressLink.Close()
		return nil, err
	}

	reader, err := ringbuf.NewReader(objs.probeMaps.Pipe)
	if err != nil {
		objs.Close()
		ingressLink.Close()
		egressLink.Close()
		return nil, err
	}

	samples := make(chan []byte)
	go func() {
		for {
			event, err := reader.Read()
			if err != nil {
				slog.Error("Failed to read from ring buffer", slog.Any("err", err))
				close(samples)
				return
			}
			samples <- event.RawSample
		}
	}()

	return &Probe{
		Samples:     samples,
		bpfObjects:  objs,
		ingressLink: ingressLink,
		egressLink:  egressLink,
		ringbuf:     reader,
	}, nil
}

func (p *Probe) Detach() {
	p.bpfObjects.Close()
	p.ingressLink.Close()
	p.egressLink.Close()
	p.ringbuf.Close()
}
