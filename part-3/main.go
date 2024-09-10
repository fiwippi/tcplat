package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"tcplat/probe"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Please specify a network interface")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		cancel()
	}()

	ifaceName := os.Args[1]
	probe, err := probe.AttachProbe(ifaceName)
	if err != nil {
		slog.Error("Failed to attach probe", slog.Any("err", err))
		return
	}
	defer probe.Detach()

	table := NewConnectionTable()
	for {
		select {
		case <-ctx.Done():
			return
		case raw := <-probe.Samples:
			p, err := UnmarshalPacket(raw)
			if err != nil {
				slog.Error("Failed to unmarshal packet", slog.Any("err", err))
				continue
			}
			d, matched := table.Match(p)
			if !matched {
				continue
			}
			fmt.Printf("Matched SYN/SYN-ACK, Source: %s, Destination: %s, Latency %s\n",
				p.SrcIP.Unmap(), p.DstIP.Unmap(), d)
		}
	}
}

type Hash uint64

type Timestamp uint64

type Packet struct {
	SrcIP     netip.Addr
	DstIP     netip.Addr
	SrcPort   uint16
	DstPort   uint16
	Syn       bool
	Ack       bool
	Timestamp Timestamp
}

func (p *Packet) Hash() Hash {
	f := func(v []byte) uint64 {
		h := fnv.New64a()
		h.Write(v)
		return h.Sum64()
	}

	src := binary.BigEndian.AppendUint16(p.SrcIP.AsSlice(), p.SrcPort)
	dst := binary.BigEndian.AppendUint16(p.DstIP.AsSlice(), p.DstPort)

	return Hash(f(src) + f(dst))
}

func UnmarshalPacket(data []byte) (Packet, error) {
	if len(data) != 48 {
		return Packet{}, fmt.Errorf("slice is not 48 bytes")
	}
	srcIP, ok := netip.AddrFromSlice(data[0:16])
	if !ok {
		panic("invalid source IP")
	}
	dstIP, ok := netip.AddrFromSlice(data[16:32])
	if !ok {
		panic("invalid destination IP")
	}

	return Packet{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: binary.BigEndian.Uint16(data[32:34]),
		DstPort: binary.BigEndian.Uint16(data[34:36]),
		Syn:     data[36] == 1,
		Ack:     data[37] == 1,
		// 2-byte hole
		Timestamp: Timestamp(binary.LittleEndian.Uint64(data[40:48])),
	}, nil
}

type ConnectionTable struct {
	table map[Hash]Timestamp
}

func NewConnectionTable() *ConnectionTable {
	return &ConnectionTable{
		table: make(map[Hash]Timestamp),
	}
}

func (c *ConnectionTable) Match(p Packet) (time.Duration, bool) {
	hash := p.Hash()

	timestamp, ok := c.table[hash]
	if ok && p.Ack {
		d := time.Duration(p.Timestamp-timestamp) * time.Nanosecond
		return d, true
	}
	if p.Syn {
		c.table[hash] = p.Timestamp
	}

	return 0, false
}
