//go:build ignore

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct packet_t {
    struct in6_addr src_ip;
    struct in6_addr dst_ip;
    __be16          src_port;
    __be16          dst_port;
    bool            syn;
    bool            ack;
    uint64_t        timestamp;
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 512 * 1024); // 512 KB
} pipe SEC(".maps");

SEC("tc")
int tcplat(struct __sk_buff *skb) {
  // Ignore packets that don't have IPV4 or IPV6
  // as their L3 protocol. We must convert the
  // protocol data from network byte order (big-
  // endian) to host byte order (small-endian)
  uint32_t l3_proto = bpf_ntohs(skb->protocol);
  if (l3_proto != ETH_P_IP && l3_proto != ETH_P_IPV6)
    return TC_ACT_OK;

  // Ensure that we have pulled enough data into
  // the linear section of the skb so that we can
  // read the headers through direct packet access
  uint32_t ip_header_len =
      (l3_proto == ETH_P_IP) ? sizeof(struct iphdr) : sizeof(struct ipv6hdr);
  uint32_t total_header_len =
      sizeof(struct ethhdr) + ip_header_len + sizeof(struct tcphdr);
  if (bpf_skb_pull_data(skb, total_header_len) < 0)
    return TC_ACT_OK;

  // To read the rest of the headers, we make
  // sure to be in bounds of of the linear skb
  // buffer
  uint8_t *head = (uint8_t *)(uint64_t)skb->data;
  uint8_t *tail = (uint8_t *)(uint64_t)skb->data_end;
  if (head + total_header_len > tail)
    return TC_ACT_OK;

  // Initialise the packet so that we can write
  // information to it as we process the headers.
  // Specifying {0} means it's initialised to all
  // zero values
  struct packet_t pkt = {0};

  // At this stage we can populate the packet's
  // src_ip and dst_ip
  struct iphdr *ip;
  struct ipv6hdr *ip6;
  switch (l3_proto) {
  case ETH_P_IP:
    ip = (struct iphdr *)(head + sizeof(struct ethhdr));
    if (ip->protocol != IPPROTO_TCP)
      return TC_ACT_OK;

    // Store an IPv4-mapped IPv6 address
    pkt.src_ip.in6_u.u6_addr32[3] = ip->saddr;
    pkt.dst_ip.in6_u.u6_addr32[3] = ip->daddr;
    pkt.src_ip.in6_u.u6_addr16[5] = 0xffff;
    pkt.dst_ip.in6_u.u6_addr16[5] = 0xffff;

    break;
  case ETH_P_IPV6:
    ip6 = (struct ipv6hdr *)(head + sizeof(struct ethhdr));
    if (ip6->nexthdr != IPPROTO_TCP)
      return TC_ACT_OK;

    pkt.src_ip = ip6->saddr;
    pkt.dst_ip = ip6->daddr;

    break;
  };

  // Parse the port and SYN/SYN-ACK data from
  // the TCP header
  struct tcphdr *tcp =
      (struct tcphdr *)(head + sizeof(struct ethhdr) + ip_header_len);
  if (tcp->syn) {
    pkt.src_port = tcp->source;
    pkt.dst_port = tcp->dest;
    pkt.syn = tcp->syn;
    pkt.ack = tcp->ack;
    pkt.timestamp = bpf_ktime_get_ns();

    // No need to check if this function fails
    // because we return after this with TC_ACT_OK
    // anyways
    bpf_ringbuf_output(&pipe, &pkt, sizeof(pkt), 0);
  }

  return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL v2";
