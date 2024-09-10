#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

SEC("tc")
int skb_pull_vis(struct __sk_buff *skb) {
    bpf_printk("(Before Pull) Linear Size: %d, Total Size: %d", \
            skb->data_end - skb->data, skb->len);

    if (bpf_skb_pull_data(skb, skb->len) < 0) 
        return TC_ACT_OK;

    bpf_printk("(After Pull) Linear Size: %d, Total Size: %d", \
            skb->data_end - skb->data, skb->len);

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL v2";
