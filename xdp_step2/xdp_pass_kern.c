#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include "bpf_helpers.h"

// nic index starts from 1, so use array type
struct bpf_map_def SEC("maps") nic_rx_cnt_map = { .type = BPF_MAP_TYPE_ARRAY,
						  .key_size = sizeof(__u32),
						  .value_size = sizeof(__u64),
						  .max_entries = 1024 };

// ip addr can be any value of __u32, so use hash type
struct bpf_map_def SEC("maps") ip_cnt_map = { .type = BPF_MAP_TYPE_HASH,
					      .key_size = sizeof(__u32),
					      .value_size = sizeof(__u64),
					      .max_entries = 1024 };

SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx)
{
	bpf_printk("hello world\n");
	return XDP_PASS;
}

SEC("xdp_drop")
int xdp_drop_func(struct xdp_md *ctx)
{
	bpf_printk("hello world\n");
	return XDP_DROP;
}

static int __always_inline handle_ip(void *ip_data, struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	if (ip_data + sizeof(struct iphdr) > data_end) {
		return XDP_PASS;
	}

	struct iphdr *ip_header = ip_data;

	__u32 ip_src = ip_header->saddr;
	bpf_printk("source ip address is %u\n", ip_src);

	__u64 *ip_cnt, ip_cnt_init_val = 1;
	ip_cnt = bpf_map_lookup_elem(&ip_cnt_map, &ip_src);
	if (ip_cnt)
		__sync_fetch_and_add(ip_cnt, 1);
	else
		bpf_map_update_elem(&ip_cnt_map, &ip_src, &ip_cnt_init_val,
				    BPF_ANY);

	return XDP_PASS;
}

static int __always_inline handle_ipv6(void *ip_data, struct xdp_md *ctx)
{
	return XDP_PASS;
}

SEC("xdp_stats")
int xdp_stats_func(struct xdp_md *ctx)
{
	bpf_printk("receive a packet\n");

	// xdp nic receive packet cnt
	__u64 *nic_rx_cnt, ifindex, nic_rx_cnt_init_val = 0;
	ifindex = ctx->ingress_ifindex;

	nic_rx_cnt = bpf_map_lookup_elem(&nic_rx_cnt_map, &ifindex);
	if (nic_rx_cnt)
		__sync_fetch_and_add(nic_rx_cnt, 1);
	else
		bpf_map_update_elem(&nic_rx_cnt_map, &ifindex,
				    &nic_rx_cnt_init_val, BPF_ANY);

	// specific ip packet cnt

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth_header = data;

	// verify the offset bound, otherwise the kernel bpf checker will fail to load this prog
	if (data + sizeof(*eth_header) > data_end) {
		return XDP_PASS;
	}

	void *ip_data = data + sizeof(*eth_header);
	if (eth_header->h_proto == htons(ETH_P_IP)) {
		return handle_ip(ip_data, ctx);
	} else if (eth_header->h_proto == htons(ETH_P_IPV6)) {
		return handle_ipv6(ip_data, ctx);
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";