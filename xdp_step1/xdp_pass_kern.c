#include <linux/bpf.h>
#include "bpf_helpers.h"

SEC("xdp_pass")
int  xdp_prog_simple(struct xdp_md *ctx)
{
    bpf_printk("hello world\n");
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";