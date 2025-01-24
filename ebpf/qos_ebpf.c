#include "asm/types.h"
#include <stdint.h>

#include "linux/types.h"
#include "bpf/bpf_endian.h"
#include "bpf/bpf_helpers.h"
#include "linux/if_arp.h"
#include "linux/if_ether.h"
#include "linux/if_packet.h"
#include "linux/ip.h"
#include "linux/udp.h"
#include "linux/tcp.h"
#include "linux/icmp.h"
#include "linux/in.h"
#include "linux/filter.h"
#include "linux/pkt_cls.h"
#include "linux/bpf.h"
#include "linux/bpf.h"
#include "linux/pkt_sched.h"

#include "helpers.h"
#include "maps.h"
#include "macros.h"

#include "helpers.c"

__section("tc/host_egr")
int set_priority(struct __sk_buff *ctx) {
	ebpf_printk1(-1, "QOS: <-|->");
	struct ethhdr *eth_header = NULL;
	struct iphdr *ip_header = NULL;
	VALIDATE_ETH_PACKET(ctx, eth_header, return TC_ACT_OK);
        VALIDATE_IP_PACKET(ctx, eth_header, ip_header, return TC_ACT_OK);

	ctx->tc_classid = ctx->cb[0];
	ebpf_printk1(-1, "%pI4->%pI4", &ip_header->saddr, &ip_header->daddr);
	ebpf_printk1(-1, "cb %d", ctx->cb[0]);
	ctx->cb[0] = 0;
	ebpf_printk1(-1, "QOS: Set priority to [%x]", ctx->tc_classid);
	return TC_ACT_OK;
}


char __license[] __section("license") = "GPL";
