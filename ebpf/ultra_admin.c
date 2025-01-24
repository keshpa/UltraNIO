#include <stdint.h>
#include <asm/types.h>
#include <sys/param.h>
#include "string.h"

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
#include <linux/bpf.h>
#include <linux/pkt_sched.h>

#include "helpers.h"
#include "macros.h"
#include "maps.h"
#include "helpers.c"

#include "ultra_admin_helpers.h"

__section("tc/ultra_admin_egress")
int ultra_admin_egress(struct __sk_buff *ctx) {
	ebpf_printk1(-2, "ultra-admin-egress invoked");
	if (ctx == NULL) {
		ebpf_printk1(-2, "ultra-admin-egress with NULL ctx -> dead");
                return TC_ACT_SHOT;
        }

	struct packet_ultra_admin_context packet_ctx = {0};
	packet_ctx.ctx = ctx;
	ebpf_printk1(-2, "ultra-admin-egress check eth");
	VALIDATE_ETH_PACKET(ctx, packet_ctx.eth_header, return TC_ACT_SHOT);
	ebpf_printk1(-2, "ultra-admin-egress check ip");
	VALIDATE_IP_PACKET(ctx, packet_ctx.eth_header, packet_ctx.ip_header, return TC_ACT_SHOT);
	ebpf_printk1(-2, "ultra-admin-egress ip & eth found");

	mac_addr_t host_mac = {0};
	__builtin_memcpy(host_mac.mac, packet_ctx.eth_header->h_source, 6);
	ebpf_printk1(-2, "ultra-admin-egress smac %llx", host_mac.mac_64);
	mac_addr_t host_ifindex_uvm_tip = {0};
	__builtin_memcpy(host_ifindex_uvm_tip.mac, packet_ctx.eth_header->h_dest, 6);
	ebpf_printk1(-2, "ultra-admin-egress dmac %llx", host_ifindex_uvm_tip.mac_64);

	__be32 uvm_tip = host_ifindex_uvm_tip.mac_64 & 0xFFFFFFFFU;
	__u16 host_ifindex = (host_ifindex_uvm_tip.mac_64 >> 32) & 0xFFFFU;
	ebpf_printk1(-2, "ultra-admin-egress uvm tip %pI4 ifindex %d", &uvm_tip, host_ifindex);

	CREATE_ENCAP_ETH(host_mac.mac, host_mac.mac);
        CREATE_ENCAP_IP(0x0000FF1CE, 0x0000FF1CE, IPPROTO_UDP);
        CREATE_ENCAP_ROUTINGHDR(PACKET_DENONAT_INGRESS_WITHOUT_UVM_ROUTER, 
			ROUTING_HDR_METADATA_ADMIN_HOST_DNS_REPLY_PROCESSED, 0, uvm_tip, NO_LOR_IP, 
			NO_URL_ID, URL_ID_TYPE_NONE);
        encap_routinghdr.unused = 0x1234;
        if (encap_with_routinghdr(ctx, &encap_ethhdr, &encap_iphdr, &encap_routinghdr) != 0) {
		ebpf_printk1(-2, "ultra-admin-egress encap failed");
                return TC_ACT_SHOT;
        }

	ebpf_printk1(-2, "ultra-admin-egress encap redirect to %d", host_ifindex);
	int ret = REDIRECT_PKT_INGRESS(host_ifindex);
	ebpf_printk1(-2, "ultra-admin-egress redirect ret %d", ret);
	return ret;
}

char __license[] __section("license") = "GPL";
