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

static inline int valid_dhcp_port(__be16 udp_port) {
	return udp_port == 67 || udp_port == 68;
}

__section("tc/macvtap_egress")
int request_macvtap_egress(struct __sk_buff *ctx) {
	if (ctx == NULL) {
		return TC_ACT_SHOT;
	}

	// ==== Drop all packets that are not DHCP
	struct ethhdr *eth_header = NULL;
	struct iphdr *ip_header = NULL;
	struct udphdr *udp_header = NULL;
	VALIDATE_ETH_PACKET(ctx, eth_header, return TC_ACT_SHOT);
        VALIDATE_IP_PACKET(ctx, eth_header, ip_header, return TC_ACT_SHOT);
	VALIDATE_UDP_PACKET(ctx, ip_header, udp_header, return TC_ACT_SHOT);

	mac_addr_t dest_mac = { .mac_64 = 0 };
        __builtin_memcpy(dest_mac.mac, eth_header->h_dest, 6);
        mac_addr_t BROADCAST_MAC = { .mac_64 = 0xFFFFFFFFFFFFFFFFUL };
        if (macs_equal(&dest_mac, &BROADCAST_MAC) != 0) {
		return TC_ACT_SHOT;
	}

	if (!valid_dhcp_port(udp_header->source) || !valid_dhcp_port(udp_header->dest)) {
		return TC_ACT_SHOT;
	}
	return TC_ACT_OK;
}
