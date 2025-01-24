#ifndef MACROS_H
#define MACROS_H

#define MAX_MTU	9001
#define MIN_MTU	1500
#define MAX_UVMS 50000
#define MAX_TIMESTAMP_LIFE (350 * 1000 * 1000 * 1000UL)
#define MIN_PACKET_SIZE 64 /* mininum packet size (in bytes) */

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#define get_ebpf_macro(packet_info, print_string, ebpf_marco, ...) ebpf_marco

#define ebpf_printk(...) fbpf_printk(__VA_ARGS__)
#define ebpf_printk1(...) fbpf_printk1(__VA_ARGS__)

#if EGRESS == 1
#if HOST == 1
#define fbpf_printk(...) dbpf_printk(STR(LOCAL_HOST_ETH_INDEX) " HEGR: " __VA_ARGS__);
#define fbpf_printk1(ifindex, print_string, ...) dbpf_printk("%d HEGR: " print_string, ifindex, ##__VA_ARGS__); 
#else
#define fbpf_printk(packet_info, print_string, ...) dbpf_printk("%d EGR: " print_string, (packet_info)->local_uvm_ifindex, ##__VA_ARGS__); 
#define fbpf_printk1(ifindex, print_string, ...) dbpf_printk("%d EGR: " print_string, ifindex, ##__VA_ARGS__); 
#endif
#else
#if HOST == 1
#define fbpf_printk(...) dbpf_printk(STR(LOCAL_HOST_ETH_INDEX) " HIGR: " __VA_ARGS__);
#define fbpf_printk1(ifindex, print_string, ...) dbpf_printk("%d HIGR: " print_string, ifindex, ##__VA_ARGS__); 
#else
#define fbpf_printk(packet_info, print_string, ...) dbpf_printk("%d IGR: " print_string, (packet_info)->local_uvm_ifindex, ##__VA_ARGS__); 
#define fbpf_printk1(ifindex, print_string, ...) dbpf_printk("%d IGR: " print_string, ifindex, ##__VA_ARGS__); 
#endif
#endif

#if DEBUG == 1
#define dbpf_printk(fmt, ...) bpf_trace_printk(fmt, sizeof(fmt), ##__VA_ARGS__)
#else
#define dbpf_printk(...)
#endif

#define ibpf_printk(...)
#define ibpf_printk1(...)

#define VALIDATE_ETH_PACKET(ctx, eth_header_return, failure_return) do {							\
	if ((eth_header_return = validate_ethernet_packet(ctx)) == NULL) {							\
		failure_return;													\
	}															\
} while (0)

#define VALIDATE_ARP_PACKET(ctx, arp_header_offset, arp_headerp, arp_data, failure_return) do {					\
	if ((arp_data = validate_arp_packet(ctx, arp_header_offset, arp_headerp)) == NULL) {					\
		failure_return;													\
	} else if (*(arp_headerp) == NULL) {											\
		failure_return;													\
	}															\
} while (0)

#define VALIDATE_IP_PACKET(ctx, eth_header, ip_header, failure_return) do {							\
	if ((ip_header = validate_ip_packet(ctx, eth_header)) == NULL) {							\
		failure_return;													\
	}															\
} while (0)

#define VALIDATE_UDP_PACKET(ctx, ip_header, udp_header, failure_return) do {							\
	if ((udp_header = validate_udp_packet(ctx, ip_header)) == NULL) {							\
		failure_return;													\
	}															\
} while (0)

#define VALIDATE_TCP_PACKET(ctx, ip_header, tcp_header, failure_return) do {							\
	if ((tcp_header = validate_tcp_packet(ctx, ip_header)) == NULL) {							\
		failure_return;													\
	}															\
} while (0)

#define VALIDATE_ICMP_PACKET(ctx, ip_header, icmp_header, failure_return) do {							\
	if ((icmp_header = validate_icmp_packet(ctx, ip_header)) == NULL) {							\
		failure_return;													\
	}															\
} while (0)

#define VALIDATE_VXLAN_PACKET(ctx, udp_header, vxlan_header, failure_return) do {						\
	if ((vxlan_header = validate_vxlan_packet(ctx, udp_header)) == NULL) {							\
		failure_return;													\
	}															\
} while (0)

#define VALIDATE_DHCP_PACKET(ctx, udp_header, dhcp_header, failure_return) do {							\
	if ((dhcp_header = validate_dhcp_packet(ctx, udp_header)) == NULL) {							\
		failure_return;													\
	}															\
} while (0)

#define VALIDATE_ROUTING_PACKET(ctx, vxlan_header, routing_header, failure_return) do {						\
	if ((routing_header = validate_routing_packet(ctx, vxlan_header)) == NULL) {						\
		failure_return;													\
	}															\
} while (0)

#define VALIDATE_HOST_NAT_NONAT_METADATA_PACKET(ctx, host_nat_nonat_metadata, failure_return) do {				\
	if ((host_nat_nonat_metadata = validate_host_nat_nonat_metadata_packet(ctx)) == NULL) {					\
		failure_return;													\
	}															\
} while(0)

#define VALIDATE_LB_CLOSING_CONNECTION_METADATA(ctx, lb_closing_connection_metadata, failure_return) do {			\
	if ((lb_closing_connection_metadata = validate_lb_closing_connection_metadata(ctx)) == NULL) {				\
		failure_return;													\
	}															\
} while(0)

#define VALIDATE_ENTIRE_DHCP_PACKET(ctx, eth_header, ip_header, udp_header, dhcp_header, failure_return) do {			\
	VALIDATE_ETH_PACKET(ctx, eth_header, failure_return);									\
	VALIDATE_IP_PACKET(ctx, eth_header, ip_header, failure_return);								\
	VALIDATE_UDP_PACKET(ctx, ip_header, udp_header, failure_return);							\
	VALIDATE_DHCP_PACKET(ctx, udp_header, dhcp_header, failure_return);							\
} while(0)

#define CREATE_ENCAP_ETH(source_mac, dest_mac)											\
        struct ethhdr encap_ethhdr = {												\
                .h_source = {source_mac[0], source_mac[1], source_mac[2], source_mac[3], source_mac[4], source_mac[5]},		\
                .h_dest = {dest_mac[0], dest_mac[1], dest_mac[2], dest_mac[3], dest_mac[4], dest_mac[5]},			\
                .h_proto = bpf_htons(ETH_P_IP),											\
        }

#define CREATE_ENCAP_IP(saddr_val, daddr_val, protocol_val)									\
        struct iphdr encap_iphdr = {												\
                .version = 0x4,													\
                .ihl = 0x5,													\
                .tos = 0x0,													\
                .tot_len = 0,													\
                .id = bpf_get_prandom_u32(),											\
                .frag_off = bpf_htons(0x4000),											\
                .ttl = 0x7f,													\
                .protocol = protocol_val,											\
                .saddr = saddr_val,												\
                .daddr = daddr_val,												\
        }

#define NO_LOR_IP	0
#define CREATE_ENCAP_ROUTINGHDR(case_number_val, metadata_val, uvm_tip_val, next_hop_tip_val, lor_host_lb_ip_val, url_id_val, 	\
		url_id_type_val)												\
	struct routinghdr encap_routinghdr = {											\
		.case_number = case_number_val,											\
		.metadata = metadata_val,											\
		.url_id_type = url_id_type_val,											\
		.unused = 0,													\
		.uvm_tip = uvm_tip_val,												\
		.next_hop_tip = next_hop_tip_val,										\
		.lor_host_lb_ip = lor_host_lb_ip_val,										\
		.url_id = url_id_val,												\
	}

#define RETURN_FROM_TAIL(packet_info, ret_val_statement) do {                           					\
        __u8 ret_value = ret_val_statement;                                             					\
        packet_info->tail_call_return = ret_value;                                      					\
	packet_info->packet_info_in_use = 0;  											\
	ebpf_printk(packet_info, "classid %d", ctx->tc_classid);								\
        return ret_value;                                                               					\
} while (0)

#define RETURN_SHOT_FROM_TAIL(packet_info) RETURN_FROM_TAIL(packet_info, TC_ACT_SHOT)
#define RETURN_OK_FROM_TAIL(packet_info) 											\
	RETURN_FROM_TAIL(packet_info, TC_ACT_OK)
#define RETURN_OK_FROM_ITAIL(packet_info)											\
	if (!packet_info->is_veth_pair) {											\
		RETURN_OK_FROM_TAIL(packet_info);										\
	} else {														\
		RETURN_FROM_TAIL(packet_info, bpf_redirect(packet_info->local_uvm_ifindex, 0));					\
	}

#define UPDATE_SADDR	1

#define SPECIAL_PACKET_TIP(special_id) ((LOCAL_TIP_MASK & ~LOCAL_TIP_OFFSET_MASK) + bpf_htonl(special_id))
#define PBR_CHAIN_END_ENTRY_TIP	 	SPECIAL_PACKET_TIP(1)
#define OUTSIDE_VPC_IP_TIP 		SPECIAL_PACKET_TIP(2)
#define INVALID_TIP			SPECIAL_PACKET_TIP(3)

#define true 	1
#define false 	0

#define ENCAP_HDR_SZ (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct vxlanhdr) +		\
		sizeof(struct routinghdr))

#define MAX_TCP_HDR_SIZE	60
#define MAX_IPV4_HDR_SIZE	60

#define IP_DF			bpf_htons(0x4000)

#define IP_SIZE(ip_header)	(ip_header->ihl * 4)

#define DNS_PORT		53

#endif
