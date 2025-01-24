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

// Only turn around eth, ip, udp/tcp headers. Does not change anything in packet_ctx->packet_info
static __u8 turn_packet_around(struct __sk_buff *ctx, struct packet_context *packet_ctx) __attribute__((noinline)) {
	if (packet_ctx == NULL || packet_ctx->eth_header == NULL || packet_ctx->ip_header == NULL
			|| packet_ctx->packet_info == NULL || ctx == NULL) {
		return -1;
	}
	__u8 temp_ha[6];
	__builtin_memcpy(temp_ha, packet_ctx->eth_header->h_source, 6);
	__builtin_memcpy(packet_ctx->eth_header->h_source, packet_ctx->eth_header->h_dest, 6);
	__builtin_memcpy(packet_ctx->eth_header->h_dest, temp_ha, 6);

	packet_ctx->ip_header->saddr = packet_ctx->packet_info->dip;
	packet_ctx->ip_header->daddr = packet_ctx->packet_info->sip;

	switch (packet_ctx->ip_header->protocol) {
		case IPPROTO_UDP: {
					  struct udphdr *udp_header = NULL;
					  VALIDATE_UDP_PACKET(ctx, packet_ctx->ip_header, udp_header, return -1);
					  udp_header->source = packet_ctx->packet_info->dport;
					  udp_header->dest = packet_ctx->packet_info->sport;
					  break;
				  }
		case IPPROTO_TCP: {
					  struct tcphdr *tcp_header = NULL;
					  VALIDATE_TCP_PACKET(ctx, packet_ctx->ip_header, tcp_header, return -1);
					  tcp_header->source = packet_ctx->packet_info->dport;
					  tcp_header->dest = packet_ctx->packet_info->sport;
					  break;
				  }
		default:
				  break;
	}
	return 0;
}


//============================= MACVTAP EGRESS SECTION =======================
#if EGRESS == 1

static int process_mac_routed_packet(struct __sk_buff *ctx, const struct packet_context_value *packet_info) __attribute__((noinline)) {
	if (ctx == NULL || packet_info == NULL) {
		return TC_ACT_SHOT;
	}
	CREATE_ENCAP_ETH(packet_info->local_host_mac.mac, packet_info->next_hop_host_mac.mac);
	CREATE_ENCAP_IP(packet_info->local_host_ip, packet_info->next_hop_host_ip, IPPROTO_UDP);
	CREATE_ENCAP_ROUTINGHDR(PACKET_MAC_ROUTED_EW, ROUTING_HDR_METADATA_NO_METADATA, packet_info->stip, packet_info->next_hop_tip, 
			NO_LOR_IP, NO_URL_ID, URL_ID_TYPE_NONE);
	if (encap_with_routinghdr(ctx, &encap_ethhdr, &encap_iphdr, &encap_routinghdr) != 0) {
		return TC_ACT_SHOT;
	}
	ebpf_printk(packet_info, "HOST M-RT-> @if %d--%llx", packet_info->local_host_ifindex, packet_info->local_host_mac.mac_64);
	return REDIRECT_PKT(packet_info->local_host_ifindex, (packet_info->next_hop_host_ip == packet_info->local_host_ip));
}

static int get_lb_mac(__be32 dest_ip, mac_addr_t *uvm_mac, const struct packet_context_value *packet_info) {
	if (uvm_mac == NULL || packet_info == NULL) {
		return -1;
	}
	struct load_balancer_key load_balancer_key = {0};
	load_balancer_key.vpc_id = packet_info->vpcid;
	load_balancer_key.load_balancer_ip = dest_ip;
	if (bpf_map_lookup_elem(&load_balancer_map, &load_balancer_key) == NULL) {
		return -1;
	}
	uvm_mac->mac_64 = LOCAL_UVM_LB_MAC;
	return 0;
}

static __be32 get_ip_mac_from_tip(__be32 tip, mac_addr_t* uvm_mac) {
	struct tip_value *value = get_tip_value(tip);
	if (value == NULL) {
		return 0;
	}
	if (uvm_mac != NULL) {
		uvm_mac->mac_64 = value->uvm_mac.mac_64;
	}
	return value->uvm_ip;
}

enum PROCESS_BROADCAST_REQUEST_STATUS {
	PROCESS_BROADCAST_REQUEST_STATUS_ERROR				= 1,
	PROCESS_BROADCAST_REQUEST_STATUS_REDIRECT			= 2,
	PROCESS_BROADCAST_REQUEST_STATUS_SEND_UNDERLAY			= 3,
	PROCESS_BROADCAST_REQUEST_STATUS_SEND_OVERLAY			= 4,
	PROCESS_BROADCAST_REQUEST_STATUS_SEND_UNDERLAY_AND_OVERLAY	= 5,
};

static enum PROCESS_BROADCAST_REQUEST_STATUS process_arp_request(struct __sk_buff *ctx, const struct packet_context *packet_ctx) {
	if (ctx == NULL || packet_ctx == NULL || packet_ctx->packet_info == NULL) {
		return PROCESS_BROADCAST_REQUEST_STATUS_ERROR;
	}
	struct arphdr *arp_header;
	struct arpdata *arp_data;
	mac_addr_t uvm_mac = { .mac_64 = 0 };

	VALIDATE_ARP_PACKET(ctx, sizeof(struct ethhdr), &arp_header, arp_data, return PROCESS_BROADCAST_REQUEST_STATUS_ERROR);

	__be32 dest_ip;
	__builtin_memcpy(&dest_ip, arp_data->ar_dip, sizeof(__be32));
	__be32 src_ip;
	__builtin_memcpy(&src_ip, arp_data->ar_sip, sizeof(__be32));
	ebpf_printk(packet_ctx->packet_info, "ARP for [%pI4] .1 [%pI4]\n", &dest_ip, &packet_ctx->packet_info->intermediary_gw_ip); 

	// === Check for GARPs
	if (src_ip == dest_ip) {
		struct subnet_secondary_ip_key key = {
			.sb_tip = packet_ctx->packet_info->src_bcast_tip,
			.secondary_ip = src_ip
		};
		struct subnet_secondary_ip_value *value = bpf_map_lookup_elem(&subnet_secondary_ip_map, &key);
		if (value != NULL) {
			value->hosted_uvm_tip = packet_ctx->packet_info->stip;
		}
		return packet_ctx->packet_info->local_default_nat ? 
			PROCESS_BROADCAST_REQUEST_STATUS_SEND_OVERLAY : 
			PROCESS_BROADCAST_REQUEST_STATUS_SEND_UNDERLAY_AND_OVERLAY;
	}
	// === Check if ARP meant for subnet default router (.1) -- if yes, we must pseudo-ARP as the default router is emulated by eBPF
	else if (dest_ip == packet_ctx->packet_info->intermediary_gw_ip) {
		uvm_mac.mac_64 = LOCAL_UVM_SUB_GW_MAC;
	} 
	// === Check if psuedo/proxy arp is anbled
	else if (packet_ctx->packet_info->send_proxy_arp_reply == 0) {
		if (get_lb_mac(dest_ip, &uvm_mac, packet_ctx->packet_info) != 0) {
			return packet_ctx->packet_info->local_default_nat ? 
				PROCESS_BROADCAST_REQUEST_STATUS_SEND_OVERLAY : 
				PROCESS_BROADCAST_REQUEST_STATUS_SEND_UNDERLAY_AND_OVERLAY;
		}
	} else {
		// Now check if ARP for a UVM within the subnet
		struct local_to_tip_key local_to_tip_key = {
			.ip = dest_ip,
			.vpc_or_mac.dip_info.mac_lookup = 0, // Search on VPC_ID
			.vpc_or_mac.dip_info.vpc_id = packet_ctx->packet_info->vpcid,
		};
		struct local_to_tip_value *value = bpf_map_lookup_elem(&local_to_tip_map, &local_to_tip_key);
		if (value == NULL) { 
			// destination IP is not assigned to a UVM in the VPC; it could still be a LB (load balancer) IP though
			// for LB IP, we return a special mac in the ARP reply
			if (get_lb_mac(dest_ip, &uvm_mac, packet_ctx->packet_info) != 0) {
				// if we are part of NO-NAT subnet, do not shoot the packet -- it could be ARPing for a underlay host
				return packet_ctx->packet_info->local_default_nat ? 
					PROCESS_BROADCAST_REQUEST_STATUS_ERROR : 
					PROCESS_BROADCAST_REQUEST_STATUS_SEND_UNDERLAY; 
			}
		} else {
			// destination IP belongs to a UVM in the VPC; lookup the mac of the UVM from the UVM's TIP
			if (get_ip_mac_from_tip(value->tip, &uvm_mac) == 0) {
				// if we are part of NO-NAT subnet, do not shoot the packet -- it could be ARPing for a underlay host
				return packet_ctx->packet_info->local_default_nat ? 
					PROCESS_BROADCAST_REQUEST_STATUS_ERROR : 
					PROCESS_BROADCAST_REQUEST_STATUS_SEND_UNDERLAY;
			}
		}
	}

	return covert_arp_request_to_reply(packet_ctx->eth_header, arp_header, arp_data, uvm_mac) == 0 ?
		PROCESS_BROADCAST_REQUEST_STATUS_REDIRECT :
		PROCESS_BROADCAST_REQUEST_STATUS_ERROR;
}

struct send_broadcast_to_each_host_context {
	struct __sk_buff *ctx;
	const struct packet_context_value *packet_info;
};

static __u64 send_broadcast_to_each_host(struct bpf_map *map, const __be32 *dest_host_ip, mac_addr_t *dest_host_mac, 
		struct send_broadcast_to_each_host_context *bctx) {
	if (dest_host_ip == NULL || dest_host_mac == NULL || bctx == NULL || bctx->ctx == NULL || bctx->packet_info == NULL) {
		return 1;
	}

	struct ethhdr *eth_header;
	VALIDATE_ETH_PACKET(bctx->ctx, eth_header, return 1);
	if (dest_host_mac->mac_64 == 0) {
		mac_addr_t underlay_router_mac = { .mac_64 = get_host_mac(bctx->packet_info->underlay_gw_ip, 
				bctx->packet_info->local_host_ip, bctx->packet_info->local_host_mac) };
		if (underlay_router_mac.mac_64 == 0) {
			arp_for_host(bctx->ctx, bctx->packet_info->underlay_gw_ip, bctx->packet_info->local_host_ip, 
					bctx->packet_info->local_host_mac, bctx->packet_info->local_host_ifindex,
					false /* clone_redirect */);
			return 1;
		}
		set_mac(eth_header->h_dest, &underlay_router_mac);
	} else {
		set_mac(eth_header->h_dest, dest_host_mac);

		struct iphdr *ip_header;
		VALIDATE_IP_PACKET(bctx->ctx, eth_header, ip_header, return 1);
		update_ip_daddr(bctx->ctx, ip_header, *dest_host_ip, sizeof(struct ethhdr), -1);
	}

	bpf_clone_redirect(bctx->ctx, bctx->packet_info->local_host_ifindex,
			(*dest_host_ip == bctx->packet_info->local_host_ip) ? BPF_F_INGRESS : 0);
	return 0;
}

static int process_nondhcp_broadcast(struct __sk_buff *ctx, struct packet_context *packet_ctx) __attribute__((noinline)) {
	if (ctx == NULL || packet_ctx == NULL || packet_ctx->eth_header == NULL || packet_ctx->packet_info == NULL) {
		return TC_ACT_SHOT;
	}

	enum PROCESS_BROADCAST_REQUEST_STATUS broadcast_state = PROCESS_BROADCAST_REQUEST_STATUS_SEND_UNDERLAY;
	if (packet_ctx->eth_header->h_proto == bpf_htons(ETH_P_ARP)) {
		broadcast_state = process_arp_request(ctx, packet_ctx);
		if (broadcast_state == PROCESS_BROADCAST_REQUEST_STATUS_ERROR) { 
			return TC_ACT_SHOT;
		} else if (broadcast_state == PROCESS_BROADCAST_REQUEST_STATUS_REDIRECT) {
			return bpf_redirect(packet_ctx->packet_info->local_uvm_ifindex, BPF_F_INGRESS);
		}
	}

	if (broadcast_state == PROCESS_BROADCAST_REQUEST_STATUS_SEND_OVERLAY || 
			broadcast_state == PROCESS_BROADCAST_REQUEST_STATUS_SEND_UNDERLAY_AND_OVERLAY) {
		struct packet_context_value *packet_info = packet_ctx->packet_info;
		mac_addr_t dhost_mac = { .mac_64 = 0 };

		// the destination IP and mac will be updated when we send the packet to the host
		CREATE_ENCAP_ETH(packet_ctx->packet_info->local_host_mac.mac, dhost_mac.mac); 	
		CREATE_ENCAP_IP(packet_ctx->packet_info->local_host_ip, 0, IPPROTO_UDP);
		CREATE_ENCAP_ROUTINGHDR(PACKET_UVM_BROADCAST_EW, ROUTING_HDR_METADATA_NO_METADATA, packet_info->stip, 
				packet_info->src_bcast_tip, NO_LOR_IP, NO_URL_ID, URL_ID_TYPE_NONE);
		if (encap_with_routinghdr(ctx, &encap_ethhdr, &encap_iphdr, &encap_routinghdr) != 0) {
			return TC_ACT_SHOT;
		}

		struct send_broadcast_to_each_host_context bctx = {
			.ctx = ctx,
			.packet_info = packet_info,
		};
		bpf_for_each_map_elem(&host_map, send_broadcast_to_each_host, &bctx, 0);	
	}

	VALIDATE_ETH_PACKET(ctx, packet_ctx->eth_header, return TC_ACT_SHOT);
	set_mac(packet_ctx->eth_header->h_source, &packet_ctx->packet_info->local_host_mac);

	if (packet_ctx->eth_header->h_proto == bpf_htons(ETH_P_ARP)) {
		struct arphdr *arp_header;
		struct arpdata *arp_data;
		VALIDATE_ARP_PACKET(ctx, sizeof(struct ethhdr), &arp_header, arp_data, return TC_ACT_SHOT);
		set_mac(arp_data->ar_sha, &packet_ctx->packet_info->local_host_mac);
	}

	return (broadcast_state == PROCESS_BROADCAST_REQUEST_STATUS_SEND_UNDERLAY || 
			broadcast_state == PROCESS_BROADCAST_REQUEST_STATUS_SEND_UNDERLAY_AND_OVERLAY) ? 
		REDIRECT_PKT_EGRESS(packet_ctx->packet_info->local_host_ifindex) : TC_ACT_SHOT;
}

static void get_url_id_type(struct packet_context_value* packet_info, __be32* url_id, enum URL_ID_TYPE* url_id_type) {
	if (packet_info == NULL || url_id == NULL || url_id_type == NULL) {
		return;
	}
	if (packet_info->destination_has_url) {
		*url_id = packet_info->destination_id;
		*url_id_type = URL_ID_TYPE_DESTINATION;
	} else if (packet_info->source_has_url) {
		*url_id = packet_info->source_id;
		*url_id_type = URL_ID_TYPE_SOURCE;
	} else {
		*url_id = NO_URL_ID;
		*url_id_type = URL_ID_TYPE_NONE;
	}
}

static int process_ip_routed_packet(struct __sk_buff *ctx, struct packet_context *packet_ctx) __attribute__((noinline)) {
	if (ctx == NULL || packet_ctx == NULL || packet_ctx->packet_info == NULL ||
			packet_ctx->eth_header == NULL || packet_ctx->ip_header == NULL) {
		return TC_ACT_SHOT;
	}
	struct packet_context_value* packet_info = packet_ctx->packet_info;
	packet_ctx->eth_header->h_proto = bpf_htons(ETH_P_IP);
	set_mac(packet_ctx->eth_header->h_source, &packet_info->local_host_mac);
	set_mac(packet_ctx->eth_header->h_dest, &packet_info->next_hop_host_mac);

	packet_info->update_l4_csum = 0;
	if (update_ip_addrs(ctx, packet_ctx, packet_info->stip, packet_info->next_hop_tip, 
				sizeof(struct ethhdr)) != 0) {
		return TC_ACT_SHOT;
	}

	__be32 url_id = NO_URL_ID;
	enum URL_ID_TYPE url_id_type = URL_ID_TYPE_NONE;
	get_url_id_type(packet_info, &url_id, &url_id_type);
	CREATE_ENCAP_ETH(packet_info->local_host_mac.mac, packet_info->next_hop_host_mac.mac);
	CREATE_ENCAP_IP(packet_info->local_host_ip, packet_info->next_hop_host_ip, IPPROTO_UDP);
	CREATE_ENCAP_ROUTINGHDR(PACKET_IP_ROUTED_EW, ROUTING_HDR_METADATA_NO_METADATA, packet_info->stip, 
			packet_info->next_hop_tip, NO_LOR_IP, url_id, url_id_type);
	if (encap_with_routinghdr(ctx, &encap_ethhdr, &encap_iphdr, &encap_routinghdr) != 0) {
		return TC_ACT_SHOT;
	}

	ebpf_printk(packet_info, "HOST IP-RT -> @if %d--%llx", packet_info->local_host_ifindex, packet_info->local_host_mac.mac_64);
	return REDIRECT_PKT(packet_info->local_host_ifindex,
			(packet_info->next_hop_host_ip == packet_info->local_host_ip));
}

static int send_nat_nonat_packet(struct __sk_buff *ctx, struct packet_context_value *packet_info) {
	if (ctx == NULL || packet_info == NULL) {
		return TC_ACT_SHOT;
	}
	__be32 url_id = NO_URL_ID;
	enum URL_ID_TYPE url_id_type = URL_ID_TYPE_NONE;
	get_url_id_type(packet_info, &url_id, &url_id_type);
	CREATE_ENCAP_ETH(packet_info->local_host_mac.mac, packet_info->next_hop_host_mac.mac);
	CREATE_ENCAP_IP(packet_info->local_host_ip, packet_info->next_hop_host_ip, IPPROTO_UDP);
	CREATE_ENCAP_ROUTINGHDR(packet_info->packet_type, packet_info->macvtap_host_metadata, packet_info->stip, 
			packet_info->intermediary_tip, packet_info->lor_host_ip, url_id, url_id_type);
	if (encap_with_routinghdr(ctx, &encap_ethhdr, &encap_iphdr, &encap_routinghdr) != 0) {
		return TC_ACT_SHOT;
	}

	return REDIRECT_PKT(packet_info->local_host_ifindex, 
			(packet_info->next_hop_host_ip == packet_info->local_host_ip));
}

static int process_nat_packet(struct __sk_buff *ctx, struct packet_context *packet_ctx) {
	if (ctx == NULL || packet_ctx == NULL || packet_ctx->packet_info == NULL || packet_ctx->ip_header == NULL) {
		return TC_ACT_SHOT;
	}

	// === Set source ip in original IP packet to NAT-IP so host natting packet knows the nat-ip we plan to use
	packet_ctx->ip_header->saddr = packet_ctx->packet_info->nat_ip;
	if (update_ip_checksum(ctx, sizeof(struct ethhdr), packet_ctx->packet_info->sip, packet_ctx->packet_info->nat_ip, 
				IP_SIZE(packet_ctx->ip_header),
				get_ip_l4_checksum_offset(packet_ctx->packet_info->protocol)) != 0) {
		return TC_ACT_SHOT;
	}
	return send_nat_nonat_packet(ctx, packet_ctx->packet_info);
}

static int process_no_nat_packet(struct __sk_buff *ctx, struct packet_context *packet_ctx) {
	if (ctx == NULL || packet_ctx == NULL || packet_ctx->packet_info == NULL) {
		return TC_ACT_SHOT;
	}
	return send_nat_nonat_packet(ctx, packet_ctx->packet_info);
}

static int get_host_and_local_mtu(struct __sk_buff *ctx, __u16 host_ifindex, __u16 uvm_ifindex, __u32* lower_mtu) {
	if (ctx == NULL || lower_mtu == NULL) {
		return -1;
	}
	__u32 mtu_len_host = 0;
	__u32 mtu_len_uvm = 0;
	int ret1 = 0;
	int ret2 = 0;

	if (host_ifindex != 0) {
		ret1 = bpf_check_mtu(ctx, host_ifindex, &mtu_len_host, 0, BPF_MTU_CHK_SEGS);
	}
	if (uvm_ifindex != 0) {
		ret2 = bpf_check_mtu(ctx, uvm_ifindex, &mtu_len_uvm, 0, BPF_MTU_CHK_SEGS);
	}
	if (ret1 != 0 || ret2 != 0) {
		return -1;
	}

	*lower_mtu = mtu_len_uvm < mtu_len_host ? mtu_len_uvm : mtu_len_host;
	*lower_mtu = *lower_mtu < MAX_MTU ? *lower_mtu : MAX_MTU;
	if (*lower_mtu == 0) {
		return -1;
	}       

	return 0;
}

static int adjust_tcp_mss(struct __sk_buff *ctx, struct packet_context* packet_ctx, __u16 fragment_sz) {
	if (ctx == NULL || packet_ctx == NULL) {
		return -1;
	}
	struct tcphdr* tcp_header = NULL;
	struct iphdr* ip_header = packet_ctx->ip_header;
	if (ip_header == NULL) {
		return -1;
	}
	VALIDATE_TCP_PACKET(ctx, ip_header, tcp_header, return -1);
	__u16 tcp_options_len = tcp_header->doff * 4 - sizeof (struct tcphdr);
	__u16 index = 0;
	__u16 command_posn = 0;
	__u16 len_posn = 1;
	__u16 value_posn = 2;
	__u8 *val = (__u8 *)(tcp_header+1);
	__u8 mss_command = 0;
	__u8 mss_offset = 0;
	__u32 mss_value = 0;

	while (index < 40 && index < tcp_options_len) {
		if (val >= (__u8 *)(__u64)ctx->data_end || (val <= (__u8 *)(__u64)ctx->data)) {
			break;
		}

		if (index == command_posn) {
			if (*val == 0x00) {
				break;
			} else if (*val == 1) {
				command_posn++;
			} else if (*val == 2) {
				mss_command = 1;
			} else {
				if (mss_command) {
					mss_command = 0;
					break;
				}
			}
			len_posn = command_posn + 1;
		} else if (index == len_posn) {
			value_posn = len_posn + 1;
			len_posn += *val; /* (*val) include size of current len posn, current length value, and current command posn */
			command_posn = len_posn - 1;
		} else if (index >= value_posn) {
			if ((val+1 < (__u8 *)(__u64)ctx->data_end)) {
				if (mss_command && mss_offset == 0) {
					mss_offset = index;
					mss_value = bpf_ntohs(*(__u16 *)val);
					break;
				}
			}
		}
		++index;
		++val;
	}
	if (mss_value < fragment_sz) {
		return 0;
	}
	__u16* tcp_mss_offset = (__u16 *)((__u8 *)(tcp_header+1) + mss_offset);
	if (tcp_mss_offset+1 <= (__u16 *)(__u64)ctx->data_end && (tcp_mss_offset > (__u16 *)(__u64)ctx->data)) {
		*tcp_mss_offset = bpf_htons(fragment_sz);
	}
	__u16 tcp_checksum_offset = sizeof(struct ethhdr) + IP_SIZE(packet_ctx->ip_header) + offsetof(struct tcphdr, check);
	// Make sure mss is something we can handle after account for encap overheads
	bpf_l4_csum_replace(ctx, tcp_checksum_offset, bpf_htons(mss_value), bpf_htons(fragment_sz), sizeof(__u16));

	VALIDATE_ETH_PACKET(ctx, packet_ctx->eth_header, return -1);
	VALIDATE_IP_PACKET(ctx, packet_ctx->eth_header, packet_ctx->ip_header, return -1);
	return 0;
}

static int update_dhcp_options_sname_cksum(struct __sk_buff *ctx, __u32 cksum_offset, struct dhcphdr* dhcp_header, 
		struct packet_context_value *packet_info) __attribute__((noinline)) {
	if (ctx == NULL || dhcp_header == NULL || packet_info == NULL) {
		return -1;
	}
	__u16 old_type_len[4];
	__u16 old_value[2 + 2 + 2];

	char old_sname[sizeof (DHCP_SERVER_NAME) + 1];
	__builtin_memcpy(old_sname, dhcp_header->sname, sizeof (DHCP_SERVER_NAME) + 1);
	__builtin_memcpy(dhcp_header->sname, DHCP_SERVER_NAME, sizeof(DHCP_SERVER_NAME) + 1);

	old_type_len[0] = *(__u16*)(&dhcp_header->offer_options.lease_option.type);
	*((__u32*)(old_value + 0)) = *((__u32*)dhcp_header->offer_options.lease_option.duration);
	dhcp_header->offer_options.lease_option.type = 51;
	dhcp_header->offer_options.lease_option.length = 4;
	*((__u32*)dhcp_header->offer_options.lease_option.duration) = 0x7FFFFFFF;

	old_type_len[1] = *(__u16*)(&dhcp_header->offer_options.router_ip_option.type);
	*((__u32*)(old_value + 2)) = *((__u32*)dhcp_header->offer_options.router_ip_option.router_ip);
	dhcp_header->offer_options.router_ip_option.type = 3;
	dhcp_header->offer_options.router_ip_option.length = 4;
	*((__u32*)dhcp_header->offer_options.router_ip_option.router_ip) = packet_info->intermediary_gw_ip;

	old_type_len[2] = *(__u16*)(&dhcp_header->offer_options.subnet_mask_option.type);
	*((__u32*)(old_value + 4)) = *((__u32*)dhcp_header->offer_options.subnet_mask_option.subnet_mask);
	dhcp_header->offer_options.subnet_mask_option.type = 1;
	dhcp_header->offer_options.subnet_mask_option.length = 4;
	*((__u32*)dhcp_header->offer_options.subnet_mask_option.subnet_mask) = packet_info->intermediary_subnet_mask;

	old_type_len[3] = *(__u16*)(&dhcp_header->offer_options.end_marker.type);
	dhcp_header->offer_options.end_marker.type = 0xFF;
	dhcp_header->offer_options.end_marker.length = 1;

	if (bpf_l4_csum_replace(ctx, cksum_offset, old_type_len[0], bpf_htons((51 << 8) | 4), 2) != 0) {
		return -1;
	} else if (bpf_l4_csum_replace(ctx, cksum_offset, old_type_len[1], bpf_htons((3 << 8) | 4), 2) != 0) {
		return -1;
	} else if (bpf_l4_csum_replace(ctx, cksum_offset, old_type_len[2], bpf_htons((1 << 8) | 4), 2) != 0) {
		return -1;
	} else if (bpf_l4_csum_replace(ctx, cksum_offset, old_type_len[3], bpf_htons((0xFF << 8) | 1), 2) != 0) {
		return -1;
	} else if (bpf_l4_csum_replace(ctx, cksum_offset, *((__u32*)(old_value + 0)), 0x7FFFFFFF, 4) != 0) {
		return -1;
	} else if (bpf_l4_csum_replace(ctx, cksum_offset, *((__u32*)(old_value + 2)), packet_info->intermediary_gw_ip, 4) != 0) {
		return -1;
	} else if (bpf_l4_csum_replace(ctx, cksum_offset, *((__u32*)(old_value + 4)), packet_info->intermediary_subnet_mask, 4) != 0) {
		return -1;
	} else if (bpf_l4_csum_replace(ctx, cksum_offset, ((__u32 *)old_sname)[0], ((__u32 *)(DHCP_SERVER_NAME))[0], 4) != 0) {
		return -1;
	} else if (bpf_l4_csum_replace(ctx, cksum_offset, ((__u32 *)old_sname)[1], ((__u32 *)(DHCP_SERVER_NAME))[1], 4) != 0) {
		return -1;
	} else if (bpf_l4_csum_replace(ctx, cksum_offset, ((__u32 *)old_sname)[2], ((__u32 *)(DHCP_SERVER_NAME))[2], 4) != 0) {
		return -1;
	} else if (bpf_l4_csum_replace(ctx, cksum_offset, ((__u32 *)old_sname)[3], ((__u32 *)(DHCP_SERVER_NAME))[3], 4) != 0) {
		return -1;
	} else if (bpf_l4_csum_replace(ctx, cksum_offset, ((__u32 *)old_sname)[4], ((__u32 *)(DHCP_SERVER_NAME))[4], 4) != 0) {
		return -1;
	} else if (bpf_l4_csum_replace(ctx, cksum_offset, ((__u32 *)old_sname)[5], ((__u32 *)(DHCP_SERVER_NAME))[5], 2) != 0) {
		return -1;
	}
	return 0;
}

static int send_dhcp_response(struct __sk_buff *ctx, struct packet_context *packet_ctx, 
		struct dhcphdr *dhcp_header) __attribute__((noinline)) {
	if (packet_ctx == NULL || packet_ctx->ip_header == NULL || packet_ctx->packet_info == NULL ||
			dhcp_header->hlen != 6 || dhcp_header->htype != 1) {
		return TC_ACT_SHOT;
	} else if (turn_packet_around(ctx, packet_ctx) != 0) {
		return TC_ACT_SHOT;
	}
	mac_addr_t router_mac = { .mac_64 = LOCAL_UVM_LB_MAC };
	__builtin_memcpy(packet_ctx->eth_header->h_source, router_mac.mac, 6);

	__u32 cksum_offset = sizeof(struct ethhdr) + IP_SIZE(packet_ctx->ip_header) + offsetof(struct udphdr, check);

	__u32 your_ip = dhcp_header->your_ip;
	__u32 server_ip = dhcp_header->server_ip;

	__u16 old_op_htype = *(__u16*)(&dhcp_header->op_code);
	dhcp_header->op_code = DHCP_OFFER;
	__u16 new_op_htype = *(__u16*)(&dhcp_header->op_code);
	dhcp_header->your_ip = packet_ctx->packet_info->intermediary_ip;
	dhcp_header->server_ip = packet_ctx->packet_info->intermediary_gw_ip;

	if (update_dhcp_options_sname_cksum(ctx, cksum_offset, dhcp_header, packet_ctx->packet_info) != 0) {
		return TC_ACT_SHOT;
	} 
	bpf_l4_csum_replace(ctx, cksum_offset, old_op_htype, new_op_htype, 2);
	bpf_l4_csum_replace(ctx, cksum_offset, your_ip, packet_ctx->packet_info->intermediary_ip, 4);
	bpf_l4_csum_replace(ctx, cksum_offset, server_ip, packet_ctx->packet_info->intermediary_gw_ip, 4);
	struct udphdr *udp_header = NULL;
	VALIDATE_ENTIRE_DHCP_PACKET(ctx, packet_ctx->eth_header, packet_ctx->ip_header,
			udp_header, dhcp_header, RETURN_SHOT_FROM_TAIL(packet_ctx->packet_info));

	packet_ctx->packet_info->update_l4_csum = 1;
	update_ip_addrs(ctx, packet_ctx, packet_ctx->packet_info->intermediary_gw_ip, BROADCAST_IP,
			sizeof(struct ethhdr));
	return REDIRECT_PKT(packet_ctx->packet_info->local_uvm_ifindex, BPF_F_INGRESS);
}

#else
//============================= MACVTAP INGRESS SECTION =======================

static int process_arp(struct __sk_buff *ctx, struct packet_context *packet_ctx) {
	if (ctx == NULL || packet_ctx == NULL || packet_ctx->packet_info == NULL) {
		return -1;
	}
	struct arphdr *arp_header;
	struct arpdata *arp_data;

	VALIDATE_ARP_PACKET(ctx, sizeof(struct ethhdr), &arp_header, arp_data, return -1);

	__be32 dest_ip;
	__builtin_memcpy(&dest_ip, arp_data->ar_dip, sizeof(__be32));
	__be32 src_ip;
	__builtin_memcpy(&src_ip, arp_data->ar_sip, sizeof(__be32));

	// === Check for GARPs
	if (src_ip != dest_ip) {
		return 0;
	}
	struct subnet_secondary_ip_key key = {
		.sb_tip = packet_ctx->packet_info->src_bcast_tip,
		.secondary_ip = src_ip
	};
	struct subnet_secondary_ip_value *value = bpf_map_lookup_elem(&subnet_secondary_ip_map, &key);
	if (value == NULL || value->hosted_uvm_tip == packet_ctx->packet_info->stip) {
		return 0;
	}

	mac_addr_t src_mac = { .mac_64 = 0 };
	__builtin_memcpy(src_mac.mac, arp_data->ar_sha, 6);
	if (macs_equal(&src_mac, &packet_ctx->packet_info->local_uvm_mac) == 0) {
		return 0;
	}	
	value->hosted_uvm_tip = 0xDEADBEEF;
	return 1;
}

#endif
