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

#include "host_ingress_helpers.h"
#include "host_ingress_helpers.c"

static void print_pkt_type(struct packet_host_context *packet_ctx) {
	if (packet_ctx == NULL || packet_ctx->packet_info == NULL) {
		return;
	}
	ebpf_printk("print_pkt_type: src tip %pI4 next hop tip %pI4", &packet_ctx->packet_info->source_tip, 
			&packet_ctx->packet_info->next_hop_tip);
	switch(packet_ctx->packet_info->packet_type) {
		case PACKET_TYPE_GARBAGE:
			ebpf_printk("case %d garbage @%s", packet_ctx->packet_info->class_number,
					(packet_ctx->packet_info->packet_path == EGRESS_PATH ? "EGR" : "INGR"));
			return;
		case PACKET_TYPE_UNDERLAY_RAW:
			ebpf_printk("case %d underlay-ray @%s", packet_ctx->packet_info->class_number,
					(packet_ctx->packet_info->packet_path == EGRESS_PATH ? "EGR" : "INGR"));
			return;
		case PACKET_TYPE_UNDERLAY_BCAST:
			ebpf_printk("case %d underlay-bcast @%s", packet_ctx->packet_info->class_number,
					(packet_ctx->packet_info->packet_path == EGRESS_PATH ? "EGR" : "INGR"));
			return;
		case PACKET_TYPE_UNDERLAY_IP:
			ebpf_printk("case %d underlay-ip @%s", packet_ctx->packet_info->class_number,
					(packet_ctx->packet_info->packet_path == EGRESS_PATH ? "EGR" : "INGR"));
			return;

		case PACKET_TYPE_NAT_REPLY_INGRESS:
			ebpf_printk("case %d nat-reply-ingress @%s", packet_ctx->packet_info->class_number,
					(packet_ctx->packet_info->packet_path == EGRESS_PATH ? "EGR" : "INGR"));
			return;
		case PACKET_TYPE_NONAT_REQUEST_REPLY_INGRESS:
			ebpf_printk("case %d nonat-reply-ingress @%s", packet_ctx->packet_info->class_number,
					(packet_ctx->packet_info->packet_path == EGRESS_PATH ? "EGR" : "INGR"));
			return;

		case PACKET_UVM_BROADCAST_EW:
			ebpf_printk("case %d broadcast @%s", packet_ctx->packet_info->class_number,
					(packet_ctx->packet_info->packet_path == EGRESS_PATH ? "EGR" : "INGR"));
			return;
		case PACKET_IP_ROUTED_EW:
			ebpf_printk("case %d ip-routed @%s", packet_ctx->packet_info->class_number,
					(packet_ctx->packet_info->packet_path == EGRESS_PATH ? "EGR" : "INGR"));
			return;

		case PACKET_NAT_EGRESS_WITHOUT_ROUTER:
			ebpf_printk("case %d nat-egress-uvm @%s", packet_ctx->packet_info->class_number,
					(packet_ctx->packet_info->packet_path == EGRESS_PATH ? "EGR" : "INGR"));
			return;
		case PACKET_NAT_EGRESS_WITH_ROUTER:
			ebpf_printk("case %d nat-egress-router @%s", packet_ctx->packet_info->class_number,
					(packet_ctx->packet_info->packet_path == EGRESS_PATH ? "EGR" : "INGR"));
			return;
		case PACKET_NONAT_EGRESS_WITHOUT_ROUTER:
			ebpf_printk("case %d nonat-egress-uvm @%s", packet_ctx->packet_info->class_number,
					(packet_ctx->packet_info->packet_path == EGRESS_PATH ? "EGR" : "INGR"));
			return;
		case PACKET_NONAT_EGRESS_WITH_ROUTER:
			ebpf_printk("case %d nonat-egress-router @%s", packet_ctx->packet_info->class_number,
					(packet_ctx->packet_info->packet_path == EGRESS_PATH ? "EGR" : "INGR"));
			return;

		case PACKET_LOR_NAT_EGRESS_WITHOUT_ROUTER:
			ebpf_printk("case %d lor-nat-egress-uvm @%s", packet_ctx->packet_info->class_number,
					(packet_ctx->packet_info->packet_path == EGRESS_PATH ? "EGR" : "INGR"));
			return;
		case PACKET_LOR_NAT_EGRESS_WITH_ROUTER:
			ebpf_printk("case %d lor-nat-egress-router @%s", packet_ctx->packet_info->class_number,
					(packet_ctx->packet_info->packet_path == EGRESS_PATH ? "EGR" : "INGR"));
			return;
		case PACKET_LOR_NONAT_EGRESS_WITHOUT_ROUTER:
			ebpf_printk("case %d lor-nonat-egress-uvm @%s", packet_ctx->packet_info->class_number,
					(packet_ctx->packet_info->packet_path == EGRESS_PATH ? "EGR" : "INGR"));
			return;
		case PACKET_LOR_NONAT_EGRESS_WITH_ROUTER:
			ebpf_printk("case %d lor-nonat-egress-router @%s", packet_ctx->packet_info->class_number,
					(packet_ctx->packet_info->packet_path == EGRESS_PATH ? "EGR" : "INGR"));
			return;

		case PACKET_DENAT_INGRESS_WITHOUT_UVM_ROUTER:
			ebpf_printk("case %d denat-ingress-uvm @%s", packet_ctx->packet_info->class_number,
					(packet_ctx->packet_info->packet_path == EGRESS_PATH ? "EGR" : "INGR"));
			return;
		case PACKET_DENAT_INGRESS_WITH_UVM_ROUTER:
			ebpf_printk("case %d denat-ingress-router @%s", packet_ctx->packet_info->class_number,
					(packet_ctx->packet_info->packet_path == EGRESS_PATH ? "EGR" : "INGR"));
			return;
		case PACKET_DENONAT_INGRESS_WITHOUT_UVM_ROUTER:
			ebpf_printk("case %d denonat-ingress-uvm @%s", packet_ctx->packet_info->class_number,
					(packet_ctx->packet_info->packet_path == EGRESS_PATH ? "EGR" : "INGR"));
			return;
		case PACKET_DENONAT_INGRESS_WITH_UVM_ROUTER:
			ebpf_printk("case %d denonat-ingress-router @%s", packet_ctx->packet_info->class_number,
					(packet_ctx->packet_info->packet_path == EGRESS_PATH ? "EGR" : "INGR"));
			return;

		case PACKET_NAT_INGRESS_EW:
			ebpf_printk("case %d nat-ingress @%s", packet_ctx->packet_info->class_number,
					(packet_ctx->packet_info->packet_path == EGRESS_PATH ? "EGR" : "INGR"));
			return;
		case PACKET_NONAT_INGRESS_EW:
			ebpf_printk("case %d nonat-ingress @%s", packet_ctx->packet_info->class_number,
					(packet_ctx->packet_info->packet_path == EGRESS_PATH ? "EGR" : "INGR"));
			return;

		case PACKET_MAC_ROUTED_EW:
			ebpf_printk("case %d mac @%s", packet_ctx->packet_info->class_number,
					(packet_ctx->packet_info->packet_path == EGRESS_PATH ? "EGR" : "INGR"));
			return;
	}
}

static enum NAT_NONAT_MAP_UPDATE_RETURN handle_denat_denonat(struct packet_host_context *packet_ctx) __attribute__((noinline)) {
	if (packet_ctx == NULL || packet_ctx->packet_info == NULL) {
		return TC_ACT_SHOT;
	}
	return is_ingress_nat_packet(packet_ctx->packet_info->packet_type) ?
		denat_packet(packet_ctx) : 
		denonat_packet(packet_ctx);
}

static int handle_arp_underlay_packets(struct packet_host_context *packet_ctx) {
	struct arphdr *arp_header;
	struct arpdata *arp_data;

	if (packet_ctx == NULL || packet_ctx->packet_info == NULL) {
		return TC_ACT_SHOT;
	}

	VALIDATE_ETH_PACKET(packet_ctx->ctx, packet_ctx->eth_header, return TC_ACT_SHOT);
	VALIDATE_ARP_PACKET(packet_ctx->ctx, sizeof(struct ethhdr), &arp_header, arp_data, return TC_ACT_SHOT);
	if (arp_data == NULL) {
		return TC_ACT_SHOT;
	}

	// There are two cases for ARP underlay packets:
	// 1. we ARPed for a underlay host because we need its mac to redirect packets to the host. In this case, the destination IP of the ARP
	//    must be our host IP and the ARP must be a reply packet (i.e. non-broadcast)
	// 2. We received a ARP request for our host IP
	// 3. noNAT UVMS are allowed to send and receive ARP on underlay (ex. EC2 instance). In this case, we need to confirm the destination IP 
	//    in ARP packet belongs to noNAT UVMs; if yes, we send to the UVM dierctly

	__be32 dest_ip = arp_data->ar_dip[0] | (arp_data->ar_dip[1] << 8) | (arp_data->ar_dip[2] << 16) | (arp_data->ar_dip[3] << 24);
	__be32 src_ip = arp_data->ar_sip[0] | (arp_data->ar_sip[1] << 8) | (arp_data->ar_sip[2] << 16) | (arp_data->ar_sip[3] << 24);

	// === Check for case 1: ARP is a reply destined for our host
	if (LOCAL_HOST_ETH_IP == dest_ip && packet_ctx->packet_info->packet_type != PACKET_TYPE_UNDERLAY_BCAST) {
		struct host_key hk = {
			.host_ip = src_ip
		};
		struct host_value hv = {0};
		__builtin_memcpy(hv.host_mac.mac, arp_data->ar_sha, 6);
		bpf_map_update_elem(&host_map, &hk, &hv, BPF_ANY);
		return TC_ACT_OK;
	}

	// === Check for case 2: ARP is requesting our host mac
	if (LOCAL_HOST_ETH_IP == dest_ip && packet_ctx->packet_info->packet_type == PACKET_TYPE_UNDERLAY_BCAST) {
		mac_addr_t host_mac = { .mac_64 = LOCAL_HOST_ETH_MAC };
		if (covert_arp_request_to_reply(packet_ctx->eth_header, arp_header, arp_data, host_mac) != 0) {
			return TC_ACT_OK;
		}
		return bpf_redirect(LOCAL_HOST_ETH_INDEX, BPF_F_EGRESS);
	}

	// === Check for case 3: ARP is destined for a no-nat ip
	packet_ctx->nat_nonat_host_group = get_nat_nonat_host_group(dest_ip, false /* is not nat */, &packet_ctx->packet_info->d_vpcid);
	if (packet_ctx->nat_nonat_host_group == NULL) {
		return TC_ACT_OK; // packet could be meant for a secondary host IP
	}

	// === Identify the host IP and UVM mac of the noNAT IP
	struct local_to_tip_value *local_to_tip_value = NULL;
	if ((local_to_tip_value = get_local_information_impl(packet_ctx->packet_info->d_vpcid, NULL, dest_ip, 0)) == NULL) {
		return TC_ACT_SHOT;
	}
	packet_ctx->packet_info->next_hop_host_ip = local_to_tip_value->host_ip;
	struct tip_value *tip_value = NULL;
	if ((tip_value = get_tip_value(local_to_tip_value->tip)) == NULL) {
		return TC_ACT_SHOT;
	}

	// === Update ARP destination mac to match the UVM mac (just for safety)
	__builtin_memcpy(arp_data->ar_dha, tip_value->uvm_mac.mac, 6);

	// === If noNAT UVM is local, redirect to UVM's ifindex. Else, vxlan encap packet as a mac-routed packet and send to UVM's host.
	// Note: we do NOT need to send this packet to host(s) responsible for the noNAT IP as this is not a IP routed packet
	if (packet_ctx->packet_info->next_hop_host_ip == LOCAL_HOST_ETH_IP) {
		packet_ctx->packet_info->next_hop_ifindex = tip_value->uvm_ifindex;
		packet_ctx->packet_info->next_hop_mac.mac_64 = tip_value->uvm_mac.mac_64;
		int redirected = send_packet_to_uvm(packet_ctx, true /* update_dmac */, false /* clone_redirect */);
		return redirected;
	} else {
		mac_addr_t host_mac = { .mac_64 = LOCAL_HOST_ETH_MAC };
		__u8 send_to_router = 0;
		packet_ctx->packet_info->next_hop_host_mac.mac_64 = get_l2_aware_host_mac(packet_ctx->packet_info->next_hop_host_ip, 
				LOCAL_HOST_ETH_IP, host_mac, LOCAL_HOST_ETH_L2_CIDR, 
				LOCAL_UNDERLAY_GW_IP, &send_to_router); 
		if (packet_ctx->packet_info->next_hop_host_mac.mac_64 == 0) {
			mac_addr_t host_mac = { .mac_64 = LOCAL_HOST_ETH_MAC };
			return arp_for_host(packet_ctx->ctx, send_to_router ? LOCAL_UNDERLAY_GW_IP : packet_ctx->packet_info->next_hop_host_ip,
					LOCAL_HOST_ETH_IP, host_mac, LOCAL_HOST_ETH_INDEX, false /* clone_redirect */);
		}
		CREATE_ENCAP_ETH(host_mac.mac, packet_ctx->packet_info->next_hop_host_mac.mac);
		CREATE_ENCAP_IP(LOCAL_HOST_ETH_IP, packet_ctx->packet_info->next_hop_host_ip, IPPROTO_UDP);
		CREATE_ENCAP_ROUTINGHDR(PACKET_MAC_ROUTED_EW, ROUTING_HDR_METADATA_NO_METADATA, 0, local_to_tip_value->tip, NO_LOR_IP, NO_URL_ID, 
				URL_ID_TYPE_NONE);
		if (encap_with_routinghdr(packet_ctx->ctx, &encap_ethhdr, &encap_iphdr, &encap_routinghdr) != 0) {
			return TC_ACT_SHOT;
		}
		return bpf_redirect(LOCAL_HOST_ETH_INDEX, 0);
	}

	return TC_ACT_SHOT;
}

static int set_up_host_main(struct __sk_buff *ctx, enum PACKET_PATH packet_path, struct packet_host_context *packet_context_ret, 
		struct host_packet_context_value **packet_info_ret) __attribute__((noinline)) {
	if (ctx == NULL || packet_info_ret == NULL || packet_context_ret == NULL) {
		return -1;
	}

	// === Get reference to a packet context struct we will use to record information about this packet
	__u32 packet_id_index = 0;
	__u32 *packet_id_ptr = bpf_map_lookup_elem(&host_packet_ids_map, &packet_id_index);
	if (packet_id_ptr == NULL) {
		return -1;
	}
	__u32 packet_id = __sync_fetch_and_add(packet_id_ptr, 1) % MAX_OUTSTANDING_PACKETS;

	struct host_packet_context_value *packet_info = bpf_map_lookup_elem(&host_packet_context_map, &packet_id);
	if (packet_info == NULL) {
		dbpf_printk("ERR: invalid pkt id %d\n", packet_id);
		return -1;
	} else if (packet_info->packet_info_in_use == 1) {
		dbpf_printk("ERR: pkt id %d in use\n", packet_id);
		return -1;
	}
	packet_info->packet_info_in_use = 1;
	__builtin_memset(packet_info, 0, sizeof(struct host_packet_context_value));

	packet_context_ret->packet_info = packet_info;
	*packet_info_ret = packet_info;
	return 0;
}

__section("tc/request_host_ingress")
int request_process_host_ingress(struct __sk_buff *ctx) {
	if (ctx == NULL) {
		return TC_ACT_SHOT;
	}
	ebpf_printk("h <-");

	struct host_packet_context_value *packet_info = NULL;
	struct packet_host_context packet_ctx = {0};
	packet_ctx.ctx = ctx;

	if (set_up_host_main(ctx, INGRESS_PATH, &packet_ctx, &packet_info) != 0) {
		if (packet_info == NULL) {
			return TC_ACT_SHOT;
		}
		RETURN_SHOT_FROM_MAIN("DROP: No pkt slot", packet_ctx);
	}

	// === Fetch packet type and basic sip/dip info
	packet_info->packet_type = PACKET_TYPE_GARBAGE;
	if (get_host_packet_context(&packet_ctx) != 0) {
		if (packet_info->packet_type == PACKET_TYPE_GARBAGE) {
			RETURN_SHOT_FROM_MAIN("DROP: garbage pkt", packet_ctx);
		} else if (packet_info->packet_type == PACKET_TYPE_UNDERLAY_RAW || packet_info->packet_type == PACKET_TYPE_UNDERLAY_BCAST) { 	
			// We allow raw (LIKE NTP/ARP) reply etc since the host may need these packets for its internal functions.
			// for ex. the host at times ARPs for other hosts (ex. hosts running VPN server) and we need the host to process
			// the ARP replies for these requests
			__u32 ret = handle_arp_underlay_packets(&packet_ctx);
			RETURN_FROM_MAIN(packet_ctx, ret);
		} else if (packet_info->packet_type == PACKET_TYPE_UNDERLAY_IP) {
			// The packet is meant for our host IP or a secondary host IP on our NIC
			RETURN_OK_FROM_MAIN(packet_ctx);
		}
		RETURN_SHOT_FROM_MAIN("DROP: unknown pkt type", packet_ctx);
	}
	print_pkt_type(&packet_ctx);

	// === Shrink packet if ip length and ctx length don't match. This may happen if we (eBPF) frragmented a large packet
	// and then looped back each fragment to our host for processing. When we fragment packets, we change the ip header
	// length but not the ctx length. Thus, we get a larger ctx->len but a smaller ip->tot_len
	__u32 expected_pkt_len = bpf_ntohs(packet_ctx.ip_header->tot_len) + sizeof(struct ethhdr);
	if (ctx->len > expected_pkt_len) {
		int ret = bpf_skb_change_tail(ctx, expected_pkt_len, 0);
		if (ret != 0) {
			ret = bpf_skb_change_tail(ctx, 700, 0);
			RETURN_SHOT_FROM_MAIN("DROP: change tail fail", packet_ctx);
		}
		VALIDATE_ETH_PACKET(ctx, packet_ctx.eth_header, RETURN_SHOT_FROM_MAIN("DROP: Bad ETH", packet_ctx));
		VALIDATE_IP_PACKET(ctx, packet_ctx.eth_header, packet_ctx.ip_header, RETURN_SHOT_FROM_MAIN("DROP: Bad IP", packet_ctx));
		ebpf_printk("IP csum: %x", bpf_ntohs(packet_ctx.ip_header->check));
	}

	// === For all packets from outside world,, ensure the packet size doesn't exceed our MTU, otherwise, we must fragment 
	// the packet beforehand as the host kernel does not account for our encap header correctly when fragmenting the packets
	if (packet_info->is_vxlan_encapped == 0) {
		__u32 mtu_len = 0;
		int ret = bpf_check_mtu(ctx, LOCAL_HOST_ETH_INDEX, &mtu_len, 0, BPF_MTU_CHK_SEGS);
		if (ret != 0 && mtu_len == 0) {
			RETURN_SHOT_FROM_MAIN("DROP: no mtu on host", packet_ctx);
		}
		if (mtu_len > MAX_MTU) {
			mtu_len = MAX_MTU;
		}
		fbpf_printk("got mtu %d pkt len %d hdr %d", mtu_len, bpf_ntohs(packet_ctx.ip_header->tot_len), ENCAP_HDR_SZ);
		if (bpf_ntohs(packet_ctx.ip_header->tot_len) + ENCAP_HDR_SZ > mtu_len) {
			mac_addr_t host_mac = { .mac_64 = LOCAL_HOST_ETH_MAC };
			fbpf_printk("need to frag");
			if (fragment_pkt(ctx, mtu_len - ENCAP_HDR_SZ, LOCAL_HOST_ETH_INDEX, &host_mac) == 0) {
				RETURN_SHOT_FROM_MAIN("DROP: frag failed", packet_ctx);
			}
			RETURN_SHOT_FROM_MAIN("DROP: frag pkt", packet_ctx);
		}
		if (packet_ctx.ip_header->protocol == IPPROTO_TCP) {
			struct tcphdr *tcp_header = NULL;
			VALIDATE_TCP_PACKET(ctx, packet_ctx.ip_header, tcp_header, RETURN_SHOT_FROM_MAIN("DROP: Bad TCP", packet_ctx));
			if (tcp_header->syn && tcp_header->ack) {
				if (adjust_tcp_mss(ctx, &packet_ctx, mtu_len - ENCAP_HDR_SZ - MAX_TCP_HDR_SIZE - MAX_IPV4_HDR_SIZE) != 0) {
					RETURN_SHOT_FROM_MAIN("DROP: mss change fail", packet_ctx);
				}
			}
		}
		fbpf_printk("processing cases...");
	}

	// === If we are not the next hop host for this packet, send the packet E/W
	if (packet_info->next_hop_is_local == 0) {
		fbpf_printk("not local");
		__u32 ret = handle_non_local_packet(&packet_ctx);
		RETURN_FROM_MAIN(packet_ctx, ret);
	}

	// === If the packet was vxlan encapped by us, we should decap here now that we know we won't be sending the packet E/W
	if (packet_info->is_vxlan_encapped == 1) {
		__u16 encap_header_size = ENCAP_HDR_SZ;
		if (decap_packet(ctx, encap_header_size, encap_header_size) != 0) {
			RETURN_SHOT_FROM_MAIN("DROP: decap fail", packet_ctx);
		}
		packet_ctx.eth_header = NULL;
		packet_ctx.ip_header = NULL;
		packet_ctx.inner_ip_header = NULL;
		packet_info->is_vxlan_encapped = 0;
		// In all cases except class 10, the packet must have an inner ETH and IP
		if (packet_info->class_number != 10) {
			VALIDATE_ETH_PACKET(ctx, packet_ctx.eth_header, RETURN_SHOT_FROM_MAIN("DROP: Bad ETH", packet_ctx));
		}
		// In all cases except class 4 and 10, the packet must have an inner IP
		if (packet_info->class_number != 10 && packet_info->class_number != 4) {
			VALIDATE_IP_PACKET(ctx, packet_ctx.eth_header, packet_ctx.ip_header, RETURN_SHOT_FROM_MAIN("DROP: Bad IP", packet_ctx));
			packet_info->source_ip = packet_ctx.ip_header->saddr;
			packet_info->destination_ip = packet_ctx.ip_header->daddr;
		}
	}

	// === For packets dependent on NAT (i.e. all cases except 4/5/10), we must have its ports and protocol. For all other
	// packets we need to fetch its ports to check it is a DNS packet.
	__u8 error_protocol_ports = get_protocol_sport_dport(&packet_ctx);
	if (packet_info->class_number != 4 && packet_info->class_number != 5 && packet_info->class_number != 10 && 
			error_protocol_ports != 0) {
		RETURN_SHOT_FROM_MAIN("DROP: no port/protocol", packet_ctx);
	}

	// === Case 11 packet in packet formats from another host with metadata information to close connection on a load balancer
	if (packet_info->class_number == 11) {
		struct lb_closing_connection_metadata *lb_closing_connection_metadata;
		VALIDATE_LB_CLOSING_CONNECTION_METADATA(ctx, lb_closing_connection_metadata, RETURN_SHOT_FROM_MAIN("DROP: Bad lb meta", packet_ctx));

		struct load_balancer_value *load_balancer_info = get_public_load_balancer_info(packet_info->lor_host_lb_ip);
		if (load_balancer_info == NULL) {
			RETURN_SHOT_FROM_MAIN("DROP: no lb", packet_ctx);
		}

		close_load_balancer_connection(load_balancer_info, lb_closing_connection_metadata->lb_backed_ip);
		RETURN_SHOT_FROM_MAIN("DROP: lb meta", packet_ctx);
	}

	// === Case 10 packet in packet formats from another host with metadata information to construct NAT/noNAT connection
	if (packet_info->class_number == 10) {
		struct host_nat_nonat_metadata *host_nat_nonat_metadata;
		VALIDATE_HOST_NAT_NONAT_METADATA_PACKET(ctx, host_nat_nonat_metadata, RETURN_SHOT_FROM_MAIN("DROP: Bad no/nat meta", packet_ctx));

		packet_info->nat_nonat_ip = host_nat_nonat_metadata->nat_nonat_ip;
		packet_info->destination_ip = host_nat_nonat_metadata->destination_ip;
		packet_info->source_ip = host_nat_nonat_metadata->source_ip;

		packet_info->nat_port = host_nat_nonat_metadata->nat_port;
		packet_info->dport = host_nat_nonat_metadata->destination_port;
		packet_info->sport = host_nat_nonat_metadata->source_port;

		if (is_egress_nat_packet(packet_info->packet_type) || is_ingress_nat_packet(packet_info->packet_type)) {
			refresh_nat_connection_map(packet_info);
		} else {
			refresh_nonat_connection_map(packet_info);
		}

		RETURN_SHOT_FROM_MAIN("DROP: no/nat meta", packet_ctx);
	}

	// === Case 8 packet in packet formats from outside world to a load balancer IP; we must change its destination IP
	// to the backend load balancer IP
	if (packet_info->class_number == 8 && packet_info->packet_type == PACKET_TYPE_PUBLIC_LOAD_BALANCER) {
		get_load_balancer_backed_ip(&packet_ctx, &packet_info->next_hop_ip);
		packet_info->nat_nonat_ip = packet_info->next_hop_ip;

		if (packet_info->next_hop_ip == -1) {
			RETURN_SHOT_FROM_MAIN("DROP: no lb", packet_ctx);
		} else if (packet_ctx.ip_header == NULL) {
			RETURN_SHOT_FROM_MAIN("DROP: Bad IP", packet_ctx);
		}

		if (set_dip_to_next_hop_ip(&packet_ctx) != 0) {
			RETURN_SHOT_FROM_MAIN("DROP: ip change fail", packet_ctx);
		}

		if (packet_info->tcp_rst || packet_info->tcp_fin) {
			close_load_balancer_connection(packet_ctx.load_balancer_info, packet_info->nat_nonat_ip);
		}

		packet_info->packet_type = PACKET_TYPE_LOAD_BALANCER_NONAT_REQUEST_REPLY_INGRESS;
		packet_info->class_number = 9;

		if (packet_ctx.nat_nonat_host_group == NULL) {
			packet_ctx.nat_nonat_host_group = get_nat_nonat_host_group(packet_info->nat_nonat_ip, false /* is not nat */, 
					&packet_info->d_vpcid);
		}
		if (get_preferred_nat_nonat_host(packet_ctx.nat_nonat_host_group, LOCAL_HOST_ETH_IP, &packet_info->next_hop_host_ip) != 0) {
			RETURN_SHOT_FROM_MAIN("DROP: no host grp", packet_ctx);
		}

		packet_info->next_hop_is_local = HOST_IP_IS_LOCAL(packet_info->next_hop_host_ip);
		// === If we cannot be the next hop host for this packet, send the packet E/W
		if (packet_info->next_hop_is_local == 0) {
			__u32 ret = handle_non_local_packet(&packet_ctx);
			RETURN_FROM_MAIN(packet_ctx, ret);
		}
	}

	// === Case 7/3/9 packet in packet formats from outside world to host for de-NAT/NONAT
	// We deNATed/deNoNated the packet and then either deliver to the UVM/next hop if we have the UVM/next hop locally on this host or 
	// encap and send to the host that actually has the UVM or it's router
	if (packet_info->class_number == 7 || packet_info->class_number == 3 || packet_info->class_number == 9) {
		enum SPECIAL_PACKET_ID original_packet_type = packet_info->packet_type;

		enum NAT_NONAT_MAP_UPDATE_RETURN update_state = handle_denat_denonat(&packet_ctx);
		if (update_state == NAT_NONAT_MAP_UPDATE_RETURN_ERROR) {
			RETURN_FROM_MAIN(packet_ctx, TC_ACT_SHOT);
		} else if (update_state == NAT_NONAT_MAP_UPDATE_RETURN_FAILURE_NO_ENTRY) {
			packet_info->metadata = ROUTING_HDR_METADATA_HOST_HOST_REQUEST_NAT_NONAT_REFRESH;
			RETURN_FROM_MAIN(packet_ctx, send_nat_nonat_to_different_host(&packet_ctx));
		}

		__u8 craft_metadata_packet = (nat_nonat_update_request_metadata(update_state) || 
				should_send_nat_nonat_metadata(packet_info->metadata));
		ebpf_printk("craft metadata packet: %d", craft_metadata_packet);

		__u8 ret = TC_ACT_SHOT;
		// We need to flip the url id type of the packet after deNAT/noNAT the packet. Ex. if the a UVM sent a 
		// NAT/noNAT packet to google.com, in the NAT/noNAT connection, we would record url_id_type as destination.
		// Now, we are processing the reply packet from google.com, thus the source is google and we need to 
		// change the url_id_type to be source.
		enum URL_ID_TYPE flipped_url_type = flip_url_id_type(packet_info->url_id_type);
		// We de-NAT/noNATed the packet, now send it to the next hop UVM. If the next hop UVM is local to the host,
		// send it directly the ifindex of the next hop UVM. Otherwise, encap the packet and send the packet to the 
		// next hop host.
		if (packet_info->next_hop_is_local == 1) {
			VALIDATE_IP_PACKET(ctx, packet_ctx.eth_header, packet_ctx.ip_header, RETURN_SHOT_FROM_MAIN("DROP: Bad IP", packet_ctx));
			ret = send_packet_to_uvm(&packet_ctx, true /* update_dmac */, craft_metadata_packet);
		} else {
			mac_addr_t host_mac = { .mac_64 = LOCAL_HOST_ETH_MAC };
			packet_info->next_hop_host_mac.mac_64 = get_host_mac(LOCAL_UNDERLAY_GW_IP, LOCAL_HOST_ETH_IP, host_mac);
			if (packet_info->next_hop_host_mac.mac_64 == 0) {
				ret =  arp_for_host(ctx, LOCAL_UNDERLAY_GW_IP, LOCAL_HOST_ETH_IP, host_mac, 
						LOCAL_HOST_ETH_INDEX, craft_metadata_packet);
			} else {
				CREATE_ENCAP_ETH(host_mac.mac, packet_info->next_hop_host_mac.mac);
				CREATE_ENCAP_IP(LOCAL_HOST_ETH_IP, packet_info->next_hop_host_ip, IPPROTO_UDP);
				CREATE_ENCAP_ROUTINGHDR(packet_info->packet_type, ROUTING_HDR_METADATA_NO_METADATA, 0, 
						packet_info->next_hop_tip, NO_LOR_IP, packet_info->url_id, flipped_url_type);
				if (encap_with_routinghdr(packet_ctx.ctx, &encap_ethhdr, &encap_iphdr, &encap_routinghdr) != 0) {
					RETURN_FROM_MAIN(packet_ctx, TC_ACT_SHOT);
				}
				ret = craft_metadata_packet ? 
					bpf_clone_redirect(packet_ctx.ctx, LOCAL_HOST_ETH_INDEX, 0) : 
					bpf_redirect(LOCAL_HOST_ETH_INDEX, 0);
			}
		}

		if (craft_metadata_packet) {
			packet_info->packet_type = original_packet_type;
			if (packet_info->class_number == 7) {
				packet_info->packet_type = original_packet_type == PACKET_TYPE_NAT_REPLY_INGRESS ? 
					PACKET_NAT_INGRESS_EW : PACKET_NONAT_INGRESS_EW;
			}
			replicate_nat_nonat_metadata(&packet_ctx, is_ingress_nat_packet(packet_info->packet_type));
			ret = TC_ACT_SHOT;
		}

		RETURN_FROM_MAIN(packet_ctx, ret);
	}

	// === Case 1/6 in packet formats from UVM to NAT/NONAT HOST for egress
	if (packet_info->class_number == 1 || packet_info->class_number == 6) {
		ebpf_printk("next hop tip %pI4 host %pI4:%llx\n", &packet_info->next_hop_tip, &packet_info->next_hop_host_ip, 
				packet_info->next_hop_host_mac.mac_64);

		struct tip_value *src_tip_info = get_tip_value(packet_info->source_tip);
		if (src_tip_info == NULL) {
			RETURN_SHOT_FROM_MAIN("DROP: Bad TIP", packet_ctx);
		}
		packet_info->source_ip = src_tip_info->uvm_ip;

		enum NAT_NONAT_MAP_UPDATE_RETURN update_state;
		__u8 is_nat = is_egress_nat_packet(packet_info->packet_type);
		if (is_nat) {
			update_state = update_nat_connection_map(&packet_ctx);
		} else {
			// Read connection map to see if we have a load balancer IP and if yes, record it in lor_host_lb_ip
			if (handle_nonat_with_load_balancer(&packet_ctx) != 0) {
				RETURN_SHOT_FROM_MAIN("DROP: lb fail", packet_ctx);
			}
			update_state = update_nonat_connection_map(packet_info);
		}

		if (update_state == NAT_NONAT_MAP_UPDATE_RETURN_ERROR) {
			RETURN_SHOT_FROM_MAIN("DROP: no/natting fail", packet_ctx);
		} else if (update_state == NAT_NONAT_MAP_UPDATE_RETURN_FAILURE_NO_ENTRY) {
			packet_info->metadata = ROUTING_HDR_METADATA_HOST_HOST_REQUEST_NAT_NONAT_REFRESH;
			RETURN_FROM_MAIN(packet_ctx, send_nat_nonat_to_different_host(&packet_ctx));
		}

		VALIDATE_ETH_PACKET(ctx, packet_ctx.eth_header, RETURN_SHOT_FROM_MAIN("DROP: Bad ETH", packet_ctx));

		__u8 craft_metadata_packet = nat_nonat_update_request_metadata(update_state) || should_send_nat_nonat_metadata(packet_info->metadata);
		__u8 close_lb_connection = packet_info->tcp_rst && packet_info->has_lb_ip;
		__u8 should_clone_packet = craft_metadata_packet || close_lb_connection;

		__u32 ret;
		if (packet_info->class_number == 1) {
			ret = send_to_underlay_router(&packet_ctx, should_clone_packet);
		} else {
			mac_addr_t host_mac = { .mac_64 = LOCAL_HOST_ETH_MAC };
			mac_addr_t lor_host_mac = { .mac_64 = get_host_mac(packet_info->lor_host_lb_ip, LOCAL_HOST_ETH_IP, host_mac) };
			if (lor_host_mac.mac_64 == 0UL) {
				ret =  arp_for_host(ctx, packet_info->lor_host_lb_ip, LOCAL_HOST_ETH_IP, host_mac,
						LOCAL_HOST_ETH_INDEX, should_clone_packet);
			} else {
				ret = send_to_l2_host(packet_ctx.eth_header, &lor_host_mac, packet_ctx.ctx, should_clone_packet);
			}
		}
		if (craft_metadata_packet) {
			replicate_nat_nonat_metadata(&packet_ctx, is_nat);
			ret = TC_ACT_SHOT;
		}

		if (close_lb_connection) {
			struct load_balancer_value *load_balancer_value = get_public_load_balancer_info(packet_info->lor_host_lb_ip);
			if (load_balancer_value == NULL) {
				RETURN_SHOT_FROM_MAIN("DROP: Bad lb", packet_ctx);
			}
			if (HOST_IP_IS_LOCAL(load_balancer_value->host_ip)) {
				close_load_balancer_connection(load_balancer_value, packet_info->nat_nonat_ip);
				ret = TC_ACT_SHOT;
			} else {
				ret = (close_connection_at_lb_host(&packet_ctx, load_balancer_value->host_ip, packet_info->nat_nonat_ip) < 0) ?
					TC_ACT_SHOT : TC_ACT_OK;
			}
		}
		RETURN_FROM_MAIN(packet_ctx, ret);
	}

	// === Case 2 in packet formats from NAT/NONAT HOST to UVM for ingress
	// We received a deNATed or deNoNATed packet from some other host and now the packet needs to make its way to the UVM or it's router
	if (packet_info->class_number == 2) {
		if (packet_ctx.eth_header == NULL) {
			ebpf_printk("no eth");
			RETURN_SHOT_FROM_MAIN("DROP: Bad ETH", packet_ctx);
		}
		mac_addr_t uvm_default_router_mac = { .mac_64 = LOCAL_UVM_DEFAULT_ROUTER_MAC };
		set_mac(packet_ctx.eth_header->h_source, &uvm_default_router_mac);
		__u32 ret = send_packet_to_uvm(&packet_ctx, true /* update_dmac */, false /* clone_redirect */);
		RETURN_FROM_MAIN(packet_ctx, ret);
	}

	// === Case 4 packet in packet from UVM to UVM or UVM broadcast packet
	if (packet_info->class_number == 4) {
		if (packet_info->packet_type == PACKET_MAC_ROUTED_EW) {
			__u32 ret = send_packet_to_uvm(&packet_ctx, true /* update_dmac */, false /* clone_redirect */);
			RETURN_FROM_MAIN(packet_ctx, ret);
		} else if (packet_info->packet_type == PACKET_UVM_BROADCAST_EW) {
			send_broadcast(&packet_ctx);
			RETURN_SHOT_FROM_MAIN("DROP: bcast", packet_ctx);
		}
	}

	// === Case 5 packet in packet from UVM to UVM
	if (packet_info->packet_type == PACKET_IP_ROUTED_EW) {
		fbpf_printk("processing case 5");
		if (packet_ctx.ip_header == NULL) {
			RETURN_SHOT_FROM_MAIN("DROP: Bad IP", packet_ctx);
		}
		// Recover the true mac of the source and destination uvm
		struct tip_value fake_tip = {0};
		struct tip_value *src_tip_info = NULL;
		src_tip_info = get_tip_value(packet_info->source_tip);
		if (src_tip_info == NULL) {
			RETURN_SHOT_FROM_MAIN("DROP: Bad TIP", packet_ctx);
		} else if (src_tip_info->sb_tip == packet_info->next_hop_sbtip) {
			set_mac(packet_ctx.eth_header->h_source, &src_tip_info->uvm_mac);
		} else {
			mac_addr_t uvm_default_router_mac = { .mac_64 = LOCAL_UVM_DEFAULT_ROUTER_MAC };
			set_mac(packet_ctx.eth_header->h_source, &uvm_default_router_mac);
		}
		set_mac(packet_ctx.eth_header->h_dest, &packet_info->next_hop_mac);

		// Convert the source/destination TIPs to IPs
		__be32 dtip = packet_info->next_hop_tip;
		__be32 stip = packet_info->source_tip;
		packet_ctx.ip_header->daddr = packet_info->next_hop_ip;
		packet_ctx.ip_header->saddr = src_tip_info->uvm_ip;
		if (update_ip_checksum(ctx, sizeof(struct ethhdr), dtip, packet_info->next_hop_ip,
				IP_SIZE(packet_ctx.ip_header), -1) != 0) {
			RETURN_SHOT_FROM_MAIN("DROP: IP csum", packet_ctx);
		}
		if (update_ip_checksum(ctx, sizeof(struct ethhdr), stip, src_tip_info->uvm_ip, 
				IP_SIZE(packet_ctx.ip_header), -1) != 0) {
			RETURN_SHOT_FROM_MAIN("DROP: IP csum", packet_ctx);
		}

		VALIDATE_ETH_PACKET(ctx, packet_ctx.eth_header, RETURN_SHOT_FROM_MAIN("DROP: Bad ETH", packet_ctx));
		VALIDATE_IP_PACKET(ctx, packet_ctx.eth_header, packet_ctx.ip_header, RETURN_SHOT_FROM_MAIN("DROP: Bad IP", packet_ctx));
		fbpf_printk("calling send_packet_to_uvm");
		__u32 ret = send_packet_to_uvm(&packet_ctx, false /* update_dmac */, false /* clone_redirect */);
		if (ret == TC_ACT_SHOT) {
			fbpf_printk("DROP: send to uvm fail");
		}
		RETURN_FROM_MAIN(packet_ctx, ret);
	}

	RETURN_OK_FROM_MAIN(packet_ctx);
}

__section("tc/load_all_maps")
int load_all_maps_ingress(struct __sk_buff *ctx) {
	return TC_ACT_OK;
}

char __license[] __section("license") = "GPL";
