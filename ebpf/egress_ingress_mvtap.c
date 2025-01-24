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
#include "macvtap_main_egress_ingress.c"
#include "macvtap_security_rules.c"
#include "macvtap_send.c"
#include "macvtap_isend.c"
#include "macvtap_esend.c"

static int set_up_macvtap_main(struct __sk_buff *ctx, enum PACKET_PATH packet_path, struct packet_context *packet_context_ret, 
		struct packet_context_value **packet_info_ret) __attribute__((noinline)) {
	if (ctx == NULL || packet_info_ret == NULL || packet_context_ret == NULL) {
		return -1;
	}

	// === Get reference to a packet context struct we will use to record information about this packet
	__u32 packet_id_index = 0;
	__u32 *packet_id_ptr = bpf_map_lookup_elem(&packet_ids_map, &packet_id_index);
	if (packet_id_ptr == NULL) {
		return -1;
	}
	__u32 packet_id = __sync_fetch_and_add(packet_id_ptr, 1) % MAX_OUTSTANDING_PACKETS;

	struct packet_context_value *packet_info = bpf_map_lookup_elem(&packet_context_map, &packet_id);
	if (packet_info == NULL) {
		dbpf_printk("ERR: invalid pkt id %d\n", packet_id);
		return -1;
	} else if (packet_info->packet_info_in_use == 1) {
		dbpf_printk("ERR: pkt id %d in use\n", packet_id);
		return -1;
	}
	ctx->tc_classid = ctx->cb[0];
	ctx->cb[0] = packet_id;
	__builtin_memset(packet_info, 0, sizeof(struct packet_context_value));

	// === Set default values in packet_info
	packet_info->packet_info_in_use = 1;
	packet_info->stip 		= INVALID_TIP;
	packet_info->dtip 		= INVALID_TIP;
	packet_info->src_bcast_tip 	= INVALID_TIP;
	packet_info->dest_bcast_tip 	= INVALID_TIP;
	packet_info->next_hop_tip 	= INVALID_TIP;


	// === Validate eth and, if applicable, ip packets
	packet_context_ret->packet_info = packet_info;
	VALIDATE_ETH_PACKET(ctx, packet_context_ret->eth_header, return -1);
	VALIDATE_IP_PACKET(ctx, packet_context_ret->eth_header, packet_context_ret->ip_header, packet_context_ret->ip_header = NULL);

	// === Set constant values of packet_info
	packet_info->local_host_mac.mac_64 	= LOCAL_HOST_ETH_MAC;
	packet_info->local_host_ip		= LOCAL_HOST_ETH_IP;
	packet_info->underlay_gw_ip		= LOCAL_UNDERLAY_GW_IP;
	packet_info->intermediary_gw_ip 	= LOCAL_UVM_SUB_GW_IP;
	packet_info->intermediary_tip 		= LOCAL_UVM_TIP;
	packet_info->intermediary_ip 		= LOCAL_UVM_IP;
	packet_info->intermediary_subnet_mask	= LOCAL_UVM_SUB_MASK;
	if (packet_path == EGRESS_PATH) {
		packet_info->src_bcast_tip 	= LOCAL_UVM_SUB_TIP; 	// if we are a router, the packet's source must be in the same 
									// subnet as us. Thus, we can safely use LOCAL_UVM_SUB_TIP here 
									// regardless of if we are a router or not	
	} else {
		packet_info->dest_bcast_tip 	= LOCAL_UVM_SUB_TIP; 	
	}
	packet_info->vpcid 			= LOCAL_UVM_VPCID;	// we don't support vpc-peerings yet so we packet source must 
									// be same VPC as us
	packet_info->local_uvm_ifindex 		= LOCAL_UVM_PRIMARY_IFINDEX;
	packet_info->is_veth_pair 		= LOCAL_VETH_PAIR;
	packet_info->local_uvm_mac.mac_64	= LOCAL_UVM_MAC;
	packet_info->local_host_ifindex 	= LOCAL_HOST_ETH_IFINDEX;
	packet_info->send_proxy_arp_reply 	= SEND_PROXY_ARP_RESPONSE;
	packet_info->intermediary_is_router 	= LOCAL_UVM_IS_ROUTER;
	packet_info->src_dest_check_enabled 	= LOCAL_UVM_CHECK_SRC_DEST;

	packet_info->loopback_egress_ifindex 	= LOOPBACK_EGRESS_IFINDEX;

	*packet_info_ret = packet_info;
	return 0;
}

static int tail_call_starter(struct __sk_buff *ctx, struct packet_context_value **packet_info, 
		struct packet_context *packet_context)  __attribute__((noinline)) {
	if (ctx == NULL || packet_info == NULL || packet_context == NULL) {
		return -1;
	}
	__u32 index = ctx->cb[0];
	*packet_info = bpf_map_lookup_elem(&packet_context_map, &index);
	if (*packet_info == NULL) {
		return -1;
	}

	packet_context->packet_info = *packet_info;
	packet_context->eth_header = NULL;
	packet_context->ip_header = NULL;

	VALIDATE_ETH_PACKET(ctx, packet_context->eth_header, return -1);
	if ((*packet_info)->protocol != MICRO_SEG_NOTA) {
		VALIDATE_IP_PACKET(ctx, packet_context->eth_header, packet_context->ip_header, return -1);
	}
	return 0;
}

//============================= FORWARD DECLARATION ==========================

int request_macvtap_egress(struct __sk_buff *ctx);
int request_macvtap_pkt_eprocess(struct __sk_buff *ctx);
int request_macvtap_esend(struct __sk_buff *ctx);
int request_macvtap_ingress(struct __sk_buff *ctx);
int request_macvtap_pkt_iprocess(struct __sk_buff *ctx);
int request_macvtap_isend(struct __sk_buff *ctx);

//============================ TAIL CALL MAP =================================

#if EGRESS == 1
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 8);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__array(values, __u32 (void *));
} egress_prog_array_init SEC(".maps");

#else 
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 8);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__array(values, __u32 (void *));
} ingress_prog_array_init SEC(".maps");
#endif

//============================= MACVTAP EGRESS SECTION =======================
#if EGRESS == 1

static int tail_call_egress_ebpf(struct packet_context_value *packet_info, struct __sk_buff *ctx, int index) __attribute__((noinline)) {
	if (packet_info == NULL) { // just to keep the verifier happy
		return -1;
	}
	bpf_tail_call(ctx, &egress_prog_array_init, index);
	// If the tail call goes to success, we will never reach the below code
	packet_info->tail_call_return = TC_ACT_SHOT;
	return -1;
}

__section("tc/macvtap_egress")
int request_macvtap_egress(struct __sk_buff *ctx) {
	if (ctx == NULL) {
		return TC_ACT_SHOT;
	}
	struct packet_context_value *packet_info = NULL;
	struct packet_context packet_context = {0};
	if (set_up_macvtap_main(ctx, EGRESS_PATH, &packet_context, &packet_info) != 0) {
		if (packet_info == NULL) {
			return TC_ACT_SHOT;
		}
		RETURN_SHOT_FROM_MAIN("DROP: No pkt slot", packet_info);
	}

	// === If destination mac (and if applicable ip) is ours and we are a veth-pair, just okay the packet through
	if (packet_destination_match_uvm(&packet_context) == 0 && packet_info->is_veth_pair) {
		ctx->cb[0] = ctx->tc_classid;
		ebpf_printk(packet_info, "rdr-ok: classid %d cb[0] %d", ctx->tc_classid, ctx->cb[0]);
		RETURN_OK_FROM_MAIN(packet_info);
	}

	// === Verify source mac (and if applicable ip) are ours. If not, this packet is masquerading as somebody else so drop it
	// Note: Only case where the source mac may not be ours is if we are a router, loopback is enabled, **and** loopback ifindex
	// is different from out ifindex -- loopback is **never** enabled in production so this is safe
	__u8 enforce_source_mac = !(ENABLE_ROUTER_LOOPBACK && packet_info->intermediary_is_router && 
			(packet_info->loopback_egress_ifindex != packet_info->local_uvm_ifindex));
	if (enforce_source_mac == 0) {
		set_mac(packet_context.eth_header->h_source, &packet_info->local_uvm_mac);
	} else if (packet_source_match_uvm(&packet_context) != 0) {
		RETURN_SHOT_FROM_MAIN("DROP: MAC no match", packet_info);
	}

	// === Get packet protocol and if applicable, sip, dip, sport, dport
	if (get_static_packet_info(ctx, &packet_context, EGRESS_PATH) != 0) {
		RETURN_SHOT_FROM_MAIN("DROP: pkt_info bad/null", packet_info);
	}

	ebpf_printk(packet_info, "request_macvtap_egress: Src %pI4:%d", &packet_info->sip, bpf_ntohs(packet_info->sport));
	ebpf_printk(packet_info, "Protocol %c",
			((packet_info->protocol == MICRO_SEG_NOTA) 	? 'R' :
			 (packet_info->protocol == MICRO_SEG_IP) 	? 'I' :
			 (packet_info->protocol == MICRO_SEG_ICMP) 	? 'C' :
			 (packet_info->protocol == MICRO_SEG_TCP) 	? 'T' :
			 (packet_info->protocol == MICRO_SEG_UDP) 	? 'U' :
			 (packet_info->protocol == MICRO_SEG_HTTP) 	? 'H' :
			 (packet_info->protocol == MICRO_SEG_HTTPS)	? 'S' : '?')
		   );
	ebpf_printk(packet_info, "Dest ->%pI4:%d", &packet_info->dip, bpf_ntohs(packet_info->dport));

	// === If the packet is part of an established connection, we can skip directly to the esend call
	// Note: Each IP connection has a it's own entry in the connection map. All non-IP packets (i.e.
	// MICRO_SEG_NOTA protocol) are assigned a single connection map entry that is used ONLY to track
	// statistics. Non-IP packets must go through eprocess call regardless of connection map
	packet_info->tcp_syn_ack_connection &= packet_info->uvm_pkt_relation == UVM_PKT_RELATION_SRC;
	enum CONNECTION_ESTABLISHED_STATE connection_state = CONNECTION_NOT_ESTABLISHED;
	if (packet_info->protocol != MICRO_SEG_NOTA) {
		connection_state = is_established_connection(&packet_context, EGRESS_PATH, CLEANUP_ON_TCP_FIN);
	} else {
		record_raw_packet_length(ctx, packet_info, EGRESS_PATH);
	}
	if (connection_state == CONNECTION_ERROR) {
		RETURN_SHOT_FROM_MAIN("DROP: conn error", packet_info);
	} 

	// === Log packet stats if needed
	if (report_packet_connection_stats(packet_info->num_pkts, packet_info->closed_connection)) {
		send_packet_connection_stats(ctx, &packet_context, EGRESS_PATH);
	}
	
	// === Prepare packets for esend call
	if (connection_state != CONNECTION_NOT_ESTABLISHED && packet_info->is_within_vpc == 0 &&	
			packet_info->host_ips.nat_nonat_egress_policy == NAT_NONAT_EGRESS_ROUND_ROBIN) {
		// Even for established connections, we may choose a different host for each north/south packet if the 
		// the nat/nonat egress policy is set to round-robin. This is helps load-balance nat/nonat packets
		// in all hosts in the host group.
		if (get_nat_nonat_host_ip(&packet_info->host_ips, &packet_info->next_hop_host_ip) >= MAX_NAT_NONAT_HOSTS) {
			RETURN_SHOT_FROM_MAIN("DROP: Bad nat/nonat host", packet_info);
		}
		mac_addr_t host_mac = { .mac_64 = LOCAL_HOST_ETH_MAC };
		packet_info->next_hop_host_mac.mac_64 = get_l2_aware_host_mac(packet_info->next_hop_host_ip,
				LOCAL_HOST_ETH_IP, host_mac, LOCAL_HOST_ETH_L2_CIDR, LOCAL_UNDERLAY_GW_IP, NULL);
		if (packet_info->next_hop_host_mac.mac_64 == 0) {
			RETURN_FROM_MAIN(packet_info, arp_for_host(ctx, LOCAL_UNDERLAY_GW_IP, LOCAL_HOST_ETH_IP, host_mac, 
						LOCAL_HOST_ETH_IFINDEX, false /* clone_redirect */));
		}
	} else if (packet_info->is_within_vpc == 0) {
		process_macvtap_host_nat_nonat_metadata(packet_info, connection_state);
	}
	if (connection_state == CONNECTION_FULLY_ESTABLISHED) {
		// === Fetch qos level
		get_qos_level(ctx, packet_info, EGRESS_PATH);
		ebpf_printk(packet_info, "qos level %d", ctx->tc_classid);

		tail_call_egress_ebpf(packet_info, ctx, PARSE_MVTAP_ESEND);
		RETURN_FROM_MAIN(packet_info, packet_info->tail_call_return);
	}

	// === Set defaults for establishing connection entry for this packet
	packet_info->create_est_connection = packet_info->protocol == MICRO_SEG_NOTA ? 0 : 1; // IP packets can be used to create connections
	packet_info->allow_rule_stateful = packet_info->create_est_connection;

	// === Get destination tip, category, microseg/security group defaults, and classify the packet routing
	if (get_egress_destination_information(&packet_context) != 0) {
		RETURN_SHOT_FROM_MAIN("DROP: Bad dest/hop", packet_info);
	}

	// === Get source tip, category, microseg/security group defaults, and classify the packet routing between NAT/noNAT
	// if the packet is leaving the VPC. 
	// If we are a router and this is an IP packet is not generated by us, there is a chance this packet may be from the outside 
	// world going to a UVM in our subnet. In this case, we won't find the source information, but that is not a reason to 
	// drop the packet; the packet will be mac-routed so it doesn't matter if we can find the source ip or not
	if (get_egress_source_information(&packet_context) != 0) {
		if (packet_info->uvm_pkt_relation == UVM_PKT_RELATION_SRC) {
			RETURN_SHOT_FROM_MAIN("SHOT: Bad src", packet_info);
		}
		packet_info->packet_type = PACKET_MAC_ROUTED_EW;
	}

	// === Check whether source/destination IP is from a known URL
	if (packet_info->dtip != INVALID_TIP) {
		packet_info->source_has_url = get_ip_url_id(packet_info->dtip, packet_info->vpcid, packet_info->sip, &packet_info->source_id,
				true /* lru_lookup */);
		ebpf_printk(packet_info, "src url: %c id %d", (packet_info->source_has_url ? 'y' : 'n'),
				packet_info->source_id);
	}
	if (!packet_info->source_has_url && packet_info->stip != INVALID_TIP) {
		packet_info->destination_has_url = get_ip_url_id(packet_info->stip, packet_info->vpcid, packet_info->dip, 
				&packet_info->destination_id, packet_info->uvm_pkt_relation != UVM_PKT_RELATION_SRC /* lru_lookup */);
		ebpf_printk(packet_info, "dest url: %c id %d", (packet_info->destination_has_url ? 'y' : 'n'), 
				packet_info->destination_id);
	}

	// === Fetch qos level
	get_qos_level(ctx, packet_info, EGRESS_PATH);
	ebpf_printk(packet_info, "qos level %d", ctx->tc_classid);
	if (ctx->tc_classid == DROP_PRIORITY) {
		RETURN_SHOT_FROM_MAIN("SHOT: Bad src", packet_info);
	}

	// === Fetch the appropriate router information -- note: information on designated router was recorded when we fetched 
	//     source/destination information
	// A packet follows through routers in the following order:
	// source uvm -> source desginated router -> source PBR -> source LOR -> destination PBR -> destination designated router -> destination uvm
	// destination LOR is not considered
	enum NEXT_HOP_ROUTER_TYPE router_type = NEXT_HOP_ROUTER_NONE;
	if (packet_info->uvm_pkt_relation == UVM_PKT_RELATION_SRC && packet_info->source_router_type == NEXT_HOP_ROUTER_DESIGNATED) {
		router_type = NEXT_HOP_ROUTER_UVM;
	} else if (packet_info->uvm_pkt_relation != UVM_PKT_RELATION_DEST_DESIGNATED &&
			(packet_info->source_router_type == NEXT_HOP_ROUTER_PBR_SOURCE || 
			 packet_info->source_router_type == NEXT_HOP_ROUTER_LOR_UVM_OR_PBR_SOURCE || 
			 packet_info->source_router_type == NEXT_HOP_ROUTER_LOR_SUBNET_OR_PBR_SOURCE)) {
		if (get_next_hop_pbr(packet_info, FETCH_EGRESS_PBR, (packet_info->uvm_pkt_relation == UVM_PKT_RELATION_SRC || 
						packet_info->uvm_pkt_relation == UVM_PKT_RELATION_SRC_DESIGNATED)) == GET_ROUTER_FOUND) {
			router_type = NEXT_HOP_ROUTER_UVM;
		} else if (packet_info->source_router_type == NEXT_HOP_ROUTER_LOR_UVM_OR_PBR_SOURCE) {
			packet_info->source_router_type = NEXT_HOP_ROUTER_LOR_UVM; 
		} else if (packet_info->source_router_type == NEXT_HOP_ROUTER_LOR_SUBNET_OR_PBR_SOURCE) {
			packet_info->source_router_type = NEXT_HOP_ROUTER_LOR_SUBNET;
		}
	} 
	if (router_type == NEXT_HOP_ROUTER_NONE && 
			(packet_info->source_router_type == NEXT_HOP_ROUTER_LOR_UVM || packet_info->source_router_type == NEXT_HOP_ROUTER_LOR_SUBNET) &&
			(packet_info->uvm_pkt_relation == UVM_PKT_RELATION_SRC || packet_info->uvm_pkt_relation == UVM_PKT_RELATION_SRC_DESIGNATED ||
			 packet_info->uvm_pkt_relation == UVM_PKT_RELATION_SRC_LAST_PBR)) {
		enum GET_ROUTER_RETURN ret = get_lor_information(packet_info);
		if (ret == GET_ROUTER_ERROR) {
			RETURN_SHOT_FROM_MAIN("DROP: Bad LOR", packet_info);
		} else if (ret == GET_ROUTER_FOUND) {
			router_type = packet_info->source_router_type;
		}
	} 
	if (router_type == NEXT_HOP_ROUTER_NONE && (packet_info->destination_router_type == NEXT_HOP_ROUTER_PBR_DESTINATION || 
				packet_info->destination_router_type == NEXT_HOP_ROUTER_DESIGNATED_OR_PBR_DESTINATION)) {
		if (get_next_hop_pbr(packet_info, !FETCH_EGRESS_PBR, true) == GET_ROUTER_FOUND) {
			router_type = NEXT_HOP_ROUTER_UVM;
		} else if (packet_info->destination_router_type == NEXT_HOP_ROUTER_DESIGNATED_OR_PBR_DESTINATION) {
			router_type = NEXT_HOP_ROUTER_UVM;
		} else {
			router_type = NEXT_HOP_ROUTER_NONE;
		}
	}
	if (router_type == NEXT_HOP_ROUTER_HOST) {
		packet_info->is_within_vpc = 0;
		packet_info->is_within_subnet = 0;
		packet_info->check_dingress_policy = 0; // packet is headed for a router, so don't check destination ingress rules 
	} else if (router_type == NEXT_HOP_ROUTER_UVM) {
		packet_info->packet_type = PACKET_MAC_ROUTED_EW;
		packet_info->is_within_vpc = 1;
		packet_info->is_within_subnet = 1;
		packet_info->check_dingress_policy = 0; // packet is headed for a router, so don't check destination ingress rules 
	}
	ebpf_printk(packet_info, "request_macvtap_egress: relation %d\n", packet_info->uvm_pkt_relation);
	ebpf_printk(packet_info, "Src: %pI4=%pI4", &packet_info->sip, &packet_info->stip);
	ebpf_printk(packet_info, "Next hop: %pI4=%pI4", &packet_info->next_hop_ip, &packet_info->next_hop_tip);
	ebpf_printk(packet_info, "IDs %d->%d", packet_info->source_id, packet_info->destination_id);
	ebpf_printk(packet_info, "Dest: %pI4 Within VPC %d", &packet_info->dip, packet_info->is_within_vpc);

	// === For packets headed outside the VPC, determine if we should nat or no-nat the packet based on the policy based routing rules
	if (packet_info->is_within_vpc == 0) {
		__u8 nat_nonat_with_router = (packet_info->intermediary_is_router == 1 && packet_info->uvm_pkt_relation != UVM_PKT_RELATION_SRC);
		process_macvtap_host_nat_nonat_metadata(packet_info, connection_state);
		if (should_nat_packet(packet_info->stip, packet_info->next_hop_ip, packet_info->local_default_nat)) {
			// Ensure that the destination IP is indeed outside the VPC; there is a corner case where a packet may be headed
			// for a destination IP within VPC but the destination is NOT a UVM. In this case, we declared the packet as outside
			// VPC eariler, however, such packets are only supported if the source UVM is no-nat, which it clearly is not in 
			// this case. So, drop packets headed for non-UVMs within the VPC
			if ((packet_info->next_hop_ip & LOCAL_UVM_VPC_MASK) == (LOCAL_UVM_IP & LOCAL_UVM_VPC_MASK)) {
				RETURN_SHOT_FROM_MAIN("DROP: Bad dest nonat ?", packet_info);
			}
			packet_info->packet_type = nat_nonat_with_router ?
				(router_type == NEXT_HOP_ROUTER_HOST ?
				 PACKET_LOR_NAT_EGRESS_WITH_ROUTER : PACKET_NAT_EGRESS_WITH_ROUTER) :
				(router_type == NEXT_HOP_ROUTER_HOST ?
				 PACKET_LOR_NAT_EGRESS_WITHOUT_ROUTER : PACKET_NAT_EGRESS_WITHOUT_ROUTER);
			if (get_nat_ip_host(packet_info) >= MAX_NAT_NONAT_HOSTS) {
				RETURN_SHOT_FROM_MAIN("DROP: Bad NAT host", packet_info);
			}
		} else {
			packet_info->packet_type = nat_nonat_with_router ? 
				(router_type == NEXT_HOP_ROUTER_HOST ? 
				 PACKET_LOR_NONAT_EGRESS_WITH_ROUTER : PACKET_NONAT_EGRESS_WITH_ROUTER) :
				(router_type == NEXT_HOP_ROUTER_HOST ? 
				 PACKET_LOR_NONAT_EGRESS_WITHOUT_ROUTER : PACKET_NONAT_EGRESS_WITHOUT_ROUTER);
			if (get_no_nat_host(packet_info) >= MAX_NAT_NONAT_HOSTS) {
				RETURN_SHOT_FROM_MAIN("DROP: Bad noNAT host", packet_info);
			}
		}
	}

	// === Get the next hop host mac for egressing packet.
	// No distinction is made whether the packet is NAT/noNAT/Broadcast or within VPC or outside VPC or whatever.
	mac_addr_t host_mac = { .mac_64 = LOCAL_HOST_ETH_MAC };
	if (packet_info->next_hop_ip == 0xFFFFFFFF) {
		packet_info->next_hop_host_mac.mac_64 = 0;
	} else {
		__u8 send_to_router = 0;
		packet_info->next_hop_host_mac.mac_64 = get_l2_aware_host_mac(packet_info->next_hop_host_ip, LOCAL_HOST_ETH_IP, 
				host_mac, LOCAL_HOST_ETH_L2_CIDR, LOCAL_UNDERLAY_GW_IP, &send_to_router);
		if (packet_info->next_hop_host_mac.mac_64 == 0) {
			RETURN_FROM_MAIN(packet_info, arp_for_host(ctx, send_to_router ? LOCAL_UNDERLAY_GW_IP : packet_info->next_hop_host_ip,
						LOCAL_HOST_ETH_IP, host_mac, LOCAL_HOST_ETH_IFINDEX, false /* clone_redirect */));
		}
	}

	if (packet_info->uvm_pkt_relation != UVM_PKT_RELATION_SRC && packet_info->intermediary_is_router == 1) {
		// We are the packet's router so we don't evaluate any security rules; the source/destination will evaluate 
		// egress and ingress rules respectively
		if (connection_state != CONNECTION_ESTABLISHED_WITHOUT_NEXTHOP) {
			struct security_action_reason reason = {
				.action = RULE_EVALUATION_ACTION_ALLOW,
				.etcd_rule_id = NO_ETCD_RULE_ID,
			};
			update_pkt_stat_log(ctx, &packet_context, &reason, RULE_TYPE_ROUTER_BYPASS, EGRESS_PATH, 0);
		}
		tail_call_egress_ebpf(packet_info, ctx, PARSE_MVTAP_ESEND);
		RETURN_FROM_MAIN(packet_info, packet_info->tail_call_return);
	}
	ibpf_printk(packet_info, "connection_state == CONNECTION_ESTABLISHED_WITHOUT_NEXTHOP: %d",
			connection_state == CONNECTION_ESTABLISHED_WITHOUT_NEXTHOP);
	tail_call_egress_ebpf(packet_info, ctx, 
			connection_state == CONNECTION_ESTABLISHED_WITHOUT_NEXTHOP ? PARSE_MVTAP_ESEND : PARSE_MVTAP_EPROCESS);
	// If the tail call goes to success, we will never reach the below code
	RETURN_FROM_MAIN(packet_info, packet_info->tail_call_return);
}

__section("tc/tail_macvtap_eprocess")
int request_macvtap_pkt_eprocess(struct __sk_buff *ctx) {
	struct packet_context_value *packet_info = NULL;
	struct packet_context packet_context = {0};
	if (tail_call_starter(ctx, &packet_info, &packet_context) != 0) {
		if (packet_info == NULL) {
			return TC_ACT_SHOT;
		}
		RETURN_SHOT_FROM_TAIL(packet_info);
	}

	// === Determine if ingress/egress rules should even be evaluated
	// For egress, if packet is not generated locally, don't check egress rules as the original packet sender would have evaluated 
	// their own egress rules
	// For ingress, if the destination is not the VPC then we cannot even evaluate its ingress rules. Also, if the caller told us
	// not to check destination's ingress rules, then adhere to the caller's wish.
	__u8 evaluate_egress = packet_info->uvm_pkt_relation == UVM_PKT_RELATION_SRC; 
	__u8 evaluate_ingress = packet_info->check_dingress_policy == 1 && packet_info->is_within_vpc == 1;

	struct security_action_reason reason = {
		.action = RULE_EVALUATION_ACTION_ALLOW,
		.etcd_rule_id = NO_ETCD_RULE_ID,
	};
	if (evaluate_ingress == 0 && evaluate_egress == 0) {
		// Since, there are no rule to check, simply ok the packet through
		update_pkt_stat_log(ctx, &packet_context, &reason, RULE_TYPE_NO_RULES, EGRESS_PATH, 0);
		HANDLE_RULE_EVALUATION_RESULT(RULE_EVALUATION_ACTION_ALLOW, HANDLE_ALLOW_RESULT, !UPDATE_CREATE_CONNECTION, 0, EGRESS_PATH);
		// HANDLE_RULE_EVALUATION_RESULT will return from this function
	}

	// === For packets that were generated by us (egress UVM), we must check our egress category, microseg, security group rules.
	// For all other packets, we can skip the egress checks as the true packet generator UVM would have checked its egress rules
	// before sending us the packet (ex. UVM A sends a packet mean from UVM B to its router first and we are the router who is now
	// egressing A's packet out to B; A would have checked its egress policies before sending the packet to us in the first place.
	// So, now we can just check B's ingress rules)

	reason.action = RULE_EVALUATION_ACTION_NO_ACTION;
	reason.etcd_rule_id = NO_ETCD_RULE_ID;
	if (evaluate_egress) {
		__u8 handle_allow_result = evaluate_ingress ? !HANDLE_ALLOW_RESULT : HANDLE_ALLOW_RESULT;
		// === Check egress microsegmentation rules for explicit deny/allow rules
		if (packet_info->local_micro_seg_enabled == 1) {
			EVALUATE_RULE(should_drop_microseg(packet_info, EGRESS_PATH, &reason, LOCAL), &reason, RULE_TYPE_MICRO_SEG, "emicroseg", EGRESS_PATH);
			HANDLE_RULE_EVALUATION_RESULT(reason.action, handle_allow_result, UPDATE_CREATE_CONNECTION, packet_info->allow_rule_stateful, 
					EGRESS_PATH);
		}

		// === Check for explicit allow/deny rules in category rules
		if (reason.action == RULE_EVALUATION_ACTION_NO_ACTION) {
			EVALUATE_RULE(should_drop_category(packet_info, &reason), &reason, RULE_TYPE_CATEGORY,  "ecategory", EGRESS_PATH);
			HANDLE_RULE_EVALUATION_RESULT(reason.action, handle_allow_result, UPDATE_CREATE_CONNECTION, RULE_STATEFUL, EGRESS_PATH);
		}

		// === If we don't need to check destination rules, microseg and category evaluated to no-action, and security group is disabled, 
		// then we can perform the default action -- which is ALLOW-stateful. 
		__u8 evaluate_security_grp = (reason.action == RULE_EVALUATION_ACTION_NO_ACTION && packet_info->local_security_group_enabled == 1 && 
				packet_info->dest_within_subnet == 0);
		if (evaluate_security_grp == 0 && evaluate_ingress == 0) {
			HANDLE_RULE_EVALUATION_RESULT(RULE_EVALUATION_ACTION_ALLOW, HANDLE_ALLOW_RESULT, UPDATE_CREATE_CONNECTION, 
					RULE_STATEFUL, EGRESS_PATH);
			// HANDLE_RULE_EVALUATION_RESULT will return from this function
		}

		// === If there was no explict allow rule from microseg and the packet is headed across subnets or outside the vpc, 
		// check egress security group for explicit deny/allow rules
		if (evaluate_security_grp) {
			EVALUATE_RULE(should_drop_security_group(packet_info, EGRESS_PATH, &reason, LOCAL), &reason, RULE_TYPE_SECURITY_GROUP, 
					"esecurity-grp", EGRESS_PATH);
			// If the destination is not within the VPC, then there are no destination ingress rules to check we so we can
			// act on the allow rules of our egress security group
			HANDLE_RULE_EVALUATION_RESULT(reason.action, handle_allow_result, UPDATE_CREATE_CONNECTION,
					packet_info->allow_rule_stateful, EGRESS_PATH);
		}
	}

	if (evaluate_ingress == 0) {
		HANDLE_RULE_EVALUATION_RESULT(RULE_EVALUATION_ACTION_ALLOW, HANDLE_ALLOW_RESULT, !UPDATE_CREATE_CONNECTION, 0, 
				EGRESS_PATH);
		// HANDLE_RULE_EVALUATION_RESULT will return from this function
	}

	// === We now check the ingress rules of the destination. Note: we will NOT get here if there is a router as next hop or the 
	// destination is outside the VPC

	// === Check ingress microsegmentation rules of the destination for explicit deny/allow rules
	EVALUATE_RULE(should_drop_microseg(packet_info, INGRESS_PATH, &reason, REMOTE), &reason, RULE_TYPE_MICRO_SEG, "iemicroseg", EGRESS_PATH);
	HANDLE_RULE_EVALUATION_RESULT(reason.action, HANDLE_ALLOW_RESULT, !UPDATE_CREATE_CONNECTION, 0, EGRESS_PATH);

	if (packet_info->dest_within_subnet == 1) {
		// === There is no explict microseg rule and the default microseg rule is not deny. Further, the packet is within subnet, 
		// so there is no security group to evaluate. So, just follow the default rule -- ALLOW
		HANDLE_RULE_EVALUATION_RESULT(RULE_EVALUATION_ACTION_ALLOW, HANDLE_ALLOW_RESULT, !UPDATE_CREATE_CONNECTION, 0, EGRESS_PATH); 
	} else {
		// === Check ingress security group rules of the destination for explicit deny/allow rules
		EVALUATE_RULE(should_drop_security_group(packet_info, INGRESS_PATH, &reason, REMOTE), &reason, RULE_TYPE_SECURITY_GROUP, 
				"iesecurity-grp", EGRESS_PATH);
		HANDLE_RULE_EVALUATION_RESULT(reason.action, HANDLE_ALLOW_RESULT, !UPDATE_CREATE_CONNECTION, 0, EGRESS_PATH);
	}

	// === We won't get here, but we need this to keep the verifier happy
	HANDLE_RULE_EVALUATION_RESULT(RULE_EVALUATION_ACTION_ALLOW, HANDLE_ALLOW_RESULT, !UPDATE_CREATE_CONNECTION, 0, EGRESS_PATH); 
}

__section("tc/tail_macvtap_esend")
int request_macvtap_esend(struct __sk_buff *ctx) {
	struct packet_context_value *packet_info = NULL;
	struct packet_context packet_context = {0};
	if (tail_call_starter(ctx, &packet_info, &packet_context) != 0) {
		ibpf_printk1(-1, "request_macvtap_esend failure");
		if (packet_info == NULL) {
			return TC_ACT_SHOT;
		}
		RETURN_SHOT_FROM_TAIL(packet_info);
	}
	ebpf_printk(packet_info, "request_macvtap_esend: relation %d\n", packet_info->uvm_pkt_relation);
	ebpf_printk(packet_info, "Src: %pI4=%pI4", &packet_info->sip, &packet_info->stip);
	ebpf_printk(packet_info, "Next hop: %pI4=%pI4", &packet_info->next_hop_ip, &packet_info->next_hop_tip);
	ebpf_printk(packet_info, "Dest: %pI4 - sending", &packet_info->dip);

	ctx->cb[0] = ctx->tc_classid;

	// === Handle (respond) to DHCP broadacst request
	if (packet_info->dhcp_request) {
		if (packet_context.ip_header == NULL) {
			RETURN_SHOT_FROM_TAIL(packet_info);
		}
		struct udphdr *udp_header = NULL;
		struct dhcphdr *dhcp_header = NULL;
		VALIDATE_UDP_PACKET(ctx, packet_context.ip_header, udp_header, RETURN_SHOT_FROM_TAIL(packet_info));
		VALIDATE_DHCP_PACKET(ctx, udp_header, dhcp_header, RETURN_SHOT_FROM_TAIL(packet_info));
		if (dhcp_header->op_code == DHCP_DISCOVER || dhcp_header->op_code == DHCP_REQUEST) {
			RETURN_FROM_TAIL(packet_info, send_dhcp_response(ctx, &packet_context, dhcp_header));
		}
	}

	// === Handle nondhcp broadcast packets
	if (packet_info->packet_type == PACKET_UVM_BROADCAST_EW) {
		RETURN_FROM_TAIL(packet_info, process_nondhcp_broadcast(ctx, &packet_context));
	}

	// === Update destination macs and ips as needed of the inner packet
	if (packet_info->update_dest_ip == 1) {
		if (update_sip_dip_with_next_hop(ctx, &packet_context, EGRESS_PATH) != 0) {
			RETURN_SHOT_FROM_TAIL(packet_info);
		}
	}

	// === Create an entry in connection map if requested
	if (packet_info->create_est_connection == 1 && create_established_connection(&packet_context, EGRESS_PATH, NEXT_HOP_EVALUATED) != 0) {
		RETURN_SHOT_FROM_TAIL(packet_info);
	}

	__u32 mtu_len = 0;
	__u8 ret = get_host_and_local_mtu(ctx, LOCAL_HOST_ETH_IFINDEX, LOCAL_UVM_PRIMARY_IFINDEX, &mtu_len);
	if (ret != 0 || mtu_len == 0) {
		RETURN_SHOT_FROM_TAIL(packet_info);
	}

	// === Handle mac-routed packets within a subnet, including that to a designated router (or with src/dest IP mismatch)
	// Also includes non-IP packets, like ARP-reply, NTP
	if (packet_info->packet_type == PACKET_MAC_ROUTED_EW) {
		if (ctx->len > mtu_len) {
			RETURN_SHOT_FROM_TAIL(packet_info);
		}
		RETURN_FROM_TAIL(packet_info, process_mac_routed_packet(ctx, packet_info));
	}

	if (packet_context.ip_header != NULL && packet_context.ip_header->protocol == IPPROTO_TCP && 
			(packet_info->tcp_syn_connection != 0 || packet_info->tcp_syn_ack_connection != 0)) {
		if (adjust_tcp_mss(ctx, &packet_context, mtu_len - ENCAP_HDR_SZ - MAX_TCP_HDR_SIZE - MAX_IPV4_HDR_SIZE) != 0) {
			RETURN_SHOT_FROM_TAIL(packet_info);
		}
	}

	// === Handle within VPC ip-routed packets	
	if (packet_info->packet_type == PACKET_IP_ROUTED_EW && packet_info->is_within_vpc == 1) {
		RETURN_FROM_TAIL(packet_info, process_ip_routed_packet(ctx, &packet_context));
	}

	// === Handle outside VPC packet
	if (packet_info->is_within_vpc == 0) {
		if (packet_info->packet_type == PACKET_NAT_EGRESS_WITHOUT_ROUTER || 
				packet_info->packet_type == PACKET_NAT_EGRESS_WITH_ROUTER ||
				packet_info->packet_type == PACKET_LOR_NAT_EGRESS_WITHOUT_ROUTER ||
				packet_info->packet_type == PACKET_LOR_NAT_EGRESS_WITH_ROUTER) {
			RETURN_FROM_TAIL(packet_info, process_nat_packet(ctx, &packet_context));
		}

		RETURN_FROM_TAIL(packet_info, process_no_nat_packet(ctx, &packet_context));
	}

	RETURN_SHOT_FROM_TAIL(packet_info);
}

#else
//============================= MACVTAP IGRESS SECTION =======================
static int tail_call_ingress_ebpf(struct packet_context_value *packet_info, struct __sk_buff *ctx, int index) __attribute__((noinline)) {
	if (packet_info == NULL) { // just to keep the verifier happy
		return -1;
	}
	bpf_tail_call(ctx, &ingress_prog_array_init, index);
	packet_info->tail_call_return = TC_ACT_SHOT;
	return -1;
}

#define RETURN_OK_FROM_IMAIN(packet_info)											\
	if (!packet_info->is_veth_pair) {											\
		RETURN_OK_FROM_MAIN(packet_info);										\
	} else {														\
		RETURN_FROM_TAIL(packet_info, bpf_redirect(packet_info->local_uvm_ifindex, 0));					\
	}

__section("tc/macvtap_ingress")
int request_macvtap_ingress(struct __sk_buff *ctx) {
	if (ctx == NULL) {
		return TC_ACT_SHOT;
	}
	struct packet_context_value *packet_info = NULL;
	struct packet_context packet_context = {0};
	if (set_up_macvtap_main(ctx, INGRESS_PATH, &packet_context, &packet_info) != 0) {
		if (packet_info == NULL) {
			return TC_ACT_SHOT;
		}
		RETURN_SHOT_FROM_MAIN("DROP: No slot", packet_info);
	}

	// === If source mac (and if applicable ip) is ours and we are a veth-pair, just okay the packet through
	ebpf_printk(packet_info, "is veth %d", packet_info->is_veth_pair);
	if (packet_source_match_uvm(&packet_context) == 0 && packet_info->is_veth_pair) {
		ebpf_printk(packet_info, "rdr to my egress");
		RETURN_FROM_TAIL(packet_info, bpf_redirect(packet_info->local_uvm_ifindex, BPF_F_EGRESS));
	}

	// === Verify destination mac (and if applicable ip) are ours. If not, this packet is masquerading as somebody else so drop it
	if (packet_destination_match_uvm(&packet_context) != 0) {
		RETURN_SHOT_FROM_MAIN("DROP: Bad dMAC/dIP", packet_info);
	}

	// === We are a router UVM and this packet is not meant for us as final destination, we need to decrement the packet's ttl
	packet_info->router_packet = (packet_info->uvm_pkt_relation != UVM_PKT_RELATION_DEST && LOCAL_UVM_IS_ROUTER == 1 && 
			packet_context.ip_header != NULL);
	packet_info->loopback_packet = (packet_info->router_packet && ENABLE_ROUTER_LOOPBACK);
	if (packet_info->router_packet) {
		int ret = ttl_decr_and_report_okay(ctx, packet_context.ip_header, sizeof(struct ethhdr));
		if (ret != 0) {
			RETURN_SHOT_FROM_MAIN("DROP: TTL exp", packet_info);
		}
		VALIDATE_ETH_PACKET(ctx, packet_context.eth_header, RETURN_SHOT_FROM_MAIN("DROP: Bad ETH", packet_info));
		VALIDATE_IP_PACKET(ctx, packet_context.eth_header, packet_context.ip_header, RETURN_SHOT_FROM_MAIN("DROP: Bad IP", packet_info));
	}

	// === Get packet protocol and if applicable, sip, dip, sport, dport
	if (get_static_packet_info(ctx, &packet_context, packet_info->router_packet ? EGRESS_PATH : INGRESS_PATH) != 0) {
		RETURN_SHOT_FROM_MAIN("DROP: Bad pakct_info ?", packet_info);
	}

	ebpf_printk(packet_info, "%pI4->%pI4", &packet_info->sip, &packet_info->dip); 
	ebpf_printk(packet_info, "protcol %c router pkt %c",
			((packet_info->protocol == MICRO_SEG_NOTA)      ? 'R' :
			 (packet_info->protocol == MICRO_SEG_IP)        ? 'I' :
			 (packet_info->protocol == MICRO_SEG_ICMP)      ? 'C' :
			 (packet_info->protocol == MICRO_SEG_TCP)       ? 'T' :
			 (packet_info->protocol == MICRO_SEG_UDP)       ? 'U' :
			 (packet_info->protocol == MICRO_SEG_HTTP)      ? 'H' :
			 (packet_info->protocol == MICRO_SEG_HTTPS)     ? 'S' : '?'),
			packet_info->router_packet ? 'Y' : 'N'
		   );

	// === If the packet is ARP, just OK it through without regards to security rules
	if (packet_info->protocol == MICRO_SEG_NOTA && packet_context.eth_header->h_proto == bpf_htons(ETH_P_ARP)) {
		RETURN_OK_FROM_IMAIN(packet_info);
	}

	// === If the packet is part of an established connection, we can skip directly to the isend call
	// Note: Only IP packets can be part of an established connection 
	enum CONNECTION_ESTABLISHED_STATE connection_state = CONNECTION_NOT_ESTABLISHED;
	if (packet_info->protocol != MICRO_SEG_NOTA) {
		connection_state = is_established_connection(&packet_context, packet_info->router_packet ? EGRESS_PATH : INGRESS_PATH, 
				packet_info->router_packet ? !CLEANUP_ON_TCP_FIN : CLEANUP_ON_TCP_FIN);
	} else {
		record_raw_packet_length(ctx, packet_info, packet_info->router_packet ? EGRESS_PATH : INGRESS_PATH);
	}
	if (connection_state == CONNECTION_ERROR) {
		RETURN_SHOT_FROM_MAIN("DROP: conn error", packet_info);
	}

	// === Log packet stats if needed
        if (report_packet_connection_stats(packet_info->num_pkts, packet_info->closed_connection)) {
                send_packet_connection_stats(ctx, &packet_context, packet_info->router_packet ? EGRESS_PATH : INGRESS_PATH);
        }

	// === Send packets part of a connection directly to isend
	if (connection_state != CONNECTION_NOT_ESTABLISHED) {
		ebpf_printk(packet_info, "%pI4->%pI4 est\n", &packet_info->sip, &packet_info->dip);
		ebpf_printk(packet_info, "id %d->%d est\n", packet_info->source_id, packet_info->destination_id);

		// === Fetch qos level
		get_qos_level(ctx, packet_info, packet_info->router_packet ? EGRESS_PATH : INGRESS_PATH);
		ebpf_printk(packet_info, "qos level %d", ctx->tc_classid);

		tail_call_ingress_ebpf(packet_info, ctx, PARSE_MVTAP_ISEND);
		RETURN_FROM_MAIN(packet_info, packet_info->tail_call_return);
	}
	ibpf_printk(packet_info, "%pI4->%pI4 != est\n", &packet_info->sip, &packet_info->dip);

	// === Set defaults for establishing connection entry for this packet
	packet_info->create_est_connection = packet_info->protocol == MICRO_SEG_NOTA ? 0 : connection_state != CONNECTION_FULLY_ESTABLISHED;
	packet_info->allow_rule_stateful = packet_info->create_est_connection;

	// === Fetch source and destination information needed for iprocess
	if (get_ingress_destination_information(&packet_context) != 0) {
		if (packet_info->uvm_pkt_relation == UVM_PKT_RELATION_DEST) {
			RETURN_SHOT_FROM_MAIN("DROP: L2T miss", packet_info);
		}
	} 
	get_ingress_source_information(&packet_context);

	// === Fetch qos level
	get_qos_level(ctx, packet_info, packet_info->router_packet ? EGRESS_PATH : INGRESS_PATH);
	ebpf_printk(packet_info, "qos level %d", ctx->tc_classid);

	if (packet_info->uvm_pkt_relation == UVM_PKT_RELATION_DEST) {
		tail_call_ingress_ebpf(packet_info, ctx, PARSE_MVTAP_IPROCESS);
	} else {
		if (connection_state == CONNECTION_NOT_ESTABLISHED) {
			struct security_action_reason reason = {
				.action = RULE_EVALUATION_ACTION_ALLOW,
				.etcd_rule_id = NO_ETCD_RULE_ID,
			};
			update_pkt_stat_log(ctx, &packet_context, &reason, RULE_TYPE_ROUTER_BYPASS, INGRESS_PATH, 0);
		}
		tail_call_ingress_ebpf(packet_info, ctx, PARSE_MVTAP_ISEND);
	}

	RETURN_FROM_MAIN(packet_info, packet_info->tail_call_return);
}

__section("tc/tail_macvtap_iprocess")
int request_macvtap_pkt_iprocess(struct __sk_buff *ctx) {
	struct packet_context_value *packet_info = NULL;
	struct packet_context packet_context = {0};
	if (tail_call_starter(ctx, &packet_info, &packet_context) != 0) {
		if (packet_info == NULL) {
			return TC_ACT_SHOT;
		}
		RETURN_SHOT_FROM_TAIL(packet_info);
	}
	ibpf_printk(packet_info, "chk sec rule: %pI4->%pI4=%pI4\n", &packet_info->sip, &packet_info->dip, &packet_info->stip);

	// === Check ingress microsegmentation rules of the destination for explicit deny/allow rules
	struct security_action_reason reason = {
		.action = RULE_EVALUATION_ACTION_NO_ACTION,
		.etcd_rule_id = NO_ETCD_RULE_ID,
	};
	EVALUATE_RULE(should_drop_microseg(packet_info, INGRESS_PATH, &reason, LOCAL), &reason, RULE_TYPE_MICRO_SEG, "imicroseg", INGRESS_PATH);
	HANDLE_RULE_EVALUATION_RESULT(reason.action, HANDLE_ALLOW_RESULT, UPDATE_CREATE_CONNECTION, packet_info->allow_rule_stateful, INGRESS_PATH);

	// === Check for explicit allow/deny rules in category rules
	EVALUATE_RULE(should_drop_category(packet_info, &reason), &reason, RULE_TYPE_CATEGORY, "category", INGRESS_PATH);
	HANDLE_RULE_EVALUATION_RESULT(reason.action, HANDLE_ALLOW_RESULT, UPDATE_CREATE_CONNECTION, RULE_STATEFUL, INGRESS_PATH);

	if (packet_info->is_within_subnet == 1) {
		HANDLE_RULE_EVALUATION_RESULT(RULE_EVALUATION_ACTION_ALLOW, HANDLE_ALLOW_RESULT, !UPDATE_CREATE_CONNECTION, 
				!RULE_STATEFUL, INGRESS_PATH); 
	} else {
		// === Check ingress security group rules of the destination for explicit deny/allow rules
		EVALUATE_RULE(should_drop_security_group(packet_info, INGRESS_PATH, &reason, LOCAL), &reason, RULE_TYPE_SECURITY_GROUP, "isecurity-grp", 
				INGRESS_PATH);
		HANDLE_RULE_EVALUATION_RESULT(reason.action, HANDLE_ALLOW_RESULT, !UPDATE_CREATE_CONNECTION, !RULE_STATEFUL, INGRESS_PATH);
	}

	// === We won't get here, but we need this to keep the verifier happy
	HANDLE_RULE_EVALUATION_RESULT(RULE_EVALUATION_ACTION_ALLOW, HANDLE_ALLOW_RESULT, !UPDATE_CREATE_CONNECTION, !RULE_STATEFUL, 
			INGRESS_PATH);
}

__section("tc/tail_macvtap_isend")
int request_macvtap_isend(struct __sk_buff *ctx) {
	struct packet_context_value *packet_info = NULL;
	struct packet_context packet_context = {0};
	if (tail_call_starter(ctx, &packet_info, &packet_context) != 0) {
		if (packet_info == NULL) {
			return TC_ACT_SHOT;
		}
		RETURN_SHOT_FROM_TAIL(packet_info);
	}

	if (packet_info->update_dest_ip) {
		if (update_sip_dip_with_next_hop(ctx, &packet_context, INGRESS_PATH) != 0) {
			RETURN_SHOT_FROM_TAIL(packet_info);
		}
	}

	if (packet_info->packet_type == PACKET_UVM_BROADCAST_EW && packet_context.eth_header->h_proto == bpf_htons(ETH_P_ARP)) {
		process_arp(ctx, &packet_context);
	}
	if (packet_info->create_est_connection == 1) {
		packet_info->next_hop_ip = packet_info->dip;
		if (create_established_connection(&packet_context, packet_info->router_packet ? EGRESS_PATH : INGRESS_PATH, 
					!(NEXT_HOP_EVALUATED)) != 0) {
			RETURN_SHOT_FROM_TAIL(packet_info);
		}
	}

	// === Redirect packet to egress if we are a router and loopback is enabled
	if (packet_context.packet_info->loopback_packet) {
		// Return this packet back on the egress on this interface. This is purely for testing purposes,
		// During production, there will be some sensible code running within the UVM to decide what to
		// do next with the packet
		mac_addr_t local_subnet_def_router_mac = { .mac_64 = LOCAL_UVM_SUB_GW_MAC };
		set_mac(packet_context.eth_header->h_source, &packet_info->local_uvm_mac);
		set_mac(packet_context.eth_header->h_dest, &local_subnet_def_router_mac);
		RETURN_FROM_TAIL(packet_info, bpf_redirect(packet_info->loopback_egress_ifindex, 0));
	}
	ctx->cb[0] = ctx->tc_classid;
	ebpf_printk(packet_info, "ok: classid %d cb[0] %d", ctx->tc_classid, ctx->cb[0]);
	RETURN_OK_FROM_ITAIL(packet_info);
}
#endif

char __license[] __section("license") = "GPL";
