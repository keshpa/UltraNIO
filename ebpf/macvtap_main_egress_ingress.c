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

static __u8 ip_is_known_secondary(__be32 candidate_ip) {
	struct subnet_secondary_ip_key key = {
		.sb_tip = LOCAL_UVM_SUB_TIP,
		.secondary_ip = candidate_ip,
	};
	struct subnet_secondary_ip_value *value = bpf_map_lookup_elem(&subnet_secondary_ip_map, &key);
	if (value == NULL || value->hosted_uvm_tip != LOCAL_UVM_TIP) {
		return 0;
	}
	return 1;
}

static __u8 ip_is_uvm_ip(__be32 candidate_ip) {
	if (candidate_ip == LOCAL_UVM_IP) {
		return 1;
	}
	return ip_is_known_secondary(candidate_ip);
}

static __u8 ip_is_bcast_ip(__be32 candidate_ip) {
	__be32 broadcast_ip = BROADCAST_IP;
	if (candidate_ip == broadcast_ip) {
		return 1;
	}
	return 0;
}

static __u8 ip_is_rfc3232_zero_ip(__be32 candidate_ip) {
	if ((candidate_ip & 0xFF000000) == 0x00000000) {
		return 1;
	}
	return 0;
}

static void record_raw_packet_length(const struct __sk_buff *ctx, struct packet_context_value *packet_info, 
		enum PACKET_PATH packet_path) __attribute__((noinline)) {
	if (ctx == NULL) {
		return;
	}
	__u16 packet_size = ctx->len - sizeof(struct ethhdr);
	struct stateful_connections_key key = {0};
	key.uvm_vpcid = packet_info->vpcid;
	key.uvm_ip = packet_info->intermediary_tip;
	key.protocol = packet_info->protocol;
	key.client_ip = packet_info->intermediary_ip;
	key.client_port = 0;
	key.remote_ip = 0;
	key.remote_port = 0;

	struct stateful_connections_value *value = bpf_map_lookup_elem(&stateful_connections_map, &key);
	__u64 current_time = bpf_ktime_get_ns();
	if (value != NULL) {
		value->timestamp = current_time;
		packet_info->num_pkts = ++value->num_pkts;
		value->xmit_bytes += (packet_path == EGRESS_PATH) ? packet_size : 0;
		value->rmit_bytes += (packet_path == EGRESS_PATH) ? 0 : packet_size;
		packet_info->xmit_bytes = value->xmit_bytes;
		packet_info->rmit_bytes = value->rmit_bytes;
		return;
	}
	struct stateful_connections_value connection_state = {0};
	connection_state.local_tip = packet_info->intermediary_tip,
	connection_state.timestamp = current_time,
	connection_state.xmit_bytes = (packet_path == EGRESS_PATH) ? packet_size : 0,
	connection_state.rmit_bytes = (packet_path == EGRESS_PATH) ? 0 : packet_size,
	connection_state.packet_type = packet_info->protocol,
	bpf_map_update_elem(&stateful_connections_map, &key, &connection_state, BPF_ANY);
}

static int get_static_packet_info(const struct __sk_buff *ctx, struct packet_context *packet_ctx, enum PACKET_PATH packet_path) {
	if (packet_ctx == NULL || packet_ctx->packet_info == NULL) {
		return -1;
	}
	packet_ctx->packet_info->dip = packet_ctx->packet_info->sport = packet_ctx->packet_info->dport = 0;
	if (packet_ctx->ip_header == NULL) {
		packet_ctx->packet_info->sip = LOCAL_UVM_IP; 
		packet_ctx->packet_info->protocol = MICRO_SEG_NOTA;
		return 0;
	}
	packet_ctx->packet_info->sip = packet_ctx->ip_header->saddr; 
	packet_ctx->packet_info->dip = packet_ctx->ip_header->daddr; 
	switch (packet_ctx->ip_header->protocol) {
		case IPPROTO_ICMP: 
			{
				struct icmphdr *icmp_header = NULL;
				VALIDATE_ICMP_PACKET(ctx, packet_ctx->ip_header, icmp_header, return -1);
				if (icmp_header->type == ICMP_ECHO || icmp_header->type == ICMP_ECHOREPLY) {
					// the icmp ID and sequence uniquely identify a ICMP 'connection' and packet. So, record ID/sequence 
					// number in sport/dport so we can use that later for NATing to idenfity the ICMP 'connection'
					packet_ctx->packet_info->sport = (packet_path == EGRESS_PATH) ? 
						icmp_header->un.echo.id : 0;
					packet_ctx->packet_info->dport = (packet_path == EGRESS_PATH) ? 
						0 : icmp_header->un.echo.id;
				}
				packet_ctx->packet_info->protocol = MICRO_SEG_ICMP;
				return 0;
			}
		case IPPROTO_UDP: 
			{
				struct udphdr *udp_header = NULL;
				VALIDATE_UDP_PACKET(ctx, packet_ctx->ip_header, udp_header, return -1);
				packet_ctx->packet_info->sport = udp_header->source;
				packet_ctx->packet_info->dport = udp_header->dest;
				packet_ctx->packet_info->protocol = MICRO_SEG_UDP;
				if (udp_header->source == DHCP_CLIENT_PORT && udp_header->dest == DHCP_SERVER_PORT) {
					packet_ctx->packet_info->dhcp_request = 1;
					ebpf_printk(packet_ctx->packet_info, "DHCP Request\n");
				}
				if (udp_header->source == DHCP_SERVER_PORT && udp_header->dest == DHCP_CLIENT_PORT) {
					ebpf_printk(packet_ctx->packet_info, "DHCP Response\n");
				}
				return 0;
			}
		case IPPROTO_TCP: 
			{
				struct tcphdr *tcp_header = NULL;
				VALIDATE_TCP_PACKET(ctx, packet_ctx->ip_header, tcp_header, return -1);
				packet_ctx->packet_info->sport = tcp_header->source;
				packet_ctx->packet_info->dport = tcp_header->dest;
				// Identify the L5 protocol type based on the destination port
				if (tcp_header->dest == bpf_htons(80) || tcp_header->dest == bpf_htons(7104)) {
					packet_ctx->packet_info->protocol = MICRO_SEG_HTTP;
				} else if (tcp_header->dest == bpf_htons(443) || tcp_header->dest == bpf_htons(7102) || 
						tcp_header->dest == bpf_htons(7105)) {
					packet_ctx->packet_info->protocol = MICRO_SEG_HTTPS;
				} else {
					packet_ctx->packet_info->protocol = MICRO_SEG_TCP;
				}
				packet_ctx->packet_info->end_tcp_connection = (tcp_header->fin && tcp_header->ack);
				packet_ctx->packet_info->reset_tcp_connection = tcp_header->rst;
				packet_ctx->packet_info->tcp_syn_ack_connection = tcp_header->syn && tcp_header->ack;
				packet_ctx->packet_info->tcp_syn_connection = tcp_header->syn && !tcp_header->ack;
				packet_ctx->packet_info->tcp_seq_number = bpf_ntohl(tcp_header->seq);
				packet_ctx->packet_info->tcp_ack_number = bpf_ntohl(tcp_header->ack_seq);
				return 0;
			}
		default:
			packet_ctx->packet_info->protocol = MICRO_SEG_IP;
			break;
	}
	return 0;
}

static __u8 report_packet_connection_stats(__u64 num_pkts, __u8 closed_connection) {
	return closed_connection || ((num_pkts % REPORT_PACKET_CONNECTION_STAT_INTERVAL) == 0);
}

static void send_packet_connection_stats(struct __sk_buff *ctx, struct packet_context *packet_ctx, enum PACKET_PATH packet_path) {
	if (ctx == NULL || packet_ctx == NULL || packet_ctx->packet_info == NULL || packet_ctx->eth_header == NULL) {
		return;
	}
	struct packet_context_value *packet_info = packet_ctx->packet_info;
	struct pkt_connection_stat_value *log_event = bpf_ringbuf_reserve(&pkt_connection_stat_map,
			sizeof(struct pkt_connection_stat_value), 0);
	if (log_event == NULL) {
		return;
	}

	log_event->timestamp = bpf_ktime_get_ns();
	log_event->local_uvm_ip = packet_info->intermediary_ip;
	log_event->sip = (packet_path == EGRESS_PATH) ? packet_info->sip : packet_info->dip;
	log_event->sid = (packet_path == EGRESS_PATH) ? packet_info->source_id : packet_info->destination_id;
	log_event->dip = (packet_path == EGRESS_PATH) ? packet_info->dip : packet_info->sip;
	log_event->did = (packet_path == EGRESS_PATH) ? packet_info->destination_id : packet_info->source_id;
	log_event->sport = (packet_path == EGRESS_PATH) ? packet_info->sport : packet_info->dport;
	log_event->dport = (packet_path == EGRESS_PATH) ? packet_info->dport : packet_info->sport;
	log_event->protocol = packet_info->protocol;
	log_event->packet_protocol = (packet_ctx->ip_header == NULL) ?
		bpf_ntohs(packet_ctx->eth_header->h_proto) : packet_ctx->ip_header->protocol;
	log_event->connection_open_time = packet_info->time_connection_established;
	log_event->connection_close_time = packet_info->closed_connection ? bpf_ktime_get_ns() : 0; 
	log_event->xmit_bytes = packet_info->xmit_bytes;
	log_event->rmit_bytes = packet_info->rmit_bytes;
	ibpf_printk(packet_info, "closed_connection: %d", packet_info->closed_connection);
	ibpf_printk(packet_info, "xmit_bytes: %lld rmit_bytes %lld", log_event->xmit_bytes, log_event->rmit_bytes);
	ibpf_printk(packet_info, "num pkts %d", packet_info->num_pkts);
	bpf_ringbuf_submit(log_event, 0);
}

static int update_pkt_from_connection(struct packet_context *packet_ctx, struct stateful_connections_value *connection_state, 
		enum PACKET_PATH packet_path) {
	if (packet_ctx == NULL || connection_state == NULL) {
		return -1;
	}

	if (packet_path == EGRESS_PATH && connection_state->lb_backend_ip != 0) {
		packet_ctx->packet_info->next_hop_ip = connection_state->lb_backend_ip;
		packet_ctx->packet_info->update_l4_csum = 1;
		packet_ctx->packet_info->update_dest_ip = 1;
	} else if (packet_path == INGRESS_PATH && connection_state->lb_ip != 0) {
		packet_ctx->packet_info->next_hop_ip = connection_state->lb_ip;
		packet_ctx->packet_info->update_l4_csum = 1;
		packet_ctx->packet_info->update_dest_ip = 1;
	}
	ibpf_printk(packet_ctx->packet_info, "lb ip %pI4 update dest %d next hop %pI4\n", &connection_state->lb_ip, 
			packet_ctx->packet_info->update_dest_ip, &packet_ctx->packet_info->next_hop_ip);

	packet_ctx->packet_info->next_hop_host_ip 		= connection_state->next_hop_host_ip;
	packet_ctx->packet_info->next_hop_host_mac.mac_64 	= connection_state->next_hop_host_mac.mac_64;
	packet_ctx->packet_info->next_hop_tip 			= (packet_path == EGRESS_PATH) ? 
									connection_state->next_hop_tip :
									connection_state->local_tip;

	packet_ctx->packet_info->packet_type 			= connection_state->packet_type;
	packet_ctx->packet_info->is_dest_lb_backend 		= connection_state->is_dest_lb_backend;
	packet_ctx->packet_info->is_within_vpc 			= connection_state->is_within_vpc;

	packet_ctx->packet_info->nat_ip 			= connection_state->nat_ip;
	packet_ctx->packet_info->num_pkts 			= connection_state->num_pkts;
	packet_ctx->packet_info->xmit_bytes 			= connection_state->xmit_bytes;
	packet_ctx->packet_info->rmit_bytes 			= connection_state->rmit_bytes;
	packet_ctx->packet_info->time_connection_established	= connection_state->time_established;

	packet_ctx->packet_info->stip 				= (packet_path == EGRESS_PATH) ?
									connection_state->local_tip : 
									connection_state->next_hop_tip;

	if (packet_path == EGRESS_PATH) {
		packet_ctx->packet_info->destination_has_url = connection_state->remote_has_id;
		packet_ctx->packet_info->source_has_url = connection_state->local_has_id;
		packet_ctx->packet_info->destination_id = connection_state->remote_id;
		packet_ctx->packet_info->source_id = connection_state->local_id;
        } else {
		packet_ctx->packet_info->source_has_url = connection_state->remote_has_id;
		packet_ctx->packet_info->destination_has_url = connection_state->local_has_id;
		packet_ctx->packet_info->source_id = connection_state->remote_id;
		packet_ctx->packet_info->destination_id = connection_state->local_id;
        }

	// If the packet is egressing as NAT/noNAT, we need to know the next hop host ip details.
	// These details are irrelevant if the packet is ingressing.
	if (packet_path == EGRESS_PATH) {
		if (packet_ctx->packet_info->is_within_vpc == 0) {
			__builtin_memcpy(&packet_ctx->packet_info->host_ips, &connection_state->host_ips, sizeof(struct nat_nonat_host_group));
		}
	}
	return 0;
}

enum CONNECTION_ESTABLISHED_STATE {
	CONNECTION_ERROR,
	CONNECTION_NOT_ESTABLISHED,
	CONNECTION_FULLY_ESTABLISHED,
	CONNECTION_ESTABLISHED_WITHOUT_NEXTHOP,
};
#define CLEANUP_ON_TCP_FIN 1
static enum CONNECTION_ESTABLISHED_STATE is_established_connection(struct packet_context *packet_ctx, enum PACKET_PATH packet_path,
		__u8 cleanup_on_tcp_fin) {
	if (packet_ctx == NULL || packet_ctx->ip_header == NULL) {
		return CONNECTION_ERROR;
	}

	struct stateful_connections_key key = {0};
	struct packet_context_value *packet_info = packet_ctx->packet_info;
	key.uvm_vpcid = packet_info->vpcid;
	key.uvm_ip = packet_info->intermediary_tip;
	key.protocol = packet_info->protocol;
	if (key.protocol == MICRO_SEG_HTTP || key.protocol == MICRO_SEG_HTTPS) {
		key.protocol = MICRO_SEG_TCP;
	}

	key.client_ip = (packet_path == EGRESS_PATH) ? packet_info->sip : packet_info->dip;
	key.client_port = (packet_path == EGRESS_PATH) ? packet_info->sport : packet_info->dport;
	key.remote_ip = (packet_path == EGRESS_PATH) ? packet_info->dip : packet_info->sip;
	key.remote_port = (packet_path == EGRESS_PATH) ? packet_info->dport : packet_info->sport;

	if (packet_info->tcp_syn_ack_connection) {
		// TCP SYN-ACK packet is sent by the server in response to a TCP SYN packet. The SYN packet would have
		// created a connection entry with the server port listed as 0. 
		if (packet_path == EGRESS_PATH) { 
			key.client_port = 0;
		} else {
			key.remote_port = 0;
		}
	} else if (packet_info->tcp_syn_connection) {
		if (packet_path == EGRESS_PATH) { 
			key.remote_port = 0;
		} else {
			key.client_port = 0;
		}
	}

	ibpf_printk(packet_info, "client:%pI4:%d", &key.client_ip, key.client_port);
	ibpf_printk(packet_info, "server:%pI4:%d", &key.remote_ip, key.remote_port);
	ibpf_printk(packet_info, "protocol %d", key.protocol);
	struct stateful_connections_value *value = bpf_map_lookup_elem(&stateful_connections_map, &key);

	if (value == NULL) {
		return CONNECTION_NOT_ESTABLISHED;
	}
	if (packet_info->tcp_syn_connection) {
		value->tcp_seq_number = packet_info->tcp_seq_number;
	}
	if (packet_path == EGRESS_PATH && packet_info->dip != value->remote_ip) {
		return CONNECTION_NOT_ESTABLISHED;
	} else if (packet_path == INGRESS_PATH && packet_info->sip != value->remote_ip) {
		return CONNECTION_NOT_ESTABLISHED;
	} else if (packet_info->tcp_syn_ack_connection && value->tcp_seq_number != packet_info->tcp_ack_number-1) {
		ebpf_printk(packet_info, "seq/ack mismatch %ld!=%ld\n", value->tcp_seq_number, packet_info->tcp_ack_number);
		return CONNECTION_NOT_ESTABLISHED;
	}

	__u64 current_time = bpf_ktime_get_ns();
	if (is_timestamp_expired(value->timestamp, current_time)) {
		ebpf_printk(packet_info, "time expired: cur %llu record %llu\n", current_time, value->timestamp);
		bpf_map_delete_elem(&stateful_connections_map, &key);
		packet_info->closed_connection = 1;
		return CONNECTION_NOT_ESTABLISHED;
	}

	value->timestamp = current_time;
	++value->num_pkts;
	value->xmit_bytes += (packet_path == EGRESS_PATH) ? bpf_ntohs(packet_ctx->ip_header->tot_len) : 0;
	value->rmit_bytes += (packet_path == EGRESS_PATH) ? 0 : bpf_ntohs(packet_ctx->ip_header->tot_len);

	if (update_pkt_from_connection(packet_ctx, value, packet_path) != 0) {
		return CONNECTION_NOT_ESTABLISHED;
	}

	__u8 next_hop_evaluated = (value->next_hop_evaluated == 1) && !packet_info->tcp_syn_ack_connection;
	if ((cleanup_on_tcp_fin && packet_info->end_tcp_connection) || packet_info->reset_tcp_connection) {
		// When TCP connection closes gracefully, both client and remote send a FIN packet. When 
		// closes immediately and abruptly when either side sends RST packet. 
		// We want to cleanup the connection state when the TCP connection closes to ensure stray packets
		// don't by secuity rules.
		if (packet_info->sip == key.client_ip) {
			value->client_fin_ack_done = 1;
		} else if (packet_info->sip == key.remote_ip) {
			value->remote_fin_ack_done = 1;
		}
		if ((value->remote_fin_ack_done && value->client_fin_ack_done) || packet_info->reset_tcp_connection) {
			packet_info->closed_connection = 1;
			bpf_map_delete_elem(&stateful_connections_map, &key);
		}
	}
	return next_hop_evaluated ? CONNECTION_FULLY_ESTABLISHED : CONNECTION_ESTABLISHED_WITHOUT_NEXTHOP;
}

static int packet_source_match_uvm(const struct packet_context *packet_ctx) {
	if (packet_ctx == NULL || packet_ctx->eth_header == NULL) {
		return -1;
	}
	packet_ctx->packet_info->uvm_pkt_relation = UVM_PKT_RELATION_UNKNOWN;

	// === Ensure the source mac is ours
	mac_addr_t source_mac = { .mac_64 = 0 };
	__builtin_memcpy(source_mac.mac, packet_ctx->eth_header->h_source, 6);
	ebpf_printk(packet_ctx->packet_info, "schk %llx =?= %llx", source_mac.mac_64, LOCAL_UVM_MAC);
	if (source_mac.mac_64 != LOCAL_UVM_MAC) {
		return -1;
	} else if (LOCAL_UVM_CHECK_SRC_DEST == 0 || packet_ctx->ip_header == NULL) {
		packet_ctx->packet_info->uvm_pkt_relation = UVM_PKT_RELATION_SRC;
		return 0;
	}

	// === If we are not a router, ensure source ip is ours
	packet_ctx->packet_info->uvm_pkt_relation = (ip_is_uvm_ip(packet_ctx->ip_header->saddr) || ip_is_rfc3232_zero_ip(packet_ctx->ip_header->saddr)) ? 
		UVM_PKT_RELATION_SRC : UVM_PKT_RELATION_UNKNOWN;
	ebpf_printk(packet_ctx->packet_info, "schk %pI4 is mine %d", packet_ctx->ip_header->saddr, 
			(packet_ctx->packet_info->uvm_pkt_relation == UVM_PKT_RELATION_SRC));
	if (LOCAL_UVM_IS_ROUTER == 0 && packet_ctx->packet_info->uvm_pkt_relation != UVM_PKT_RELATION_SRC) {
		return -1;
	}
	return 0;
}

static int packet_destination_match_uvm(const struct packet_context *packet_ctx) {
	if (packet_ctx == NULL || packet_ctx->eth_header == NULL) {
		return -1;
	}
	packet_ctx->packet_info->uvm_pkt_relation = UVM_PKT_RELATION_UNKNOWN;

	// === Ensure the destination mac is ours
	mac_addr_t destination_mac = { .mac_64 = 0 };
	__builtin_memcpy(destination_mac.mac, packet_ctx->eth_header->h_dest, 6);
	if (destination_mac.mac_64 != LOCAL_UVM_MAC) {
		return -1;
	} else if (LOCAL_UVM_CHECK_SRC_DEST == 0 || packet_ctx->ip_header == NULL) {
		packet_ctx->packet_info->uvm_pkt_relation = UVM_PKT_RELATION_DEST;
		return 0;
	}

	// === If we are not a router, ensure destination ip is ours
	packet_ctx->packet_info->uvm_pkt_relation = (ip_is_uvm_ip(packet_ctx->ip_header->daddr) || ip_is_bcast_ip(packet_ctx->ip_header->daddr)) ?
		UVM_PKT_RELATION_DEST : UVM_PKT_RELATION_UNKNOWN;
	if (LOCAL_UVM_IS_ROUTER == 0 && packet_ctx->packet_info->uvm_pkt_relation != UVM_PKT_RELATION_DEST) {
		return -1;
	}
	return 0;
}

static __u16 get_qos_level(struct __sk_buff *ctx, const struct packet_context_value *packet_info, enum PACKET_PATH packet_path) {
	struct qos_key key = {0};
        key.prefixlen = SET_LPM_KEY_PREFIXLEN(key);
        key.data.local_tip = (packet_path == EGRESS_PATH) ? packet_info->stip : packet_info->next_hop_tip;
        __be32 remote_ip = (packet_path == EGRESS_PATH) ? packet_info->dip : packet_info->sip;
        __be32 remote_id = (packet_path == EGRESS_PATH) ? packet_info->destination_id : packet_info->source_id;
        key.data.remote_id_lookup = (packet_path == EGRESS_PATH) ? packet_info->destination_has_url : packet_info->source_has_url;
        key.data.remote_ip_id = key.data.remote_id_lookup ? remote_id : remote_ip;

	struct qos_value *value = bpf_map_lookup_elem(&qos_map, &key);
	ctx->tc_classid = (value != NULL) ? value->level : 0;
	return ctx->tc_classid;
}

//============================= MACVTAP EGRESS SECTION =======================
#if EGRESS == 1
static struct load_balancer_value* get_load_balancer_info(const struct packet_context_value *packet_info, 
		__be32 candidate_lb_ip) __attribute__((noinline)) {
	if (packet_info == NULL) {
		return NULL;
	}

	// get the list of server ips frontended by load balancer
	struct load_balancer_key lb_key = {0};
	lb_key.vpc_id = packet_info->vpcid;
	lb_key.load_balancer_ip = candidate_lb_ip;
	struct load_balancer_value* load_balancer_info = bpf_map_lookup_elem(&load_balancer_map, &lb_key);
	if (load_balancer_info != NULL) {
		return load_balancer_info;
	}
	return get_public_load_balancer_info(candidate_lb_ip);
}

static __u8 get_egress_destination_information(struct packet_context *packet_ctx) {
	if (packet_ctx == NULL || packet_ctx->eth_header == NULL || packet_ctx->packet_info == NULL) {
		return -1;
	}
	// Note: there are five "locations" or types of destinations: broadcast, within subnet, within vpc but outside subnet, load-balancer,
	//	 and finally outside VPC
	// For all destinations except broadcast, there are 3 routing types: direct to destination (NEXT_HOP_ROUTER_NONE), through designated
	// router (NEXT_HOP_ROUTER_DESIGNATED), through PBR routers (NEXT_HOP_ROUTER_PBR_DESTINATION)
	// If a destination has desginated and PBR routers enabled, we note the information on designated router and set the router type to
	// NEXT_HOP_ROUTER_DESIGNATED_OR_PBR_DESTINATION -- the caller will then decided whether to use designated router or PBR

	packet_ctx->packet_info->destination_router_type	= NEXT_HOP_ROUTER_NONE;

	// === Check if destination is broadcast
	mac_addr_t dest_mac = { .mac_64 = 0 };
	__builtin_memcpy(dest_mac.mac, packet_ctx->eth_header->h_dest, 6);
	mac_addr_t BROADCAST_MAC = { .mac_64 = 0xFFFFFFFFFFFFFFFFUL };
	if (macs_equal(&dest_mac, &BROADCAST_MAC) == 0) {
		packet_ctx->packet_info->packet_type 		= PACKET_UVM_BROADCAST_EW;
		packet_ctx->packet_info->check_dingress_policy 	= 0;
		packet_ctx->packet_info->is_within_vpc 		= 1;
		packet_ctx->packet_info->is_within_subnet 	= 1;
		packet_ctx->packet_info->dest_within_subnet	= 1;
		packet_ctx->packet_info->dip			= BROADCAST_IP;
		packet_ctx->packet_info->next_hop_ip		= BROADCAST_IP;
		packet_ctx->packet_info->next_hop_tip		= INVALID_TIP;
		packet_ctx->packet_info->dtip 			= INVALID_TIP;
		return 0;
	}

	// === Check if destination is within subnet
	// Note: if the destination mac is the default router then we know for sure this packet cannot be within subnet packet. Similarly, for
	// load balancer packets, the destination mac could be a 'fake'/emulated mac which is not stored in the local_to_tip map, so let's
	// not bother looking up known load balancer packets right now
	mac_addr_t default_router_mac = { .mac_64 = LOCAL_UVM_SUB_GW_MAC };
	mac_addr_t emulated_load_balancer_mac = { .mac_64 = LOCAL_UVM_LB_MAC };
	__u8 definitely_load_balancer = macs_equal(&dest_mac, &emulated_load_balancer_mac) == 0;
	__u8 definitely_outside_subnet = macs_equal(&dest_mac, &default_router_mac) == 0 || definitely_load_balancer;
	struct local_to_tip_value* mac_dest_info = definitely_outside_subnet ? NULL :
		get_local_information_impl(packet_ctx->packet_info->vpcid, &dest_mac, packet_ctx->packet_info->src_bcast_tip, 1);
	if (mac_dest_info != NULL) {
		packet_ctx->packet_info->packet_type 		= PACKET_MAC_ROUTED_EW;
		packet_ctx->packet_info->check_dingress_policy 	= 1;
		packet_ctx->packet_info->is_within_vpc 		= 1;
		packet_ctx->packet_info->is_within_subnet 	= 1;
		packet_ctx->packet_info->dest_within_subnet	= 1;

		packet_ctx->packet_info->next_hop_host_ip 	= mac_dest_info->host_ip;
		packet_ctx->packet_info->next_hop_ip 		= 0;
		packet_ctx->packet_info->next_hop_tip 		= mac_dest_info->tip;
		packet_ctx->packet_info->dtip 			= mac_dest_info->tip;

		packet_ctx->packet_info->dest_category = mac_dest_info->category;

		packet_ctx->packet_info->remote_ingress_micro_seg_enabled 	= mac_dest_info->micro_seg_ingress_enabled;
		packet_ctx->packet_info->remote_ingress_micro_seg_policy 	= mac_dest_info->micro_seg_ingress_policy;

		packet_ctx->packet_info->remote_ingress_security_group_enabled 	= mac_dest_info->security_group_ingress_enabled;
		packet_ctx->packet_info->remote_ingress_security_group_policy 	= mac_dest_info->security_group_ingress_policy;

		packet_ctx->packet_info->remote_egress_micro_seg_enabled 	= mac_dest_info->micro_seg_egress_enabled;
		packet_ctx->packet_info->remote_egress_micro_seg_policy 	= mac_dest_info->micro_seg_egress_policy;

		packet_ctx->packet_info->remote_egress_security_group_enabled 	= mac_dest_info->security_group_egress_enabled;
		packet_ctx->packet_info->remote_egress_security_group_policy 	= mac_dest_info->security_group_egress_policy;
	}
	if (packet_ctx->ip_header == NULL) {
		return mac_dest_info != NULL ? 0 : -1; 	// if packet has no IP and is not a broadcast, it must be a within subnet packet 
							// and thus, its mac must be registered in local_to_tip_map
	} else if (mac_dest_info != NULL && LOCAL_UVM_CHECK_SRC_DEST == 0) {
		// we cannot trust the destination IP; the destination mac is within the subnet so we declare this packet as within subnet too
		return 0;
	} else if (mac_dest_info == NULL) {
		packet_ctx->packet_info->is_within_subnet 	= 0;
		packet_ctx->packet_info->dest_within_subnet	= 0;
	}

	// For load balancer packets, the destination ip is not meant to be assigned to any UVM. Since the IP is not assigned to anyone UVM,
	// it will not be stored in the local_to_tip mac and so we don't need to lookup in local_to_tip for known load balancer packets
	// If mac_dest_info is NULL, the packet must be IP routed and so destination IP can most certainly be trusted
	__u8 definitely_outside_vpc = definitely_load_balancer; 
	if (mac_dest_info == NULL && (packet_ctx->packet_info->dip & LOCAL_UVM_VPC_MASK) != (LOCAL_UVM_IP & LOCAL_UVM_VPC_MASK)) {
		definitely_outside_vpc = 1;
		packet_ctx->packet_info->is_within_vpc = 0;
	} else {
		packet_ctx->packet_info->is_within_vpc = 1;
	}
	struct local_to_tip_value *ip_dest_info = definitely_outside_vpc ? NULL :
		get_local_information_impl(packet_ctx->packet_info->vpcid, NULL, packet_ctx->packet_info->dip, 0);
	if (ip_dest_info == NULL && mac_dest_info != NULL) {
		// destination is within the subnet -- but the dip is not in the subnet (this can happen if the source-destination check
		// has been disabled on the destination side)
		return 0;
	} else if (mac_dest_info != NULL && ip_dest_info != NULL && ip_dest_info->tip != mac_dest_info->tip) {
		// destination is within the subnet -- but the tip of dip and dmac don't match (this can happen if the dip belongs
		// to a secondary IP)
		return 0;
	} else if (ip_dest_info == NULL && packet_ctx->packet_info->is_within_vpc == 1) {
		// The destinaton it is most likely a underlay host. We should send this packet out as an N/S packet and treat it as outside vpc
		// We will check later on if the source IP is NO-NAT and if it is not, we shall drop the packet
	} 
	if (ip_dest_info == NULL) {
		// destination is either load balancer or outside VPC -- in either case, since destination is not a UVM, we don't have to 
		// check its ingress policies. So basically, LB backend IPs within VPC are transparent to source UVM and we will not evaluate
		// Category/Security Group/MSEG rules for LB backend IPs.
		packet_ctx->packet_info->check_dingress_policy 	= 0;
		packet_ctx->packet_info->next_hop_ip 		= packet_ctx->packet_info->dip;
		packet_ctx->packet_info->next_hop_tip		= INVALID_TIP;
		packet_ctx->packet_info->dtip 			= INVALID_TIP;

		// If the packet dip is within VPC but there is no TIP, the destination must be a NO-NAT underlay host -- so it can't
		// be a load balancer IP. Thus, we declare it was outside VPC and route is as N/S
		if (packet_ctx->packet_info->is_within_vpc) { 
			packet_ctx->packet_info->is_within_vpc 	= 0;
			return 0;
		}

		struct load_balancer_value *load_balancer_info = get_load_balancer_info(packet_ctx->packet_info, packet_ctx->packet_info->dip);
		if (load_balancer_info == NULL) { 
			return (definitely_load_balancer == 1) ? -1 : 0; // destination is not a load balancer and guranteed outside the VPC
		}
		__be32 lb_backed_ip = 0;
		assign_backend_load_balancer(load_balancer_info, packet_ctx->packet_info->sip, &lb_backed_ip);
		if (lb_backed_ip == 0) { // we should never take this case but it is here to keep verifier happy
			return -1;
		}
		packet_ctx->packet_info->update_dest_ip		= 1;
		packet_ctx->packet_info->update_l4_csum		= 1;
		packet_ctx->packet_info->next_hop_ip		= lb_backed_ip;
		packet_ctx->packet_info->is_dest_lb_backend 	= 1;

		// We support LB backend to even be outside the VPC.
		packet_ctx->packet_info->is_within_vpc =
			((lb_backed_ip & LOCAL_UVM_VPC_MASK) == (LOCAL_UVM_IP & LOCAL_UVM_VPC_MASK)) ? 1 : 0;
		if (!packet_ctx->packet_info->is_within_vpc) {
			return 0;
		}
		ip_dest_info = get_local_information_impl(packet_ctx->packet_info->vpcid, NULL, lb_backed_ip, 0);
		if (ip_dest_info == NULL) {
			// The load balancer IP it is most likely a underlay host. We will send this packet as outside VPC, N/S packet. 
			// We will check later on if the source IP is NO-NAT and if it is not, we shall drop the packet
			packet_ctx->packet_info->is_within_vpc = 0;
			return 0;
		}
	} else {
		// destination is within the VPC or within the subnet where tips of dip and dmac match. in either case, the packet can be IP
		// routed
		packet_ctx->packet_info->check_dingress_policy 	= 1;
		packet_ctx->packet_info->next_hop_ip 		= packet_ctx->packet_info->dip;
	}

	packet_ctx->packet_info->packet_type 		= PACKET_IP_ROUTED_EW;
	packet_ctx->packet_info->is_within_vpc 		= 1;

	packet_ctx->packet_info->next_hop_host_mac.mac_64 	= 0;
	packet_ctx->packet_info->next_hop_tip 			= ip_dest_info->tip;
	packet_ctx->packet_info->dtip 				= ip_dest_info->tip;
	packet_ctx->packet_info->next_hop_host_ip 		= ip_dest_info->host_ip;

	__u8 designated_router_exists = (packet_ctx->packet_info->is_within_subnet == 0 && ip_dest_info->designated_router_enabled && 
			ip_dest_info->designated_router_tip != ip_dest_info->tip);
	if (designated_router_exists && ip_dest_info->designated_router_tip == packet_ctx->packet_info->intermediary_tip) {
		packet_ctx->packet_info->uvm_pkt_relation 		= UVM_PKT_RELATION_DEST_DESIGNATED;
		packet_ctx->packet_info->check_dingress_policy  	= 0;
	} else if (designated_router_exists) {
		packet_ctx->packet_info->destination_router_type	= ip_dest_info->pbr_router_enabled ? 
			NEXT_HOP_ROUTER_DESIGNATED_OR_PBR_DESTINATION : 
			NEXT_HOP_ROUTER_DESIGNATED;
		packet_ctx->packet_info->check_dingress_policy  	= 0;
		packet_ctx->packet_info->next_hop_tip 			= ip_dest_info->designated_router_tip;
		packet_ctx->packet_info->next_hop_host_ip 		= ip_dest_info->designated_router_host_ip;
	} else if (packet_ctx->packet_info->is_within_subnet == 0 && ip_dest_info->pbr_router_enabled) {
		packet_ctx->packet_info->destination_router_type	= NEXT_HOP_ROUTER_PBR_DESTINATION;
		packet_ctx->packet_info->next_hop_tip 			= ip_dest_info->tip;
		packet_ctx->packet_info->next_hop_host_ip 		= ip_dest_info->host_ip;
	}

	packet_ctx->packet_info->dest_category = ip_dest_info->category;

	packet_ctx->packet_info->remote_ingress_micro_seg_enabled 	= ip_dest_info->micro_seg_ingress_enabled;
	packet_ctx->packet_info->remote_ingress_micro_seg_policy 	= ip_dest_info->micro_seg_ingress_policy;

	packet_ctx->packet_info->remote_ingress_security_group_enabled 	= ip_dest_info->security_group_ingress_enabled;
	packet_ctx->packet_info->remote_ingress_security_group_policy 	= ip_dest_info->security_group_ingress_policy;

	packet_ctx->packet_info->remote_egress_micro_seg_enabled 	= ip_dest_info->micro_seg_egress_enabled;
	packet_ctx->packet_info->remote_egress_micro_seg_policy 	= ip_dest_info->micro_seg_egress_policy;

	packet_ctx->packet_info->remote_egress_security_group_enabled 	= ip_dest_info->security_group_egress_enabled;
	packet_ctx->packet_info->remote_egress_security_group_policy 	= ip_dest_info->security_group_egress_policy;

	return 0;
}

struct get_next_hop_pbr_ctx {
	struct pbr_router_chain_value *pbr_chain;
	struct pbr_router *router;
	struct pbr_router *last_valid_router;
	struct packet_context_value *packet_info;
	__be32 local_tip;
	__u8 fetch_egress_chain;
	__u8 last_pbr;
};
static long get_next_hop_pbr_impl(__u32 i, struct get_next_hop_pbr_ctx* ctx) {
	if (ctx == NULL || ctx->pbr_chain == NULL || ctx->packet_info == NULL || i >= MAX_ROUTERS_IN_PBR_CHAIN) {
		return 1;
	}
	struct pbr_router_chain_value* pbr_chain = ctx->pbr_chain;
	ebpf_printk1(-1, "fetch pbr: considering router ingress %pI4 egress %pI4", 
			&pbr_chain->routers[i].ingress_tip, &pbr_chain->routers[i].egress_tip);
	if (pbr_chain_ended(&pbr_chain->routers[i])) {
		return 1;
	}
	if (ctx->fetch_egress_chain && pbr_chain->routers[i].egress_tip == ctx->local_tip) {
		if (i == MAX_ROUTERS_IN_PBR_CHAIN-1) {
			ctx->packet_info->uvm_pkt_relation = UVM_PKT_RELATION_SRC_LAST_PBR;
			ctx->last_pbr = 1;
			return 1;
		}
		ctx->router = &pbr_chain->routers[i+1];
	} else if (!ctx->fetch_egress_chain && pbr_chain->routers[i].ingress_tip == ctx->local_tip) {
		if (i == 0) {
			ctx->packet_info->uvm_pkt_relation = UVM_PKT_RELATION_DEST_LAST_PBR;
			ctx->last_pbr = 1;
			return 1;
		}
		ctx->router = &pbr_chain->routers[i-1];
	}
	ctx->last_valid_router = &pbr_chain->routers[i];
	return 0;
}

static enum GET_ROUTER_RETURN get_next_hop_pbr(struct packet_context_value *packet_info, __u8 fetch_egress_chain, 
		__u8 default_to_end_router) __attribute__((noinline)) {
	if (packet_info == NULL) {
		return GET_ROUTER_ERROR;
	}
	__be32 source_ip = fetch_egress_chain ? packet_info->sip : packet_info->dip;
	__be32 remote_has_url = fetch_egress_chain ? packet_info->destination_has_url : packet_info->source_has_url;
	__be32 remote_id = fetch_egress_chain ? packet_info->destination_id : packet_info->source_id;
	__be32 remote_ip = fetch_egress_chain ? packet_info->dip : packet_info->sip;
	ebpf_printk(packet_info, "fetch pbr: source %pI4 vpc %d", &source_ip, packet_info->vpcid);
	ebpf_printk(packet_info, "fetch pbr: remote %pI4 url %d", remote_has_url ? &remote_id : &remote_ip, 
			remote_has_url);
	struct pbr_router_chain_value* pbr_chain = get_pbr_router_chain(source_ip, packet_info->vpcid, 
			remote_has_url ? remote_id : remote_ip, remote_has_url);
	ebpf_printk(packet_info, "fetch pbr: no chain");
	if (pbr_chain == NULL) {
		return GET_ROUTER_NO_ROUTER;
	}
	__be32 local_tip = packet_info->intermediary_tip;
	ebpf_printk(packet_info, "fetch pbr: local tip %pI4", &local_tip);
	struct get_next_hop_pbr_ctx ctx = {
		.pbr_chain = pbr_chain,
		.router = NULL,
		.last_valid_router = NULL,
		.packet_info = packet_info,
		.local_tip = local_tip,
		.fetch_egress_chain = fetch_egress_chain,
		.last_pbr = 0,
	};
	bpf_loop(MAX_ROUTERS_IN_PBR_CHAIN, get_next_hop_pbr_impl, &ctx, 0);

	if (ctx.last_pbr) {
		ebpf_printk(packet_info, "fetch pbr: local is last pbr");
		return GET_ROUTER_NO_ROUTER;
	}

	__u8 end_router_choosen = 0;
	if (ctx.router == NULL && default_to_end_router) {
		ebpf_printk(packet_info, "fetch pbr: choosing end router");
		end_router_choosen = 1;
		ctx.router = fetch_egress_chain ? &pbr_chain->routers[0] : ctx.last_valid_router;
	}

	if (ctx.router == NULL || pbr_chain_ended(ctx.router)) {
		ebpf_printk(packet_info, "fetch pbr: router is null/end");
		return GET_ROUTER_NO_ROUTER;
	}
	ebpf_printk(packet_info, "fetch pbr: router ingress %pI4 egress %pI4", &ctx.router->ingress_tip, &ctx.router->egress_tip);
	__be32 next_hop_tip = fetch_egress_chain ? ctx.router->ingress_tip : ctx.router->egress_tip;
	if (next_hop_tip == local_tip) {
		ebpf_printk(packet_info, "fetch pbr: next pbr is same as local");
		return GET_ROUTER_NO_ROUTER;
	} else if (!end_router_choosen) {
		packet_info->uvm_pkt_relation = fetch_egress_chain ? UVM_PKT_RELATION_SRC_INTERNAL_PBR : UVM_PKT_RELATION_DEST_INTERNAL_PBR;;
	}
	packet_info->next_hop_tip = next_hop_tip;
	packet_info->next_hop_host_ip = ctx.router->host_ip;
	return GET_ROUTER_FOUND;
}

static struct lor_routing_value* get_lor_information_impl(__be32 key_tip, struct packet_context_value *packet_info) {
	if (packet_info == NULL) {
		return NULL;
	}
	struct lor_routing_key key = {
		.prefixlen = SET_LPM_KEY_PREFIXLEN(key),
		.data = {0},
	};
	key.data.sb_or_uvm_tip = key_tip;
	key.data.source_location = packet_info->src_location;
	key.data.destination_cidr = packet_info->dip;
	ibpf_printk(packet_info, "key sb_or_uvm_tip %llx=%lld source_location %d destination_cidr %llx=%lld\n", key.data.sb_or_uvm_tip, 
			key.data.sb_or_uvm_tip, key.data.source_location, key.data.destination_cidr, key.data.destination_cidr);
	return bpf_map_lookup_elem(&lor_routing_map, &key);
}

static enum GET_ROUTER_RETURN get_lor_information(struct packet_context_value *packet_info) {
	if (packet_info == NULL) {
		return GET_ROUTER_ERROR;
	}
	struct lor_routing_value *lor_router = NULL;
	if (packet_info->source_router_type == NEXT_HOP_ROUTER_LOR_UVM) {
		lor_router = get_lor_information_impl(packet_info->stip, packet_info);
	}
	if (lor_router == NULL) {
		lor_router = get_lor_information_impl(packet_info->src_bcast_tip, packet_info);
		if (lor_router == NULL) {
			ebpf_printk(packet_info, "no lor\n");
			return GET_ROUTER_NO_ROUTER;
		}
	}
	ibpf_printk(packet_info, "lor: %p - destination %pI4/%d, router %pI4\n", lor_router, &lor_router->destination_cidr, 
			lor_router->destination_cidr_size, &lor_router->router_tip);

	__be32 mask = (lor_router->destination_cidr_size == 0) ? 0 : (0xFFFFFFFF >> (32 - lor_router->destination_cidr_size));
	if ((mask & lor_router->destination_cidr) != (mask & packet_info->dip)) {
		return GET_ROUTER_NO_ROUTER;
	}

	if (lor_router->is_router_uvm && (lor_router->router_tip == LOCAL_UVM_SUB_GW_IP || lor_router->router_tip == 
				packet_info->intermediary_tip)) {
		packet_info->uvm_pkt_relation = UVM_PKT_RELATION_SRC_LOR;
		packet_info->source_router_type = NEXT_HOP_ROUTER_NONE;
	} else if (lor_router->is_router_uvm) { 
		packet_info->source_router_type = NEXT_HOP_ROUTER_UVM; 
		packet_info->next_hop_tip	= lor_router->router_tip;
		packet_info->next_hop_host_ip	= lor_router->router_host_ip;
		ebpf_printk(packet_info, "lor uvm - host %pI4 tip %pI4\n", &packet_info->next_hop_host_ip, &packet_info->next_hop_tip);
	} else {
		packet_info->source_router_type	= NEXT_HOP_ROUTER_HOST;
		packet_info->lor_host_ip 	= lor_router->router_host_ip;
		packet_info->next_hop_tip		= 0;
		packet_info->next_hop_host_mac.mac_64	= 0;
		ebpf_printk(packet_info, "lor host - host %pI4\n", &packet_info->lor_host_ip);
	}
	return GET_ROUTER_FOUND;
}

static __u8 get_egress_source_information(struct packet_context *packet_ctx) {
	if (packet_ctx == NULL || packet_ctx->eth_header == NULL || packet_ctx->packet_info == NULL) {
		return -1;
	}

	__be32 sip = (packet_ctx->packet_info->uvm_pkt_relation != UVM_PKT_RELATION_SRC || packet_ctx->packet_info->src_dest_check_enabled == 1) ? 
		(ip_is_rfc3232_zero_ip(packet_ctx->packet_info->sip) ? LOCAL_UVM_IP : packet_ctx->packet_info->sip) : 
		LOCAL_UVM_IP;

	packet_ctx->packet_info->stip				= INVALID_TIP;
	struct local_to_tip_value *ip_src_info = get_local_information_impl(packet_ctx->packet_info->vpcid, NULL, sip, 0);
	if (ip_src_info == NULL) {
		return -1;
	}

	packet_ctx->packet_info->stip				= ip_src_info->tip;
	packet_ctx->packet_info->local_host_ip			= ip_src_info->host_ip;

	packet_ctx->packet_info->local_micro_seg_enabled	= ip_src_info->micro_seg_egress_enabled;
	packet_ctx->packet_info->local_micro_seg_policy		= ip_src_info->micro_seg_egress_policy;
	packet_ctx->packet_info->local_security_group_enabled	= ip_src_info->security_group_egress_enabled;
	packet_ctx->packet_info->local_security_group_policy	= ip_src_info->security_group_egress_policy;
	packet_ctx->packet_info->vpc_category_policy		= ip_src_info->vpc_category_policy;

	packet_ctx->packet_info->source_category		= ip_src_info->category;
	packet_ctx->packet_info->src_location			= ip_src_info->location_id;
	packet_ctx->packet_info->local_default_nat		= ip_src_info->default_nat;

	packet_ctx->packet_info->source_router_type		= NEXT_HOP_ROUTER_NONE;
	if (packet_ctx->packet_info->is_within_subnet) {
		return 0;
	}
	// check for designated router iff it is enabled and the designated router is not us (otherwise this packet will go
	// in circles) plus the packet must be generated locally since we do not support chaining designated routers -- for chaining
	// routers, use PBR
	__u8 designated_router_exists = (ip_src_info->designated_router_enabled && ip_src_info->designated_router_tip != ip_src_info->tip);
	if (designated_router_exists && ip_src_info->designated_router_tip == packet_ctx->packet_info->intermediary_tip) {
		packet_ctx->packet_info->uvm_pkt_relation 		= UVM_PKT_RELATION_SRC_DESIGNATED;
	} else if (designated_router_exists && packet_ctx->packet_info->uvm_pkt_relation == UVM_PKT_RELATION_SRC)  {
		packet_ctx->packet_info->source_router_type		= NEXT_HOP_ROUTER_DESIGNATED;
		packet_ctx->packet_info->next_hop_tip 			= ip_src_info->designated_router_tip;
		packet_ctx->packet_info->next_hop_host_mac.mac_64 	= 0;
		packet_ctx->packet_info->next_hop_host_ip 		= ip_src_info->designated_router_host_ip;
		return 0;
	}
	// check if only PBR routers are configured
	if (ip_src_info->uvm_lor_router_enabled == 0 && ip_src_info->sb_lor_router_enabled == 0) {
		packet_ctx->packet_info->source_router_type = (ip_src_info->pbr_router_enabled == 1) ? 
			NEXT_HOP_ROUTER_PBR_SOURCE : NEXT_HOP_ROUTER_NONE;
		ibpf_printk(packet_ctx->packet_info, "router type %d pbr %d none %d", packet_ctx->packet_info->source_router_type,
				NEXT_HOP_ROUTER_PBR_SOURCE, NEXT_HOP_ROUTER_NONE);
		return 0;
	}
	// PBR routers and LOR routers configured -- the caller must choose which router to take
	else if (ip_src_info->uvm_lor_router_enabled == 1) { 
		packet_ctx->packet_info->source_router_type = (ip_src_info->pbr_router_enabled == 1) ? 
			NEXT_HOP_ROUTER_LOR_UVM_OR_PBR_SOURCE : NEXT_HOP_ROUTER_LOR_UVM;
		ibpf_printk(packet_ctx->packet_info, "router type %d pbr+lor %d lor %d", packet_ctx->packet_info->source_router_type,
				NEXT_HOP_ROUTER_LOR_UVM_OR_PBR_SOURCE, NEXT_HOP_ROUTER_LOR_UVM);
		return 0;
	}
	packet_ctx->packet_info->source_router_type = (ip_src_info->pbr_router_enabled == 1) ? 
		NEXT_HOP_ROUTER_LOR_SUBNET_OR_PBR_SOURCE : NEXT_HOP_ROUTER_LOR_SUBNET;
	ibpf_printk(packet_ctx->packet_info, "router type %d pbr+lor %d lor %d", packet_ctx->packet_info->source_router_type,
			NEXT_HOP_ROUTER_LOR_SUBNET_OR_PBR_SOURCE, NEXT_HOP_ROUTER_LOR_SUBNET);
	return 0;
}

static int should_nat_packet(__be32 stip, __be32 dip, __u8 default_nat) {
	struct micro_seg_and_no_nat_key nat_no_nat_key = {
		.prefixlen = SET_LPM_KEY_PREFIXLEN(nat_no_nat_key),
		.data = {0},
	};
	nat_no_nat_key.data.local_tip = stip;
	nat_no_nat_key.data.remote_id_lookup = 0;
	nat_no_nat_key.data.remote_ip_id = dip;
	nat_no_nat_key.data.lookup_type = NAT_NO_NAT_LOOKUP;

	struct micro_seg_and_no_nat_value *nat_no_nat_value = bpf_map_lookup_elem(&micro_seg_and_no_nat_map, &nat_no_nat_key);
	dbpf_printk("nat/no nat %p prefix len %d default nat %c\n", nat_no_nat_value, nat_no_nat_key.prefixlen,
			default_nat ? 'Y' : 'N');
	dbpf_printk("stip %pI4 dip %pI4 lookup %d\n", &nat_no_nat_key.data.local_tip, &nat_no_nat_key.data.remote_ip_id, 
			nat_no_nat_key.data.lookup_type);
	if (nat_no_nat_value == NULL) {
		return default_nat; // there are no nat rules for this source-destination -- follow default action
	}

	__be32 mask = (nat_no_nat_value->remote_cidr_size == 0) ? 0 : (0xFFFFFFFF >> (32 - nat_no_nat_value->remote_cidr_size));
	dbpf_printk("mask %pI4, dip %pI4, nat/no nat dest %pI4\n", &mask, &dip, &nat_no_nat_value->remote_cidr_base_or_remote_id);
	if ((dip & mask) == (nat_no_nat_value->remote_cidr_base_or_remote_id & mask)) {
		return (default_nat == 0) ? 1 : 0;
	}
	return default_nat; // there are no nat rules for this source-destination -- follow default action
}

static struct vpc_nat_entries_value* get_vpc_nat_options(__u16 vpcid) {
	struct vpc_nat_entries_key vpc_key = {
		.vpcid = vpcid,
	};

	struct vpc_nat_entries_value* nat_options = bpf_map_lookup_elem(&vpc_nat_entries_map, &vpc_key);
	if (nat_options == NULL) {
		dbpf_printk("no vpc nat ips %d \n", vpc_key.vpcid);
		return NULL;
	}
	return nat_options;
}

static int get_nat_nonat_host(struct packet_context_value *packet_info, __be32 nat_nonat_ip, __u8 is_nat) {
	if (packet_info == NULL) {
		return MAX_NAT_NONAT_HOSTS;
	}
	struct nat_nonat_host_group *host_ips = get_nat_nonat_host_group(nat_nonat_ip, is_nat, NULL);
	if (host_ips == NULL) {
		ebpf_printk(packet_info, "no host group for %pI4 is_nat %d\n", &nat_nonat_ip, is_nat);
		return MAX_NAT_NONAT_HOSTS;
	}
	ebpf_printk(packet_info, "got host group for %pI4 is_nat %d\n", &nat_nonat_ip, is_nat);
	__builtin_memcpy(&packet_info->host_ips, host_ips, sizeof(struct nat_nonat_host_group));
	return get_nat_nonat_host_ip(host_ips, &packet_info->next_hop_host_ip);
}

static int get_nat_ip_host(struct packet_context_value *packet_info) {
	if (packet_info == NULL) {
		return MAX_NAT_NONAT_HOSTS;
	}
	struct vpc_nat_entries_value *nat_options = get_vpc_nat_options(packet_info->vpcid);
	if (nat_options == NULL) {
		ebpf_printk(packet_info, "no NAT options\n");
		return MAX_NAT_NONAT_HOSTS;
	}

	__u32 nat_ip_index = hash_src_ip_port_dest_ip(packet_info->sip, packet_info->sport, packet_info->dip) % nat_options->length;
	struct vpc_nat_entry_host* ip_entry = nat_options->ip_entry + nat_ip_index;
	if (nat_ip_index >= NUM_NAT_IPS || ip_entry < nat_options->ip_entry || ip_entry >= (nat_options->ip_entry + NUM_NAT_IPS)) {
		ebpf_printk(packet_info, "bounds check failed\n");
		return MAX_NAT_NONAT_HOSTS; // Keep the verifier happy. We will never take this path
	}
	packet_info->nat_ip = ip_entry->nat_ip;
	ebpf_printk(packet_info, "NAT = %pI4\n", &packet_info->nat_ip);
	return get_nat_nonat_host(packet_info, packet_info->nat_ip, true /* is_nat */);
}

static int get_no_nat_host(struct packet_context_value *packet_info) {
	return get_nat_nonat_host(packet_info, packet_info->sip, false /* is_nat */);
}

static void process_macvtap_host_nat_nonat_metadata(struct packet_context_value *packet_info, enum CONNECTION_ESTABLISHED_STATE established_state) {
	if (packet_info == NULL) {
		return;
	}
	if (established_state != CONNECTION_FULLY_ESTABLISHED) {
		packet_info->macvtap_host_metadata = ROUTING_HDR_METADATA_MACVTAP_HOST_NEW_NAT_NONAT_CONNECTION;
	} else if (packet_info->num_pkts % RESYNC_NAT_NONAT_HOST_INTERVAL == 0) {
		packet_info->macvtap_host_metadata = ROUTING_HDR_METADATA_MACVTAP_HOST_REQUEST_NAT_NONAT_REFRESH;
	}
	return;
}

#else
//============================= MACVTAP IGRESS SECTION =======================

static __u8 get_ingress_destination_information(struct packet_context *packet_ctx) {
	if (packet_ctx == NULL || packet_ctx->eth_header == NULL || packet_ctx->packet_info == NULL) {
		return -1;
	}

	mac_addr_t dest_mac = { .mac_64 = 0 };
	__builtin_memcpy(dest_mac.mac, packet_ctx->eth_header->h_dest, 6);
	mac_addr_t BROADCAST_MAC = { .mac_64 = 0xFFFFFFFFFFFFFFFFUL };
	if (macs_equal(&dest_mac, &BROADCAST_MAC) == 0) {
		packet_ctx->packet_info->packet_type            = PACKET_UVM_BROADCAST_EW;
		packet_ctx->packet_info->is_within_vpc          = 1;
		packet_ctx->packet_info->is_within_subnet       = 1;
		return 0;
	}

	packet_ctx->packet_info->packet_type            	= PACKET_IP_ROUTED_EW;

	__be32 dip = (packet_ctx->packet_info->uvm_pkt_relation != UVM_PKT_RELATION_DEST || packet_ctx->packet_info->src_dest_check_enabled == 1) ? 
		(ip_is_bcast_ip(packet_ctx->packet_info->dip) ? LOCAL_UVM_IP : packet_ctx->packet_info->dip) :
		LOCAL_UVM_IP;

	struct local_to_tip_value *ip_dest_info = get_local_information_impl(packet_ctx->packet_info->vpcid, NULL, dip, 0);
	if (ip_dest_info == NULL) {
		return -1;
	}

	packet_ctx->packet_info->stip				= ip_dest_info->tip;
	packet_ctx->packet_info->next_hop_tip 			= ip_dest_info->tip;
	packet_ctx->packet_info->local_host_ip			= ip_dest_info->host_ip;

	packet_ctx->packet_info->local_micro_seg_enabled	= ip_dest_info->micro_seg_ingress_enabled;
	packet_ctx->packet_info->local_micro_seg_policy		= ip_dest_info->micro_seg_ingress_policy;
	packet_ctx->packet_info->local_security_group_enabled	= ip_dest_info->security_group_ingress_enabled;
	packet_ctx->packet_info->local_security_group_policy	= ip_dest_info->security_group_ingress_policy;

	packet_ctx->packet_info->dest_category			= ip_dest_info->category;
	packet_ctx->packet_info->local_default_nat		= ip_dest_info->default_nat;

	return 0;
}

static __u8 get_ingress_source_information(struct packet_context *packet_ctx) {
	if (packet_ctx == NULL || packet_ctx->eth_header == NULL || packet_ctx->packet_info == NULL) {
		return -1;
	}

	// If the packet is not from default router, the packet must be within subnet, so we should fetch the source information based
	// on its source mac. Otherwise, this must be an IP packet and if the sip is within the VPC, we can use the source IP to fetch
	// the source information
	mac_addr_t default_router_mac = { .mac_64 = LOCAL_UVM_SUB_GW_MAC };
	mac_addr_t src_mac = { .mac_64 = 0 };
	__builtin_memcpy(src_mac.mac, packet_ctx->eth_header->h_source, 6);

	packet_ctx->packet_info->is_within_subnet 	= macs_equal(&src_mac, &default_router_mac);
	packet_ctx->packet_info->is_within_vpc		= 1;
	if (packet_ctx->packet_info->is_within_subnet) {
		struct local_to_tip_value* mac_src_info = get_local_information_impl(packet_ctx->packet_info->vpcid, &src_mac, 
				packet_ctx->packet_info->dest_bcast_tip, 1);
		if (mac_src_info == NULL) {
			return -1;
		}
		if (packet_ctx->packet_info->packet_type != PACKET_UVM_BROADCAST_EW) {
			packet_ctx->packet_info->packet_type	= PACKET_MAC_ROUTED_EW;
		}
		packet_ctx->packet_info->stip			= mac_src_info->tip;
		packet_ctx->packet_info->source_category	= mac_src_info->category;
		return 0;
	}

	packet_ctx->packet_info->packet_type            	= PACKET_IP_ROUTED_EW;

	__be32 sip = packet_ctx->packet_info->sip;
	packet_ctx->packet_info->is_within_vpc = (sip & LOCAL_UVM_VPC_MASK) != (packet_ctx->packet_info->dip & LOCAL_UVM_VPC_MASK);
	if (!packet_ctx->packet_info->is_within_vpc) {
		return 0;
	}

	struct local_to_tip_value *ip_src_info = get_local_information_impl(packet_ctx->packet_info->vpcid, NULL, sip, 0);
	if (ip_src_info == NULL) {
		return -1;
	}
	packet_ctx->packet_info->stip			= ip_src_info->tip;
	packet_ctx->packet_info->source_category	= ip_src_info->category;

	return 0;
}

#endif
