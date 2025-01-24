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

#define NEXT_HOP_EVALUATED 1

static int create_established_connection(struct packet_context *packet_ctx, enum PACKET_PATH packet_path, __u8 nexthop_evaluated) {
	if (packet_ctx == NULL || packet_ctx->packet_info == NULL || packet_ctx->ip_header == NULL) {
		return -1;
	}
	struct packet_context_value *packet_info = packet_ctx->packet_info;
	__u16 ip_data_len = bpf_ntohs(packet_ctx->ip_header->tot_len);

	struct stateful_connections_key key = {0};
	key.uvm_vpcid = packet_info->vpcid;
	// We could be just the router, in which case the sport/dport of multiple clients can collide
	// So include intermediate_tip, which makes the key unique if we are indeed the router. If not, including
	// intermediary IP makes no difference as it will be zero.
	key.uvm_ip = packet_info->intermediary_tip;
	key.protocol = packet_info->protocol;
	if (key.protocol == MICRO_SEG_HTTP || key.protocol == MICRO_SEG_HTTPS) {
		key.protocol = MICRO_SEG_TCP;
	}

	key.client_ip = (packet_path == EGRESS_PATH) ? packet_info->sip : packet_info->next_hop_ip;
	key.client_port = (packet_path == EGRESS_PATH) ? packet_info->sport : packet_info->dport;
	key.remote_ip = (packet_path == EGRESS_PATH) ? packet_info->next_hop_ip : packet_info->sip;
	key.remote_port = (packet_path == EGRESS_PATH) ? packet_info->dport : packet_info->sport;

	if (key.protocol == MICRO_SEG_TCP && packet_ctx->packet_info->tcp_syn_connection == 1) {
		ebpf_printk(packet_ctx->packet_info, "create syn conn\n");
		// the packet is SYN packet sent during the TCP handshake; the server port has not been finalized and will change 
		// once the server sends the SYN-ACK packet. Thus, we cannot record the server port right now
		if (packet_path == EGRESS_PATH) {
			key.remote_port = 0; 
		} else {
			key.client_port = 0;
		}
	} else if (key.protocol == MICRO_SEG_TCP && packet_ctx->packet_info->tcp_syn_ack_connection == 1) {
		ebpf_printk(packet_ctx->packet_info, "create syn-ack conn\n");
		// the packet is a SYN-ACK packet seny by server during the TCP handshake after the client sends SYN packet
		// we must have create a connection when we intercepted the client's SYN packet. However, in that connection,
		// server port was finalized and thus, wasn't noted. Now that the server has sent a packet though, the server's 
		// port has been set and we can store in our connection map. So, we will now fetch the connection entry we had 
		// created for the SYN packet and change its key to record the server's port
		if (packet_path == EGRESS_PATH) {
			key.client_port = 0;
		} else {
			key.remote_port = 0;
		}
		struct stateful_connections_value *connection_state = bpf_map_lookup_elem(&stateful_connections_map, &key);

		ebpf_printk(packet_ctx->packet_info, "prev conn %p\n", connection_state);
		ebpf_printk(packet_ctx->packet_info, "preq seq %ld; cur ack %ld\n", 
				connection_state ? connection_state->tcp_seq_number : -1, packet_info->tcp_ack_number);
		if (connection_state != NULL && connection_state->tcp_seq_number == packet_info->tcp_ack_number-1) {
			if (packet_path == INGRESS_PATH) {
				ebpf_printk(packet_ctx->packet_info, "coping prev syn conn\n");
				key.remote_port = packet_info->sport; 
				if (bpf_map_update_elem(&stateful_connections_map, &key, connection_state, BPF_ANY) != 0) {
					return -1;
				}
				key.remote_port = 0;
			}
			ebpf_printk(packet_ctx->packet_info, "del syn entry client %pI4:%d\n",
					&key.client_ip, key.client_port);
			ebpf_printk(packet_ctx->packet_info, "del syn entry remote %pI4:%d\n",
					&key.remote_ip, key.remote_port);
			bpf_map_delete_elem(&stateful_connections_map, &key); 
			if (packet_path == INGRESS_PATH) {
				return 0;
			}
		}
		if (packet_info->uvm_pkt_relation == UVM_PKT_RELATION_SRC || packet_info->uvm_pkt_relation == UVM_PKT_RELATION_DEST) {
			struct stateful_connections_key key1 = key;
			key1.remote_port ^= key1.client_port;
			key1.client_port ^= key1.remote_port;
			key1.remote_port ^= key1.client_port;
			key1.remote_ip ^= key1.client_ip;
			key1.client_ip ^= key1.remote_ip;
				key1.remote_ip ^= key1.client_ip;
			bpf_map_delete_elem(&stateful_connections_map, &key1); 
			ebpf_printk(packet_ctx->packet_info, "del syn entry client %pI4:%d\n",
					&key1.client_ip, key1.client_port);
			ebpf_printk(packet_ctx->packet_info, "del syn entry remote %pI4:%d\n",
					&key1.remote_ip, key1.remote_port);
		}
		key.client_port = (packet_path == EGRESS_PATH) ? packet_info->sport : packet_info->dport;
		key.remote_port = (packet_path == EGRESS_PATH) ? packet_info->dport : packet_info->sport;
	}

	struct stateful_connections_value connection_state = {0};
	connection_state.remote_ip      = key.remote_ip;
	connection_state.local_tip      = packet_info->stip;
	connection_state.lb_ip          = (packet_path == EGRESS_PATH) && packet_info->is_dest_lb_backend ? packet_info->dip : 0;
	connection_state.lb_backend_ip  = (packet_path == EGRESS_PATH) && packet_info->is_dest_lb_backend ? packet_info->next_hop_ip : 0;
	ibpf_printk(packet_ctx->packet_info, "has lb ip %d lb ip %pI4 lb backed ip %pI4\n", (packet_path == EGRESS_PATH) && packet_info->is_dest_lb_backend, 
			&connection_state.lb_ip, &connection_state.lb_backend_ip);

	connection_state.timestamp      		= bpf_ktime_get_ns();
	connection_state.time_established 		= connection_state.timestamp;
	connection_state.next_hop_host_mac.mac_64       = packet_info->next_hop_host_mac.mac_64;
	connection_state.next_hop_tip                   = packet_info->next_hop_tip;
	connection_state.next_hop_host_ip               = packet_info->next_hop_host_ip;

	__builtin_memcpy(&connection_state.host_ips, &packet_info->host_ips, sizeof(struct nat_nonat_host_group));

	connection_state.nat_ip         = packet_info->nat_ip;
	connection_state.num_pkts	= 0;
	connection_state.xmit_bytes 	= (packet_path == EGRESS_PATH) ? ip_data_len : 0;
	connection_state.rmit_bytes 	= (packet_path == EGRESS_PATH) ? 0 : ip_data_len;

	connection_state.packet_type            = packet_info->packet_type;
	connection_state.is_dest_lb_backend     = packet_info->is_dest_lb_backend;
	connection_state.is_within_vpc  	= packet_info->is_within_vpc;

	connection_state.next_hop_evaluated 	= nexthop_evaluated;
	connection_state.tcp_seq_number		= packet_info->tcp_seq_number;
	if (packet_path == EGRESS_PATH) {
		connection_state.remote_has_id = packet_info->destination_has_url;
		connection_state.local_has_id = packet_info->source_has_url;
		connection_state.remote_id = packet_info->destination_id;
		connection_state.local_id = packet_info->source_id;
	} else {
		connection_state.remote_has_id = packet_info->source_has_url;
		connection_state.local_has_id = packet_info->destination_has_url;
		connection_state.remote_id = packet_info->source_id;
		connection_state.local_id = packet_info->destination_id;
	}

	return bpf_map_update_elem(&stateful_connections_map, &key, &connection_state, BPF_ANY);
}

// This function is called in the context of the inner ethernet frame. If there's also an outer one, we set its eth and IP fields
// separately after calling this function
static long update_sip_dip_with_next_hop(struct __sk_buff *ctx, struct packet_context *packet_ctx, enum PACKET_PATH packet_path) __attribute__((noinline)) {
        if (ctx == NULL || packet_ctx == NULL || packet_ctx->eth_header == NULL || packet_ctx->ip_header == NULL || 
			packet_ctx->packet_info == NULL) {
		ebpf_printk1(-1, "invalid inpit\n");
                return -1;
        }
	__be32 new_sip, new_dip;
	if (packet_path == EGRESS_PATH) {
		new_sip = packet_ctx->packet_info->sip;
		new_dip = packet_ctx->packet_info->next_hop_ip;
	} else {
		new_sip = packet_ctx->packet_info->next_hop_ip;
		new_dip = packet_ctx->packet_info->dip;
	}
	ebpf_printk(packet_ctx->packet_info, "new packet hdr %pI4->%pI4\n", &new_sip, &new_dip);
	if (update_ip_addrs(ctx, packet_ctx, new_sip, new_dip, sizeof(struct ethhdr)) != 0) {
		ebpf_printk(packet_ctx->packet_info, "update ip failed\n");
		return -1;
	}
	ebpf_printk(packet_ctx->packet_info, "validate eth\n");
	VALIDATE_ETH_PACKET(ctx, packet_ctx->eth_header, return -1);
	ebpf_printk(packet_ctx->packet_info, "validate ip\n");
	VALIDATE_IP_PACKET(ctx, packet_ctx->eth_header, packet_ctx->ip_header, return -1);
	ebpf_printk(packet_ctx->packet_info, "all valid\n");
        return 0;
}


