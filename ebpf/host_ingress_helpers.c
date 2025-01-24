#define false 	0
#define HOST_IP_IS_LOCAL(candidate_host_ip) (candidate_host_ip == LOCAL_HOST_ETH_IP)

static int decap_packet(struct __sk_buff *ctx, __u32 ethhdr_to_preserve_offset, __u32 encap_header_size) __attribute__((noinline)) {
	if (ctx == NULL) {
		return -1;
	}
	void* data = (void*)(__u64)ctx->data;
	void* data_end = (void*)(__u64)ctx->data_end;
	if ((data + ethhdr_to_preserve_offset + sizeof(struct ethhdr) > data_end) || (data + encap_header_size > data_end)) {
		return -1;
	}

	// the inner packet must have an ethernet header -- copy it locally so we can place it back after the decap
	struct ethhdr original_eth_header;
	__builtin_memcpy(&original_eth_header, data + ethhdr_to_preserve_offset, sizeof(struct ethhdr));

	// remove the encapped ip header and the inner packet's ethernet header
	int packet_shrink_ret = 0;
	if ((packet_shrink_ret = bpf_skb_adjust_room(ctx, -(int)(encap_header_size), BPF_ADJ_ROOM_MAC, 0)) != 0) { 
		// bpf_skb_adjust_room removes intermediate ip+eth -- not exactly at head
		// So outer_eth+outer_ip + inner_eth+inner_ip ==> outer_eth+inner_ip
		BPF_LOG_BAD_ENCAP("WARN, shrink failed (error: %d)", packet_shrink_ret);
		return -1;
	}

	// copy the inner packet's ethernet header back at the start of the packet to complete packet decap logic
	data = (void*)(__u64)ctx->data;
	data_end = (void*)(__u64)ctx->data_end;
	if (data + sizeof(struct ethhdr) > data_end) {
		return -1;
	}
	__builtin_memcpy(data, &original_eth_header, sizeof(struct ethhdr));
	return 0;
}

static inline int is_expired(__u64 timestamp, __u64 current_time) {
	if ((current_time - timestamp) > NAT_EXPIRATION_THRESHOLD) {
		return 0;
	}
	return 1;
}

static struct nat_connection_value* retrive_nat_connection(const struct nat_connection_key *nat_connection_key) __attribute__((noinline)) {
	if (nat_connection_key == NULL) {
		return NULL;
	}
	struct nat_connection_value *nat_connection_value = bpf_map_lookup_elem(&nat_connection_map, nat_connection_key);
	if (nat_connection_value == NULL) {
		return NULL;
	}
	nat_connection_value->timestamp = bpf_ktime_get_ns();
	return nat_connection_value;
}

static __u8 update_nat_connction_next_hop(const struct nat_connection_key *nat_connection_key, 
		struct host_packet_context_value *packet_info) __attribute__((noinline)) {
	if (nat_connection_key == NULL || packet_info == NULL) {
		return -1;
	}
	struct nat_connection_value *nat_connection_value = retrive_nat_connection(nat_connection_key);
	if (nat_connection_value == NULL) {
		return -1;
	}
	nat_connection_value->state.next_hop_tip = packet_info->next_hop_tip;
	nat_connection_value->state.next_hop_host_mac = packet_info->next_hop_host_mac;
	return 0;
}

static inline void copy_nat_nonat_connection_state(struct nat_nonat_connection_state *dest, struct nat_nonat_connection_state *src) {
	// Note: dest and src both point to values in kernel map. Thus, if we try to use a simple memcpy, the validator throw all sorts
	// of errors complaining the pointers are 'invalid' To avoid all the validator errors, we manually copy each field from src to
	// dest
	dest->next_hop_host_mac.mac_64 = src->next_hop_host_mac.mac_64;
	dest->next_hop_host_ip = src->next_hop_host_ip;
	dest->next_hop_tip = src->next_hop_tip;
	dest->source_uvm_tip = src->source_uvm_tip;
	dest->source_uvm_ip = src->source_uvm_ip;
	dest->source_uvm_port = src->source_uvm_port;
	dest->next_hop_type = src->next_hop_type;
	dest->url_id_type = src->url_id_type;
	dest->url_id = src->url_id;
	dest->unused = src->unused;
}

static long try_using_nat_ip_port(__u32 index, struct try_nat_ip_port_reuse_context *nat_ip_port_ctx) __attribute__((noinline)) {
	if (nat_ip_port_ctx == NULL || nat_ip_port_ctx->nat_port == NULL || nat_ip_port_ctx->source_value == NULL || 
			nat_ip_port_ctx->source_dest_to_nat == NULL) {
		return 1;
	}
	struct nat_connection_key dest_nat_pair = {
		.remote_ip = nat_ip_port_ctx->daddr,
		.nat_ip = nat_ip_port_ctx->nat_ip,
		.remote_port = 0,
		.nat_port = bpf_htons(nat_ip_port_ctx->zero_nat_port ? 0 : 0 + nat_ip_port_ctx->port_index), // TODO: get rid of zero_nat_port
	};

	__u8 nat_ip_found = 0;
	// we chose a random NAT port and IP and are now checking if the reverse NAT translation map (for return packets
	// from outside the VPC) already have an entry for the DEST-IP : NAT-IP : NAT-PORT ==> STIP : PORT. If the mapping
	// does not exist, we are good.
	// check if dest-nat pair exists and if not claim it
	if (bpf_map_update_elem(&nat_connection_map, &dest_nat_pair, nat_ip_port_ctx->source_value, BPF_NOEXIST) == 0) {
		nat_ip_found = 1;
	} else {
		// dest-nat exists, but it could be an expired pair so we may be able to re-use it anyway
		struct nat_connection_value *nat_connection_state = retrive_nat_connection(&dest_nat_pair); 
		if (nat_connection_state != NULL) {
			bpf_spin_lock(&(nat_connection_state->lock));
			__be32 original_stip = nat_connection_state->state.source_uvm_tip;
			__be16 original_sport = nat_connection_state->state.source_uvm_port;
			if (is_expired(nat_connection_state->timestamp, nat_ip_port_ctx->source_value->timestamp) == 0) {
				nat_connection_state->timestamp = nat_ip_port_ctx->source_value->timestamp;
				copy_nat_nonat_connection_state(&nat_connection_state->state, &nat_ip_port_ctx->source_value->state);
				nat_ip_found = 1;
			}
			bpf_spin_unlock(&nat_connection_state->lock);

			if (nat_ip_found == 1) {
				struct nat_source_translation_key previous_source_dest_to_nat_key = {
					.remote_ip = nat_ip_port_ctx->daddr,
					.source_ip = original_stip,
					.remote_port = 0,
					.source_port = original_sport,
				};
				if (bpf_map_delete_elem(&nat_source_translations_map, &previous_source_dest_to_nat_key) != 0) {
					nat_ip_found = 0;	
				}
			}
		}
	}
	if (nat_ip_found == 1) { 
		*nat_ip_port_ctx->nat_port = dest_nat_pair.nat_port;
		// we have claimed a reverse (nat_connection_map) entry; now claim the forward (nat_source_translations_map) entry
		// note: we must initialize the fields of nat_ip_port independently as nat_ip_port has 16-byte padding at the end which
		// must be zeroed out. Thus, we first zero-out the entire struct and then initialize certian fields as needed
		struct nat_source_translation_value nat_ip_port = {0};
		nat_ip_port.nat_ip = dest_nat_pair.nat_ip;
		nat_ip_port.nat_port = dest_nat_pair.nat_port;
		if (bpf_map_update_elem(&nat_source_translations_map, nat_ip_port_ctx->source_dest_to_nat, &nat_ip_port, BPF_ANY) == 0) {
			nat_ip_port_ctx->found_nat = 1;
			return 1;
		}
	}

	// dest-nat pair existed and hadn't expired -- try a new nat ip-port
	if (nat_ip_port_ctx->port_index == ((1 << 16) - 1) || nat_ip_port_ctx->zero_nat_port == 1) {
		return 1;
	} else {
		nat_ip_port_ctx->port_index += MAX_NAT_NONAT_HOSTS;
	}
	return 0;
}

static __u8 is_egress_nat_packet(enum SPECIAL_PACKET_ID packet_type) {
	return packet_type == PACKET_NAT_EGRESS_WITHOUT_ROUTER ||
		packet_type == PACKET_NAT_EGRESS_WITH_ROUTER ||
		packet_type == PACKET_LOR_NAT_EGRESS_WITHOUT_ROUTER ||
		packet_type == PACKET_LOR_NAT_EGRESS_WITH_ROUTER;

}

static __u8 is_ingress_nat_packet(enum SPECIAL_PACKET_ID packet_type) {
	return packet_type == PACKET_TYPE_NAT_REPLY_INGRESS ||
		packet_type == PACKET_NAT_INGRESS_EW ||
		packet_type == PACKET_DENAT_INGRESS_WITHOUT_UVM_ROUTER ||
		packet_type == PACKET_DENAT_INGRESS_WITH_UVM_ROUTER;
}

static __u8 is_packet_class_10(enum ROUTING_HDR_METADATA_TYPE metadata, __u8 class_number) {
	return metadata == ROUTING_HDR_METADATA_HOST_HOST_NAT_NONAT_REFRESH && 
		(class_number == 1 || class_number == 3 || class_number == 9 || class_number == 6);
}

static __u8 check_for_class_10(struct host_packet_context_value *packet_info) {
	if (packet_info == NULL) {
		return false;
	} else if (!is_packet_class_10(packet_info->metadata, packet_info->class_number)) {
		return false;
	}
	packet_info->class_number = 10;
	packet_info->next_hop_is_local = 1;
	return true;
}

enum NAT_NONAT_MAP_UPDATE_RETURN {
	NAT_NONAT_MAP_UPDATE_RETURN_ERROR,
	NAT_NONAT_MAP_UPDATE_RETURN_SUCCESS,
	NAT_NONAT_MAP_UPDATE_RETURN_FAILURE_NO_ENTRY,
	NAT_NONAT_MAP_UPDATE_RETURN_SUCCESS_NEW_CONNECTION,
};

static __u8 nat_nonat_update_request_metadata(enum NAT_NONAT_MAP_UPDATE_RETURN nat_nonat_update_return) {
	return nat_nonat_update_return == NAT_NONAT_MAP_UPDATE_RETURN_SUCCESS_NEW_CONNECTION;
}

static enum NAT_NONAT_MAP_UPDATE_RETURN get_nat_port(struct packet_host_context *packet_ctx, __be32 nat_ip, __u16 *nat_port) __attribute__((noinline)) {
	if (packet_ctx == NULL || nat_port == NULL || packet_ctx->packet_info == NULL) {
		return NAT_NONAT_MAP_UPDATE_RETURN_ERROR;
	}
	struct host_packet_context_value *packet_info = packet_ctx->packet_info;

	// check if we have already estalished a NAT ip and port for this pair of source-destination ip and port
	struct nat_source_translation_key nat_source_translation_key = {
		.remote_ip = packet_info->destination_ip,
		.source_ip = packet_info->source_tip,
		.remote_port = 0,
		.source_port = packet_info->sport,
	};

	struct nat_source_translation_value *existing_nat = bpf_map_lookup_elem(&nat_source_translations_map, &nat_source_translation_key);
	if (existing_nat != NULL) {
		if (existing_nat->nat_ip != nat_ip) {
			return NAT_NONAT_MAP_UPDATE_RETURN_ERROR;
		}
		*nat_port = existing_nat->nat_port;
		// update timestamp in nat_connection_map to record that this connection is still alive
		struct nat_connection_key nat_key = {
			.remote_ip = packet_ctx->ip_header->daddr,
			.nat_ip = existing_nat->nat_ip,
			.remote_port = 0,
			.nat_port = existing_nat->nat_port,
		};
		update_nat_connction_next_hop(&nat_key, packet_info);
		return NAT_NONAT_MAP_UPDATE_RETURN_SUCCESS;
	}
	if (packet_info->metadata != ROUTING_HDR_METADATA_MACVTAP_HOST_NEW_NAT_NONAT_CONNECTION) {
		return NAT_NONAT_MAP_UPDATE_RETURN_FAILURE_NO_ENTRY;
	}

	// we need to assign a NAT ip-port to this source-destination pair
	// note that NAT ip-port can be used by multiple source-desination pairs so long as the destination ip is unique amongst all the pairs
	__u8 next_hop_router = (packet_info->packet_type == PACKET_NAT_EGRESS_WITH_ROUTER || 
			packet_info->packet_type == PACKET_LOR_NAT_EGRESS_WITH_ROUTER);
	struct nat_connection_value nat_source_translation_value = {0};
	nat_source_translation_value.state.next_hop_host_mac.mac_64 	= packet_info->next_hop_host_mac.mac_64;
	nat_source_translation_value.state.next_hop_host_ip  		= packet_info->next_hop_host_ip;
	nat_source_translation_value.state.next_hop_tip   		= packet_info->next_hop_tip;
	nat_source_translation_value.state.source_uvm_tip  		= packet_info->source_tip;
	nat_source_translation_value.state.source_uvm_ip  		= packet_info->source_ip;
	nat_source_translation_value.state.source_uvm_port  		= packet_info->sport;
	nat_source_translation_value.state.next_hop_type  		= next_hop_router ? NEXT_HOP_ROUTER : NEXT_HOP_UVM;
	nat_source_translation_value.state.url_id_type			= packet_info->url_id_type;
	nat_source_translation_value.state.url_id			= packet_info->url_id;
	nat_source_translation_value.state.unused   			= 0;
	nat_source_translation_value.timestamp 				= bpf_ktime_get_ns();

	struct try_nat_ip_port_reuse_context input = {
		.source_value 		= &nat_source_translation_value,
		.source_dest_to_nat 	= &nat_source_translation_key,
		.port_index 		= STARTING_NAT_PORT + packet_info->nat_nonat_host_id,
		.daddr 			= packet_ctx->ip_header->daddr,
		.zero_nat_port 		= (packet_info->sport == 0 ? 1 : 0),
		.nat_ip 		= nat_ip,

		.nat_port 		= nat_port,
		.found_nat 		= 0,
	};

	__u32 iterations = (1 << 16) + 1;
	bpf_loop(iterations, try_using_nat_ip_port, &input, 0);
	if (input.found_nat == 0) {
		// we have exhausted all avaliable nat ip/port combinations avaliable to this uvm -- this should be rare
		return NAT_NONAT_MAP_UPDATE_RETURN_ERROR;
	}

	return NAT_NONAT_MAP_UPDATE_RETURN_SUCCESS_NEW_CONNECTION;
}

static __u8 is_nat_or_nonat_ip(__be32 candidate_ip, __be32 *host_ip, __u8 *is_nat, __u16 *vpcid, 
		struct nat_nonat_host_group **host_group) __attribute__((noinline)) {
	if (host_ip == NULL || is_nat == NULL) {
		return -1;
	}
	*vpcid = 0;	// This will have to be initialized later. We can accurately detect the VPCID only for noNAT packets.
			// check if this is a nat ip
	*host_group = get_nat_nonat_host_group(candidate_ip, true /* is_nat */, vpcid);
	if (*host_group != NULL) {
		*is_nat = 1;
		return 0;
	}

	// check if this is a no-nat ip
	*host_group = get_nat_nonat_host_group(candidate_ip, false /* is_nat */, vpcid);
	if (*host_group != NULL) {
		*is_nat = 0;
		return 0;
	}
	return -1;
}

static __u8 update_with_load_balancer_info(__be32 load_balancer_ip, struct packet_host_context* packet_ctx) __attribute__((noinline)) {
	if (packet_ctx == NULL || packet_ctx->packet_info == NULL) {
		return -1;
	}
	packet_ctx->load_balancer_info = get_public_load_balancer_info(load_balancer_ip);
	if (packet_ctx->load_balancer_info == NULL) {
		return -1;
	}
	packet_ctx->packet_info->source_tip = OUTSIDE_VPC_IP_TIP;
	packet_ctx->packet_info->next_hop_host_ip = packet_ctx->load_balancer_info->host_ip;
	packet_ctx->packet_info->lor_host_lb_ip = load_balancer_ip;
	return 0;
}

static int get_packet_static_info(struct packet_host_context *packet_ctx) __attribute__((noinline)) {
	if (packet_ctx == NULL || packet_ctx->ctx == NULL || packet_ctx->ip_header == NULL || packet_ctx->packet_info == NULL) {
		return -1;
	}
	struct host_packet_context_value *packet_info = packet_ctx->packet_info;
	packet_info->is_vxlan_encapped = 0;
	packet_ctx->inner_ip_header = NULL;

	if (packet_ctx->ip_header->protocol == IPPROTO_UDP) {
		struct udphdr *udp_header = NULL;
		VALIDATE_UDP_PACKET(packet_ctx->ctx, packet_ctx->ip_header, udp_header, udp_header = NULL);
		if (udp_header != NULL && udp_header->dest == bpf_htons(IANA_VXLAN_UDP_PORT)) {
			struct vxlanhdr *vxlan_header;
			VALIDATE_VXLAN_PACKET(packet_ctx->ctx, udp_header, vxlan_header, vxlan_header = NULL);
			if (vxlan_header != NULL) { 
				struct routinghdr *rt_header;
				VALIDATE_ROUTING_PACKET(packet_ctx->ctx, vxlan_header, rt_header, rt_header = NULL);
				if (rt_header != NULL) { 
					packet_info->packet_type = rt_header->case_number;
					packet_info->url_id_type = rt_header->url_id_type;
					packet_info->source_tip = rt_header->uvm_tip;
					packet_info->next_hop_tip = rt_header->next_hop_tip;
					packet_info->lor_host_lb_ip = rt_header->lor_host_lb_ip;
					packet_info->is_vxlan_encapped = 1;
					packet_info->metadata = rt_header->metadata;
					packet_info->url_id = rt_header->url_id;

					struct ethhdr *eth_header = (struct ethhdr*)(rt_header + 1);
					if ((void *)(eth_header + 1) <= (void*)(__u64)packet_ctx->ctx->data_end) {
						struct iphdr *ip_header = (struct iphdr *)(eth_header + 1);
						if ((void *)(ip_header + 1) <= (void*)(__u64)packet_ctx->ctx->data_end) {
							packet_ctx->inner_ip_header = ip_header;
						}
					}

					return 0;
				}
			}
		}
	}
	// the packet is not VXLAN so it must either be from the outside world (class 7/8) or a pure IP routed packet (class 5)
	__u8 is_nat = 0;
	if (update_with_load_balancer_info(packet_ctx->ip_header->daddr, packet_ctx) == 0) { // Class 8
		packet_info->packet_type = PACKET_TYPE_PUBLIC_LOAD_BALANCER;
		packet_info->source_ip = packet_ctx->ip_header->saddr;
		return 0;
	}
	if (is_nat_or_nonat_ip(packet_ctx->ip_header->daddr, &packet_info->next_hop_host_ip, &is_nat, &packet_info->d_vpcid,
				&packet_ctx->nat_nonat_host_group) != 0) { // Class 5
		packet_info->packet_type = PACKET_IP_ROUTED_EW;
		packet_info->next_hop_tip = packet_ctx->ip_header->daddr;
		packet_info->source_tip = packet_ctx->ip_header->saddr;
	} else {
		// Class 7
		packet_info->packet_type = is_nat ? PACKET_TYPE_NAT_REPLY_INGRESS : PACKET_TYPE_NONAT_REQUEST_REPLY_INGRESS;
		packet_info->nat_nonat_ip = packet_ctx->ip_header->daddr;
		packet_info->source_ip = packet_ctx->ip_header->saddr;
	}
	return 0;
}

static int get_local_nat_nonat_host(struct packet_host_context *packet_ctx, __u8 is_nat) {
	if (packet_ctx == NULL || packet_ctx->packet_info == NULL) {
		return -1;
	}
	struct host_packet_context_value *packet_info = packet_ctx->packet_info;
	if (packet_ctx->nat_nonat_host_group == NULL) {
		packet_ctx->nat_nonat_host_group = get_nat_nonat_host_group(packet_info->nat_nonat_ip, is_nat, &packet_info->d_vpcid);
	}
	packet_info->nat_nonat_host_id = get_preferred_nat_nonat_host(packet_ctx->nat_nonat_host_group, LOCAL_HOST_ETH_IP, &packet_info->next_hop_host_ip);
	ibpf_printk("nat ip %pI4 next host %pI4 host id %d\n", &packet_info->nat_nonat_ip, &packet_info->next_hop_host_ip, packet_info->nat_nonat_host_id);
	return packet_info->nat_nonat_host_id >= MAX_NAT_NONAT_HOSTS ? -1 : 0;
}

static int get_host_packet_context(struct packet_host_context *packet_ctx) __attribute__((noinline)) {
	if (packet_ctx == NULL || packet_ctx->ctx == NULL || packet_ctx->packet_info == NULL) {
		return -1;
	}
	struct host_packet_context_value *packet_info = packet_ctx->packet_info;

	packet_info->packet_type = PACKET_TYPE_GARBAGE;
	VALIDATE_ETH_PACKET(packet_ctx->ctx, packet_ctx->eth_header, return -1);

	// Check if the packet is an broadcast -- if yes, it must be from the underlay as all UVM packets -- including UVM broadcasts 
	// -- are encapped in IP
	mac_addr_t bcast_mac = { .mac_64 = 0xFFFFFFFFFFFFFFFFUL, };
	mac_addr_t eth_dest_mac;
	__builtin_memcpy(eth_dest_mac.mac, packet_ctx->eth_header->h_dest, 6);
	if (macs_equal(&eth_dest_mac, &bcast_mac) == 0) {
		packet_info->packet_type = PACKET_TYPE_UNDERLAY_BCAST;
		return -1;
	}

	// Check if the packet is IP -- if not, it must be from the underlay as all UVM packets are encapped in IP
	packet_info->packet_type = PACKET_TYPE_UNDERLAY_RAW;
	packet_info->packet_path = INGRESS_PATH;
	VALIDATE_IP_PACKET(packet_ctx->ctx, packet_ctx->eth_header, packet_ctx->ip_header, return -1);
	packet_info->packet_type = PACKET_TYPE_UNDERLAY_IP;

	// Get the packet type and basic information (ex. next hop tip, source uvm tip, lor host ip)
	if (get_packet_static_info(packet_ctx) != 0 || packet_info->packet_type == PACKET_TYPE_GARBAGE) {
		return -1;
	}

	// Class 11: Check if packet is from E/W Host and arrives at us to close a load balancer connection
	if (packet_info->packet_type == PACKET_TYPE_HOST_HOST_METADATA && packet_info->metadata == ROUTING_HDR_METADATA_HOST_HOST_LB_CLOSE_CONNECTION) {
		packet_info->packet_path = INGRESS_PATH;
		packet_info->next_hop_is_local = 1;
		packet_info->class_number = 11;
		return 0;
	}

	// Class 7: Check if the packet is from the outside world to deNAT/deNO-NAT
	if (packet_info->packet_type == PACKET_TYPE_NAT_REPLY_INGRESS || packet_info->packet_type == PACKET_TYPE_NONAT_REQUEST_REPLY_INGRESS) {
		packet_info->packet_path = INGRESS_PATH;
		if (get_local_nat_nonat_host(packet_ctx, packet_info->packet_type == PACKET_TYPE_NAT_REPLY_INGRESS) != 0) {
			return -1;
		}
		packet_info->next_hop_is_local = HOST_IP_IS_LOCAL(packet_info->next_hop_host_ip); // For new nonat incoming requests, we'll reevaluate
		packet_info->class_number = 7;
		return 0;
	}

	// Class 8: Check if the packet is from the outside work heading to a public load balancer IP
	if (packet_info->packet_type == PACKET_TYPE_PUBLIC_LOAD_BALANCER) {
		packet_info->packet_path = INGRESS_PATH;
		if (packet_ctx->load_balancer_info == NULL && update_with_load_balancer_info(packet_info->lor_host_lb_ip, packet_ctx) != 0) {
			return -1;
		}
		packet_info->next_hop_is_local = HOST_IP_IS_LOCAL(packet_info->next_hop_host_ip);
		packet_info->has_lb_ip = 1;
		packet_info->class_number = 8;
		return 0;
	}

	// Class 3: Check if packet is from E/W Host (originating outside world) and arrives at us for de-NAT/de-noNATing
	else if (packet_info->packet_type == PACKET_NAT_INGRESS_EW || packet_info->packet_type == PACKET_NONAT_INGRESS_EW) {
		if (packet_ctx->inner_ip_header == NULL) {
			return -1;
		}
		packet_info->packet_path = INGRESS_PATH;
		packet_info->class_number = 3;
		packet_info->next_hop_is_local = 1;
		if (!check_for_class_10(packet_info)) {
			packet_info->nat_nonat_ip = packet_ctx->inner_ip_header->daddr;
			if (get_local_nat_nonat_host(packet_ctx, packet_info->packet_type == PACKET_NAT_INGRESS_EW) != 0) {
				return -1;
			}
			packet_info->next_hop_is_local = HOST_IP_IS_LOCAL(packet_info->next_hop_host_ip);
			return 0;
		}
	}

	// Class 6: Check if packet is from UVM, meant for a LOR host, and is here because the host must NAT/NO-NAT it
	else if (packet_info->packet_type == PACKET_LOR_NAT_EGRESS_WITHOUT_ROUTER ||
			packet_info->packet_type == PACKET_LOR_NAT_EGRESS_WITH_ROUTER ||
			packet_info->packet_type == PACKET_LOR_NONAT_EGRESS_WITHOUT_ROUTER ||
			packet_info->packet_type == PACKET_LOR_NONAT_EGRESS_WITH_ROUTER) {
		if (packet_ctx->inner_ip_header == NULL) {
			return -1;
		}
		packet_info->packet_path = EGRESS_PATH;
		packet_info->class_number = 6;
		packet_info->next_hop_is_local = 1;
		if (!check_for_class_10(packet_info)) {
			packet_info->nat_nonat_ip = packet_ctx->inner_ip_header->saddr;
			if (get_local_nat_nonat_host(packet_ctx,
						packet_info->packet_type == PACKET_LOR_NAT_EGRESS_WITHOUT_ROUTER || 
						packet_info->packet_type == PACKET_LOR_NAT_EGRESS_WITH_ROUTER) != 0) {
				return -1;
			}
			packet_info->next_hop_is_local = HOST_IP_IS_LOCAL(packet_info->next_hop_host_ip);
			if (packet_info->next_hop_is_local == 0) {
				return 0;
			}
		}
	}

	// Class 9: Packet must be from another host and is here because the host must de-NAT/NO-NAT it
	else if (packet_info->packet_type == PACKET_TYPE_LOAD_BALANCER_NONAT_REQUEST_REPLY_INGRESS) {
		if (packet_ctx->inner_ip_header == NULL) {
			return -1;
		}
		packet_info->packet_path = INGRESS_PATH;
		packet_info->has_lb_ip = 1;
		packet_info->class_number = 9;
		packet_info->next_hop_is_local = 1;
		if (!check_for_class_10(packet_info)) {
			packet_info->nat_nonat_ip = packet_ctx->inner_ip_header->daddr; // equivalent to the load balancer backed IP
			if (get_local_nat_nonat_host(packet_ctx, false /* is not nat */) != 0) {
				return -1;
			}
			packet_info->next_hop_is_local = HOST_IP_IS_LOCAL(packet_info->next_hop_host_ip);
			return 0;
		}
	}

	// Class 1: Check if packet is from UVM, meant for the outside, and is here because the host must NAT/NO-NAT it
	else if (packet_info->packet_type == PACKET_NAT_EGRESS_WITHOUT_ROUTER || 
			packet_info->packet_type == PACKET_NAT_EGRESS_WITH_ROUTER || 
			packet_info->packet_type == PACKET_NONAT_EGRESS_WITHOUT_ROUTER || 
			packet_info->packet_type == PACKET_NONAT_EGRESS_WITH_ROUTER) {
		if (packet_ctx->inner_ip_header == NULL) {
			return -1;
		}
		packet_info->packet_path = EGRESS_PATH;
		packet_info->class_number = 1;
		packet_info->next_hop_is_local = 1;
		if (!check_for_class_10(packet_info)) {
			packet_info->nat_nonat_ip = packet_ctx->inner_ip_header->saddr;
			if (get_local_nat_nonat_host(packet_ctx,
						packet_info->packet_type == PACKET_NAT_EGRESS_WITHOUT_ROUTER || 
						packet_info->packet_type == PACKET_NAT_EGRESS_WITH_ROUTER) != 0) {
				ebpf_printk("no host for nonat ip");
				return -1;
			}
			ebpf_printk("nonat host %pI4", &packet_info->next_hop_host_ip);
			packet_info->next_hop_is_local = HOST_IP_IS_LOCAL(packet_info->next_hop_host_ip);
			if (packet_info->next_hop_is_local == 0) {
				ebpf_printk("nonat host not local");
				return 0;
			}
		}
	}

	// Class 2: Check if packet is from outside world, has already been de-NAT/NO-NATed by peer host and the destination UVM/router
	// is on our host
	else if (packet_info->packet_type == PACKET_DENAT_INGRESS_WITHOUT_UVM_ROUTER || 
			packet_info->packet_type == PACKET_DENAT_INGRESS_WITH_UVM_ROUTER ||
			packet_info->packet_type == PACKET_DENONAT_INGRESS_WITHOUT_UVM_ROUTER ||
			packet_info->packet_type == PACKET_DENONAT_INGRESS_WITH_UVM_ROUTER) {
		packet_info->packet_path = INGRESS_PATH;
		packet_info->class_number = 2;
	}

	// Class 4: Check for mac-routed packets
	else if (packet_info->packet_type == PACKET_MAC_ROUTED_EW) {
		packet_info->packet_path = INGRESS_PATH;
		packet_info->class_number = 4;
	}

	// Class 5: Check for ip-routed packets
	else if (packet_info->packet_type == PACKET_IP_ROUTED_EW) {
		packet_info->packet_path = INGRESS_PATH;
		packet_info->class_number = 5;
	}

	// If we got here, the packet classification is one of the following:
	// 	Class 4-broadcast: Broadcast IPs are part of TIP space and have a special uvm_ifindex
	// 	Class 5: The packet must be a within-vpc, IP-routed packet and thus its next hop tip is it's final destination UVM TIP
	// 	Class 2/4-non-broadcast: The source IP must indicate the TIP of the UVM/router the packet is supposed to be delievered to next
	//	Class 1/6: The packet is egress outside-vpc, and thus the next hop tip is tip of the router or source UVM TIP
	//	Class 10: The packet is a NAT/noNAT metadata, and thus the next hop tip is the tip of the router ror source UVM TIP
	struct tip_value *tip_info = get_tip_value(packet_info->next_hop_tip);
	if (tip_info == NULL) {
		packet_info->packet_type = PACKET_TYPE_UNDERLAY_IP;
		return -1;
	} else if (tip_info->uvm_ifindex == SBTIP_BROADCAST) { // Class 4-broadcast
		packet_info->class_number = 4;
		packet_info->packet_type = PACKET_UVM_BROADCAST_EW;
		packet_info->packet_path = INGRESS_PATH;
		packet_info->next_hop_is_local = 1;
		return 0;
	} else {
		fbpf_printk("tip %pI4 ip %pI4", &packet_info->next_hop_tip, &tip_info->uvm_ip);
		fbpf_printk("ifindex %d", tip_info->uvm_ifindex);
		packet_info->next_hop_host_ip = tip_info->host_ip;
		if (packet_info->class_number != 1 && packet_info->class_number != 6 && packet_info->class_number != 10) {
			packet_info->next_hop_ifindex = tip_info->uvm_ifindex;
			packet_info->next_hop_is_local = HOST_IP_IS_LOCAL(packet_info->next_hop_host_ip);
		}
		packet_info->next_hop_ip = tip_info->uvm_ip;
		packet_info->next_hop_mac.mac_64 = tip_info->uvm_mac.mac_64;
		if (packet_info->class_number == 5 || packet_info->class_number == 8) {
			packet_info->next_hop_sbtip = tip_info->sb_tip;
		}
		return 0;
	}
}

static int get_protocol_sport_dport(struct packet_host_context *packet_ctx) __attribute__((noinline)) {
	if (packet_ctx == NULL || packet_ctx->ctx == NULL || packet_ctx->packet_info == NULL) {
		return -1;
	}
	struct host_packet_context_value *packet_info = packet_ctx->packet_info;
	packet_info->sport = 0;
	packet_info->dport = 0;
	if (packet_ctx->ip_header == NULL) {
		packet_info->protocol = MICRO_SEG_NOTA;
		return 0;
	}
	struct udphdr *udp_header = NULL;
	struct tcphdr *tcp_header = NULL;
	struct icmphdr *icmp_header = NULL;
	__u8 egress = (packet_info->packet_path == EGRESS_PATH);
	switch (packet_ctx->ip_header->protocol) {
		case IPPROTO_ICMP: 	// Return the identifier ID here to be used later for NATing purposes
			VALIDATE_ICMP_PACKET(packet_ctx->ctx, packet_ctx->ip_header, icmp_header, return -1);
			if (icmp_header->type == ICMP_ECHO || icmp_header->type == ICMP_ECHOREPLY) {
				packet_info->sport = icmp_header->un.echo.id;
				packet_info->dport = icmp_header->un.echo.sequence;
				if (egress == 0) {
					packet_info->dport = icmp_header->un.echo.id;
					packet_info->sport = icmp_header->un.echo.sequence;
				}
			}
			packet_info->protocol = MICRO_SEG_ICMP;
			break;
		case IPPROTO_UDP:
			VALIDATE_UDP_PACKET(packet_ctx->ctx, packet_ctx->ip_header, udp_header, return -1);
			packet_info->sport = udp_header->source;
			packet_info->dport = udp_header->dest;
			packet_info->protocol = MICRO_SEG_UDP;
			break;
		case IPPROTO_TCP:
			VALIDATE_TCP_PACKET(packet_ctx->ctx, packet_ctx->ip_header, tcp_header, return -1);
			packet_info->sport = tcp_header->source;
			packet_info->dport = tcp_header->dest;
			if (packet_info->dport == bpf_htons(80) || packet_info->dport == bpf_htons(7104)) {
				packet_info->protocol = MICRO_SEG_HTTP;
			} else if (packet_info->dport == bpf_htons(443) || packet_info->dport == bpf_htons(7102) || 
					packet_info->dport == bpf_htons(7105)) {
				packet_info->protocol = MICRO_SEG_HTTPS;
			} else {
				packet_info->protocol = MICRO_SEG_TCP;
			}
			packet_ctx->packet_info->tcp_fin = tcp_header->fin;
			packet_ctx->packet_info->tcp_rst = tcp_header->rst;
			packet_ctx->packet_info->tcp_syn = tcp_header->syn;
			packet_ctx->packet_info->tcp_ack = tcp_header->ack;

			break;
		default:
			packet_info->protocol = MICRO_SEG_IP;
			break;
	}
	return 0;
}

static void set_l4_type_port_ip(struct __sk_buff *ctx, struct set_l4_ports_context *input, __u32 l4_offset) __attribute__((noinline)) {
	if (ctx == NULL || input == NULL || input->ip_header == NULL) {
		return;
	}
	struct iphdr *ip_header = input->ip_header;
	enum MICRO_SEG_PROTOCOL protocol = input->protocol;
	__be16 dport = input->dport;
	__be16 sport = input->sport;

	__be32 old_addr = (input->packet_path == EGRESS_PATH) ? ip_header->daddr : ip_header->saddr;
	if (input->packet_path == EGRESS_PATH) {
		ip_header->daddr = input->addr;
	} else {
		ip_header->saddr = input->addr;
	}

	if (protocol == MICRO_SEG_TCP || protocol == MICRO_SEG_HTTP || protocol == MICRO_SEG_HTTPS) {
		__u8 valid = 1;
		struct tcphdr *tcp_header = NULL;
		VALIDATE_TCP_PACKET(ctx, ip_header, tcp_header, valid = 0);
		if (valid == 1) {
			__be16 org_dport = tcp_header->dest;
			tcp_header->dest = dport;
			__be16 org_sport = tcp_header->source;
			tcp_header->source = sport;
			bpf_l4_csum_replace(ctx, l4_offset + offsetof(struct tcphdr, check), org_dport, dport, sizeof(dport));
			bpf_l4_csum_replace(ctx, l4_offset + offsetof(struct tcphdr, check), org_sport, sport, sizeof(sport));
			bpf_l4_csum_replace(ctx, l4_offset + offsetof(struct tcphdr, check), old_addr, input->addr, sizeof(__be32));
			bpf_l3_csum_replace(ctx, sizeof(struct ethhdr) + offsetof(struct iphdr, check), old_addr, input->addr, sizeof(input->addr));
			return;
		}
	}

	if (protocol == MICRO_SEG_UDP) {
		__u8 valid = 1;
		struct udphdr *udp_header = NULL;
		VALIDATE_UDP_PACKET(ctx, ip_header, udp_header, valid = 0);
		if (valid == 1) {
			__be16 org_dport = udp_header->dest;
			udp_header->dest = dport;
			__be16 org_sport = udp_header->source;
			udp_header->source = sport;
			bpf_l4_csum_replace(ctx, l4_offset + offsetof(struct udphdr, check), org_dport, dport, sizeof(dport));
			bpf_l4_csum_replace(ctx, l4_offset + offsetof(struct udphdr, check), org_sport, sport, sizeof(sport));
			bpf_l4_csum_replace(ctx, l4_offset + offsetof(struct udphdr, check), old_addr, input->addr, sizeof(__be32));
			bpf_l3_csum_replace(ctx, sizeof(struct ethhdr) + offsetof(struct iphdr, check), old_addr, input->addr, sizeof(input->addr));
			return;
		}
	}

	if (protocol == MICRO_SEG_ICMP) {
		__u8 valid = 1;
		struct icmphdr *icmp_header = NULL;
		VALIDATE_ICMP_PACKET(ctx, ip_header, icmp_header, valid = 0);
		if (valid == 1) {
			if (icmp_header->type == ICMP_ECHO || icmp_header->type == ICMP_ECHOREPLY) {
				__be16 org_id = icmp_header->un.echo.id;
				icmp_header->un.echo.id = input->packet_path == EGRESS_PATH ? dport : sport;

				bpf_l4_csum_replace(ctx, l4_offset + offsetof(struct icmphdr, checksum), org_id, 
						icmp_header->un.echo.id, sizeof(org_id));
				bpf_l3_csum_replace(ctx, sizeof(struct ethhdr) + offsetof(struct iphdr, check), old_addr, input->addr, 
						sizeof(input->addr));
			}
			return;
		}
	}
}

static int convert_to_nat_nonat_metadata(struct __sk_buff* ctx, struct host_nat_nonat_metadata *host_nat_nonat_metadata) __attribute__((noinline)) {
	if (ctx == NULL || host_nat_nonat_metadata == NULL) {
		return -1;
	}
	if (resize_packet(ctx, MIN_MTU /* TODO: fetch device mtu */, sizeof(struct host_nat_nonat_metadata)) < 0) {
		return -1;
	}
	void *data_end = (void *)(__u64)ctx->data_end;
	void *data = (void *)(__u64)ctx->data;

	if ((data + sizeof(struct host_nat_nonat_metadata)) > data_end) {
		return -1;
	}
	__builtin_memcpy(data, host_nat_nonat_metadata, sizeof(struct host_nat_nonat_metadata));
	return 0;
}

static int send_nat_nonat_metadata_to_host(__u32 index, struct packet_host_context* packet_ctx) __attribute__((noinline)) {
	if (packet_ctx == NULL || packet_ctx->ctx == NULL || packet_ctx->nat_nonat_host_group == NULL) {
		return 1;
	}
	if (index < 0 || index >= MAX_NAT_NONAT_HOSTS || index >= packet_ctx->nat_nonat_host_group->host_ips_length) {
		return 1;
	}

	__be32 host_ip = packet_ctx->nat_nonat_host_group->host_ips[index];
	if (host_ip == 0) {
		return 1;
	} else if (host_ip == LOCAL_HOST_ETH_IP) {
		return 0;
	}

	struct ethhdr *eth_header = NULL;
	struct iphdr *ip_header = NULL;
	VALIDATE_ETH_PACKET(packet_ctx->ctx, eth_header, return 1);
	VALIDATE_IP_PACKET(packet_ctx->ctx, eth_header, ip_header, return 1);

	mac_addr_t local_host_mac = { .mac_64 = LOCAL_HOST_ETH_MAC };
	mac_addr_t host_mac = { .mac_64 = 0 };
	host_mac.mac_64 = get_host_mac(LOCAL_UNDERLAY_GW_IP, LOCAL_HOST_ETH_IP, local_host_mac);

	ibpf_printk("send nat/nonat metadata upd to %pI4:%llx", &host_ip, host_mac.mac_64);
	if (host_mac.mac_64 == 0) {
		arp_for_host(packet_ctx->ctx, LOCAL_UNDERLAY_GW_IP, LOCAL_HOST_ETH_IP, 
				local_host_mac, LOCAL_HOST_ETH_INDEX, false /* clone_redirect */);
		return 1;
	}

	set_mac(eth_header->h_dest, &host_mac);
	update_ip_daddr(packet_ctx->ctx, ip_header, host_ip, sizeof(struct ethhdr), -1);
	bpf_clone_redirect(packet_ctx->ctx, LOCAL_HOST_ETH_INDEX, 0);
	return 0;
}

static int replicate_nat_nonat_metadata(struct packet_host_context *packet_ctx, __u8 is_nat) __attribute__((noinline)) {
	if (packet_ctx == NULL || packet_ctx->ctx == NULL || packet_ctx->ip_header == NULL || packet_ctx->packet_info == NULL || 
			packet_ctx->nat_nonat_host_group == NULL) {
		return -1;
	}

	struct host_packet_context_value *packet_info = packet_ctx->packet_info;
	struct host_nat_nonat_metadata host_nat_nonat_metadata = {
		.destination_ip = packet_info->destination_ip,
		.nat_nonat_ip = packet_info->nat_nonat_ip,
		.source_ip = packet_info->source_ip,
		.nat_port = packet_info->nat_port,
		.destination_port = packet_info->dport,
		.source_port = packet_info->sport,
		.unused = 0,
	};

	if (convert_to_nat_nonat_metadata(packet_ctx->ctx, &host_nat_nonat_metadata) < 0) {
		return -1;
	}
	mac_addr_t host_mac = { .mac_64 = LOCAL_HOST_ETH_MAC };
	CREATE_ENCAP_ETH(host_mac.mac, host_mac.mac /* we will change this to actual host mac when we send the packet */);
	CREATE_ENCAP_IP(LOCAL_HOST_ETH_IP, LOCAL_HOST_ETH_IP /* we will change this to the IP of the next host in host_group */, IPPROTO_UDP); 
	CREATE_ENCAP_ROUTINGHDR(packet_ctx->packet_info->packet_type, ROUTING_HDR_METADATA_HOST_HOST_NAT_NONAT_REFRESH,
			packet_ctx->packet_info->source_tip, packet_ctx->packet_info->next_hop_tip, 
			packet_ctx->packet_info->lor_host_lb_ip, packet_ctx->packet_info->url_id,
			packet_ctx->packet_info->url_id_type);
	encap_routinghdr.unused = 0x1234;
	if (encap_with_routinghdr(packet_ctx->ctx, &encap_ethhdr, &encap_iphdr, &encap_routinghdr) != 0) { 
		return -1;
	}

	bpf_loop(MAX_NAT_NONAT_HOSTS, send_nat_nonat_metadata_to_host, packet_ctx, 0);
	return 0;
}

static enum NAT_NONAT_MAP_UPDATE_RETURN update_nat_connection_map(struct packet_host_context *packet_ctx) __attribute__((noinline)) {
	if (packet_ctx == NULL || packet_ctx->ctx == NULL || packet_ctx->ip_header == NULL || packet_ctx->packet_info == NULL) {
		return NAT_NONAT_MAP_UPDATE_RETURN_ERROR;
	}
	struct host_packet_context_value *packet_info = packet_ctx->packet_info;

	// === Fetch a NAT port (in network order) to replace the source port in the packet
	__be32 nat_ip = packet_info->nat_nonat_ip; // This was stored in nat_nonat_ip when the packet was classified as NAT/noNAT egress 
	enum NAT_NONAT_MAP_UPDATE_RETURN nat_port_state = get_nat_port(packet_ctx, nat_ip, &packet_info->nat_port);
	if (nat_port_state != NAT_NONAT_MAP_UPDATE_RETURN_SUCCESS && nat_port_state != NAT_NONAT_MAP_UPDATE_RETURN_SUCCESS_NEW_CONNECTION) {
		return nat_port_state;
	}
	__be16 nat_port = packet_info->nat_port;
	ibpf_printk("NAT: s %d(%d)->n %d(%d), d %d(%d)\n", bpf_ntohs(packet_info->sport), packet_info->sport, 
			bpf_ntohs(nat_port), nat_port, bpf_ntohs(packet_info->dport), packet_info->dport);

	// === Set source mac to be the true host mac
	mac_addr_t host_mac = { .mac_64 = LOCAL_HOST_ETH_MAC };
	set_mac(packet_ctx->eth_header->h_source, &host_mac);

	// === Update source port to be the nat port
	struct set_l4_ports_context pkt_protocol_ports_context = {
		.ip_header = packet_ctx->ip_header,
		.sport = nat_port,
		.dport = packet_info->dport,
		.packet_path = INGRESS_PATH,
		.protocol = packet_info->protocol,
		.addr = packet_ctx->ip_header->saddr,
	};

	set_l4_type_port_ip(packet_ctx->ctx, &pkt_protocol_ports_context, sizeof(struct ethhdr) + (packet_ctx->ip_header->ihl * 4));

	return nat_port_state;
}

static enum NAT_NONAT_MAP_UPDATE_RETURN update_nonat_connection_map(struct host_packet_context_value *packet_info) __attribute__((noinline)) {
	if (packet_info == NULL) {
		return NAT_NONAT_MAP_UPDATE_RETURN_ERROR;
	}

	// === upsert a no-nat connection entry, recording the router/source uvm information and the source uvm tip
	struct nonat_connection_key key = { 
		.nonat_ip = packet_info->nat_nonat_ip,
		.remote_ip = (packet_info->packet_path == EGRESS_PATH) ? packet_info->destination_ip : packet_info->source_ip,
		.remote_port = (packet_info->packet_path == EGRESS_PATH) ? packet_info->dport : packet_info->sport,
		.unused = 0,
	};

	__u8 next_hop_router = (packet_info->packet_path == EGRESS_PATH) ?
		(packet_info->packet_type == PACKET_NONAT_EGRESS_WITH_ROUTER || 
		 packet_info->packet_type == PACKET_LOR_NONAT_EGRESS_WITH_ROUTER) :
		(packet_info->packet_type == PACKET_DENONAT_INGRESS_WITH_UVM_ROUTER);

	struct nonat_connection_value value = {
		.state = {
			.next_hop_host_mac 	= { .mac_64 = packet_info->next_hop_host_mac.mac_64, },
			.next_hop_host_ip 	= packet_info->next_hop_host_ip,
			.next_hop_tip 		= packet_info->next_hop_tip,
			.source_uvm_tip 	= packet_info->source_tip,
			.source_uvm_ip 		= packet_info->nat_nonat_ip, // NO-NAT IP must be source UVM's IP by definition of NO-NAT
			.source_uvm_port 	= 0,
			.next_hop_type 		= next_hop_router ? NEXT_HOP_ROUTER : NEXT_HOP_UVM,
			.url_id_type		= packet_info->url_id_type,
			.url_id			= packet_info->url_id,
			.unused 		= 0,
		},
		.load_balancer_ip = packet_info->has_lb_ip ?  packet_info->lor_host_lb_ip : 0,
	};

	if (bpf_map_update_elem(&nonat_connection_map, &key, &value, BPF_ANY) != 0) {
		return NAT_NONAT_MAP_UPDATE_RETURN_ERROR;
	}

	return NAT_NONAT_MAP_UPDATE_RETURN_SUCCESS;
}

static int send_to_l2_host(struct ethhdr *eth_header, const mac_addr_t *dmac, struct __sk_buff *ctx, __u8 clone_redirect) __attribute__((noinline)) {
	// set dest mac to be the requested destination mac 
	set_mac(eth_header->h_dest, dmac);

	// set source mac to be the true host mac
	mac_addr_t host_mac = { .mac_64 = LOCAL_HOST_ETH_MAC };
	set_mac(eth_header->h_source, &host_mac);

	ebpf_printk("send out: %llx", dmac->mac_64);

	return clone_redirect ? bpf_clone_redirect(ctx, LOCAL_HOST_ETH_INDEX, 0) : bpf_redirect(LOCAL_HOST_ETH_INDEX, 0);
}

static int send_to_underlay_router(struct packet_host_context *packet_ctx, __u8 clone_redirect) __attribute__((noinline)) {
	if (packet_ctx == NULL || packet_ctx->ctx == NULL || packet_ctx->eth_header == NULL) {
		return TC_ACT_SHOT;
	}
	mac_addr_t host_mac = { .mac_64 = LOCAL_HOST_ETH_MAC };
	mac_addr_t gateway_mac = { .mac_64 = get_host_mac(LOCAL_UNDERLAY_GW_IP, LOCAL_HOST_ETH_IP, host_mac) };
	if (gateway_mac.mac_64 == 0) {
		return arp_for_host(packet_ctx->ctx, LOCAL_UNDERLAY_GW_IP, LOCAL_HOST_ETH_IP, host_mac, LOCAL_HOST_ETH_INDEX, clone_redirect);
	}
	return send_to_l2_host(packet_ctx->eth_header, &gateway_mac, packet_ctx->ctx, clone_redirect);
}

static __u8 is_dns_reply(struct packet_host_context *packet_ctx) __attribute__((noinline)) {
	if (packet_ctx == NULL || packet_ctx->ctx == NULL || packet_ctx->ip_header == NULL || packet_ctx->packet_info == NULL) {
		return -1;
	}
	struct host_packet_context_value *packet_info = packet_ctx->packet_info;
	if (packet_info->sport != bpf_htons(DNS_PORT) || 
			(packet_info->protocol != MICRO_SEG_UDP && packet_info->protocol != MICRO_SEG_TCP)) {
		return 0;
	}
	void *dns_data = NULL;
	if (packet_info->protocol == MICRO_SEG_UDP) {
		struct udphdr *udp_header = NULL;
		VALIDATE_UDP_PACKET(packet_ctx->ctx, packet_ctx->ip_header, udp_header, return 0);
		dns_data = (void *)(udp_header + 1);
	} else {
		struct tcphdr *tcp_header = NULL;
		VALIDATE_TCP_PACKET(packet_ctx->ctx, packet_ctx->ip_header, tcp_header, return 0);
		if (tcp_header->syn || tcp_header->rst) {
			return 0;
		}
		dns_data = (void *)(tcp_header) + (tcp_header->doff*4);
	}

	struct dnshdr *dns_header = (struct dnshdr *)dns_data;
	if ((void *)(dns_header + 1) > (void *)(__u64)packet_ctx->ctx->data_end) {
		return 0;
	}
	return dns_header->qr;
}

static int set_lru_url_ip_id_map(struct host_packet_context_value* packet_info) __attribute__((noinline)) {
	if (packet_info->url_id_type == URL_ID_TYPE_NONE) {
		return 0;
	} 
	ebpf_printk("pkt has url: type %d", packet_info->url_id_type);
	struct url_ip_id_key key = {0};
	key.uvm_tip = packet_info->source_tip;
	key.url_ip = (packet_info->url_id_type == URL_ID_TYPE_SOURCE) ? packet_info->source_ip : packet_info->destination_ip;
	struct url_ip_id_value value = {
		.url_id = packet_info->url_id,
		.qos_url_category_id = 0,
		.uvm_url_counter = 0
	};
	return bpf_map_update_elem(&lru_url_ip_id_map, &key, &value, BPF_ANY);
}

enum PREPROCESS_PKT_TO_UVM_ACTION {
	PREPROCESS_PKT_TO_UVM_DROP,
	PREPROCESS_PKT_TO_UVM_CONTINUE,
	PREPROCESS_PKT_TO_UVM_REDIRECT
};
static enum PREPROCESS_PKT_TO_UVM_ACTION preprocess_pkt_to_uvm(struct packet_host_context *packet_ctx, __u8 clone_redirect) __attribute__((noinline)) {
	if (packet_ctx == NULL || packet_ctx->ctx == NULL || packet_ctx->packet_info == NULL) {
		return PREPROCESS_PKT_TO_UVM_DROP;
	}
	struct host_packet_context_value *packet_info = packet_ctx->packet_info;
	// === DNS reply packets must be analyzed by admin-ultra interface before that are acknowledged back to the uvm.
	// This ensures that admin-ultra is able to program all eBPF maps related to the domain in the DNS before the uvm
	// beings sending traffic to the domain.
	if (packet_info->metadata != ROUTING_HDR_METADATA_ADMIN_HOST_DNS_REPLY_PROCESSED && is_dns_reply(packet_ctx) == 1) {
		ebpf_printk("dns rpl--send to ultra-admin");
		if (packet_ctx->ip_header == NULL) {
			return PREPROCESS_PKT_TO_UVM_DROP;
		}
		__be32 dtip = packet_info->next_hop_tip;

		mac_addr_t tmp_mac = { .mac_64 = LOCAL_HOST_ETH_MAC };
		set_mac(packet_ctx->eth_header->h_source, &tmp_mac);
		tmp_mac.mac_64 = ((__be64)(LOCAL_HOST_ETH_INDEX) << 32) + dtip;
		set_mac(packet_ctx->eth_header->h_dest, &tmp_mac);

		__u16 admin_index = admin_interface_index();
		ebpf_printk("adm idx: %d", admin_index);
		if (clone_redirect) {
			bpf_clone_redirect(packet_ctx->ctx, admin_index, BPF_F_INGRESS);
		} else if (bpf_redirect(admin_index, BPF_F_INGRESS) == TC_ACT_REDIRECT) {
			return PREPROCESS_PKT_TO_UVM_REDIRECT;
		}
		return PREPROCESS_PKT_TO_UVM_DROP;
	}
	if (set_lru_url_ip_id_map(packet_ctx->packet_info) != 0) {
		return PREPROCESS_PKT_TO_UVM_DROP;
	}
	return PREPROCESS_PKT_TO_UVM_CONTINUE;
}

static int send_packet_to_uvm(struct packet_host_context *packet_ctx, __u8 update_dmac, __u8 clone_redirect) __attribute__((noinline)) {
	if (packet_ctx == NULL || packet_ctx->packet_info == NULL || packet_ctx->eth_header == NULL) {
		return TC_ACT_SHOT;
	}
	enum PREPROCESS_PKT_TO_UVM_ACTION ret = preprocess_pkt_to_uvm(packet_ctx, clone_redirect);
	if (ret != PREPROCESS_PKT_TO_UVM_CONTINUE) {
		return ret == PREPROCESS_PKT_TO_UVM_REDIRECT ? TC_ACT_REDIRECT : TC_ACT_SHOT;
	}

	if (update_dmac) {
		set_mac(packet_ctx->eth_header->h_dest, &packet_ctx->packet_info->next_hop_mac);
	}

	ebpf_printk("send uvm: %llx:%d", packet_ctx->packet_info->next_hop_mac.mac_64, packet_ctx->packet_info->next_hop_ifindex);
	return clone_redirect ? 
		bpf_clone_redirect(packet_ctx->ctx, packet_ctx->packet_info->next_hop_ifindex, BPF_F_INGRESS) : 
		bpf_redirect(packet_ctx->packet_info->next_hop_ifindex, BPF_F_INGRESS);
}

static enum URL_ID_TYPE flip_url_id_type(enum URL_ID_TYPE url_type) {
	if (url_type == URL_ID_TYPE_DESTINATION) {
		return URL_ID_TYPE_SOURCE;
	} else if (url_type == URL_ID_TYPE_SOURCE) {
		return URL_ID_TYPE_DESTINATION;
	}
	return URL_ID_TYPE_NONE;
}

static enum NAT_NONAT_MAP_UPDATE_RETURN denat_packet(struct packet_host_context *packet_ctx) __attribute__((noinline)) {
	if (packet_ctx == NULL || packet_ctx->ctx == NULL || packet_ctx->ip_header == NULL || packet_ctx->packet_info == NULL) {
		return NAT_NONAT_MAP_UPDATE_RETURN_ERROR;
	}
	struct host_packet_context_value *packet_info = packet_ctx->packet_info;

	struct nat_connection_key nat_connection_key = {
		.remote_ip 	= packet_ctx->ip_header->saddr,
		.nat_ip 	= packet_ctx->ip_header->daddr,
		.remote_port 	= 0, // TODO: get rid of me !
		.nat_port 	= packet_info->dport,
	};
	struct nat_connection_value *nat_connection_value = retrive_nat_connection(&nat_connection_key);
	if (nat_connection_value == NULL) {
		// It is possible that this packet is part of an existing NAT connection; however, we are a new host and were 
		// brought up after this connection started. Thus, we don't have the connection state in the 
		// nat_source_translations_map map. So, send the packet to another host in the nat_nonat_host_group, hoping
		// the other host has the connection map entry. If not host has a connection map entry, the packet's TTL will 
		// eventually hit 0 and the packet will be dropped.
		return NAT_NONAT_MAP_UPDATE_RETURN_FAILURE_NO_ENTRY;
	}

	// === Update state in packet context
	ibpf_printk("DE-NAT: uvm %d(%d)->n %d(%d)\n", bpf_ntohs(nat_connection_value->state.source_uvm_port), 
			nat_connection_value->state.source_uvm_port, 
			bpf_ntohs(nat_connection_key.nat_port), nat_connection_key.nat_port);

	packet_info->next_hop_host_mac.mac_64 = nat_connection_value->state.next_hop_host_mac.mac_64;
	packet_info->next_hop_host_ip 	= nat_connection_value->state.next_hop_host_ip;
	packet_info->next_hop_tip 	= nat_connection_value->state.next_hop_tip;
	packet_info->source_tip 	= nat_connection_value->state.source_uvm_tip;
	packet_info->source_ip 		= nat_connection_value->state.source_uvm_ip;
	packet_info->dport 		= nat_connection_value->state.source_uvm_port;
	packet_info->packet_type 	= (nat_connection_value->state.next_hop_type == NEXT_HOP_ROUTER) ? 
		PACKET_DENAT_INGRESS_WITH_UVM_ROUTER : PACKET_DENAT_INGRESS_WITHOUT_UVM_ROUTER;
	packet_info->url_id_type	= nat_connection_value->state.url_id_type;
	packet_info->url_id		= nat_connection_value->state.url_id;

	packet_info->next_hop_is_local 	= HOST_IP_IS_LOCAL(packet_info->next_hop_host_ip);
	packet_info->class_number 	= 2;

	ibpf_printk("next hop tip %pI4 ip %pI4 host %llx\n", &packet_info->next_hop_tip, &packet_info->next_hop_host_ip, 
			packet_info->next_hop_host_mac.mac_64);

	// === Get the ifindex of the next hop if it is local to this host
	if (packet_info->next_hop_is_local) {
		struct tip_value *tip_info = get_tip_value(packet_info->next_hop_tip);
		if (tip_info == NULL) {
			return NAT_NONAT_MAP_UPDATE_RETURN_ERROR;
		}
		packet_info->next_hop_ifindex = packet_info->next_hop_is_local ? tip_info->uvm_ifindex : 0;
		packet_info->next_hop_mac.mac_64 = tip_info->uvm_mac.mac_64;
	}

	// === Update destination IP and port of packet
	struct set_l4_ports_context set_l4_ports_input = {
		.ip_header = packet_ctx->ip_header,
		.sport = packet_info->sport,
		.dport = packet_info->dport,
		.packet_path = EGRESS_PATH,
		.protocol = packet_info->protocol,
		.addr = nat_connection_value->state.source_uvm_ip,
	};
	set_l4_type_port_ip(packet_ctx->ctx, &set_l4_ports_input, sizeof(struct ethhdr) + (packet_ctx->ip_header->ihl * 4));

	// === re-validate the eth headers since we will to update the destination mac to send the packet to the UVM/router or their host
	VALIDATE_ETH_PACKET(packet_ctx->ctx, packet_ctx->eth_header, return NAT_NONAT_MAP_UPDATE_RETURN_ERROR); 

	return NAT_NONAT_MAP_UPDATE_RETURN_SUCCESS;
}

static int get_uvm_router(struct local_to_tip_value* local_to_tip_value, struct host_packet_context_value *packet_info) __attribute__((noinline)) {
	if (local_to_tip_value == NULL || packet_info == NULL) {
		return -1;
	}
	// We don't support LOR routers when ingressing traffic. So, we only have to check for designated router or PBR routers.
	// If neither desginated nor PBR routers exist, we send packet directly to the destination UVM
	packet_info->next_hop_host_ip = local_to_tip_value->host_ip;
	packet_info->next_hop_tip = local_to_tip_value->tip;
	if (local_to_tip_value->designated_router_enabled == 1) {
		packet_info->next_hop_host_ip = local_to_tip_value->designated_router_host_ip;
		packet_info->next_hop_tip = local_to_tip_value->designated_router_tip;
	}
	if (local_to_tip_value->pbr_router_enabled == 0) {
		return 0;
	}

	// NOTE: we do NOT PBR rules with a source CIDR from outside the VPC. We also don't support non CIDR based remote ingress 
	// PBR rules. This means when traffic is ingressing into a UVM, the only PBR rule that may exist must have the UVM IP as 
	// the source and this packet's source IP (non-VPC IP) as the remote
	struct pbr_router *pbr_router = get_last_pbr_router(packet_info->nat_nonat_ip,
			packet_info->d_vpcid, packet_info->source_ip, !FETCH_REMOTE_ID);
	if (pbr_router == NULL) {
		return 0;
	}
	packet_info->next_hop_host_ip = pbr_router->host_ip;
	packet_info->next_hop_tip = pbr_router->egress_tip;
	return 0;
}

static int handle_incoming_nonat_connection(struct packet_host_context *packet_ctx) __attribute__((noinline)) {
	if (packet_ctx == NULL || packet_ctx->packet_info == NULL) {
		return -1;
	}
	struct host_packet_context_value *packet_info = packet_ctx->packet_info;
	struct local_to_tip_value* no_nat_local_to_tip_value = NULL;
	if ((no_nat_local_to_tip_value = get_local_information_impl(packet_info->d_vpcid, NULL, packet_info->nat_nonat_ip, 0)) == NULL) {
		return -1;
	}
	packet_info->next_hop_host_ip = no_nat_local_to_tip_value->host_ip;
	packet_info->next_hop_tip = no_nat_local_to_tip_value->tip;
	packet_info->next_hop_ip = packet_info->nat_nonat_ip;
	packet_info->source_tip = no_nat_local_to_tip_value->tip; // This is the UVM TIP when it responds back to the outside VPC entity.
								  // Since we are creating the connection entry when a packet is coming to
								  // a noNAT IP from outside, we need to initialize the source_tip with
								  // what is otherwise the destination of this packet -- so that when the
								  // UVM responds, the connection map looks perfect.

	if (get_uvm_router(no_nat_local_to_tip_value, packet_info) != 0) {
		return -1;
	}
	__u8 send_to_router = 0;
	mac_addr_t host_mac = { .mac_64 = LOCAL_HOST_ETH_MAC };
	packet_info->next_hop_host_mac.mac_64 = get_l2_aware_host_mac(packet_info->next_hop_host_ip, LOCAL_HOST_ETH_IP, host_mac, 
			LOCAL_HOST_ETH_L2_CIDR, LOCAL_UNDERLAY_GW_IP, &send_to_router);
	if (packet_info->next_hop_host_mac.mac_64 == 0) {
		arp_for_host(packet_ctx->ctx, send_to_router ? LOCAL_UNDERLAY_GW_IP : packet_info->next_hop_host_ip, 
				LOCAL_HOST_ETH_IP, host_mac, LOCAL_HOST_ETH_INDEX, true /* clone_redirect */);
		return -1;
	}
	if (update_nonat_connection_map(packet_info) == NAT_NONAT_MAP_UPDATE_RETURN_ERROR) {
		return -1;
	}
	packet_info->packet_type = (no_nat_local_to_tip_value->designated_router_enabled) ? 
		PACKET_DENONAT_INGRESS_WITH_UVM_ROUTER : PACKET_DENONAT_INGRESS_WITHOUT_UVM_ROUTER;
	return 0;
}

static enum NAT_NONAT_MAP_UPDATE_RETURN denonat_packet(struct packet_host_context *packet_ctx) __attribute__((noinline)) {
	if (packet_ctx == NULL || packet_ctx->ctx == NULL || packet_ctx->ip_header == NULL || packet_ctx->packet_info == NULL) {
		return NAT_NONAT_MAP_UPDATE_RETURN_ERROR;
	}
	struct host_packet_context_value *packet_info = packet_ctx->packet_info;

	ibpf_printk("DeNO-NAT; no-nat %pI4 remote %pI4:%d\n", &packet_info->nat_nonat_ip, &packet_ctx->ip_header->saddr,
			(__be32)(packet_ctx->packet_info->sport));

	struct nonat_connection_key nonat_connection_key = {
		.nonat_ip = packet_info->nat_nonat_ip,
		.remote_ip = packet_ctx->ip_header->saddr,
		.remote_port = packet_ctx->packet_info->sport,
		.unused = 0,
	};
	struct nonat_connection_value *nonat_connection_value = bpf_map_lookup_elem(&nonat_connection_map, &nonat_connection_key);
	__u8 new_connection = false;
	if (nonat_connection_value == NULL) {
		// It is possible that this packet is part of an existing noNAT connection; however, we are a new host and were 
		// brought up after this connection started. Thus, we don't have the connection state in the 
		// nonat_connection_map map. However, it is equally likely that this is in fact a new conenction initiated from 
		// the outside world. Since we cannot tell which case this is, we shall just treat it as a new incoming connection.
		new_connection = true;
		if (handle_incoming_nonat_connection(packet_ctx) != 0) {
			return NAT_NONAT_MAP_UPDATE_RETURN_ERROR; 
		}
	} else {
		// === Update state in packet context
		packet_info->next_hop_host_mac.mac_64 = nonat_connection_value->state.next_hop_host_mac.mac_64;
		packet_info->next_hop_host_ip 	= nonat_connection_value->state.next_hop_host_ip;
		packet_info->next_hop_tip 	= nonat_connection_value->state.next_hop_tip;
		packet_info->next_hop_ip 	= nonat_connection_value->state.source_uvm_ip;
		packet_info->source_tip 	= nonat_connection_value->state.source_uvm_tip;
		packet_info->packet_type 	= (nonat_connection_value->state.next_hop_type == NEXT_HOP_ROUTER) ? 
			PACKET_DENONAT_INGRESS_WITH_UVM_ROUTER : PACKET_DENONAT_INGRESS_WITHOUT_UVM_ROUTER;
		packet_info->url_id_type	= nonat_connection_value->state.url_id_type;
		packet_info->url_id		= nonat_connection_value->state.url_id;
		if (packet_info->has_lb_ip == 1 && update_nonat_connection_map(packet_info) == NAT_NONAT_MAP_UPDATE_RETURN_ERROR) {
			return NAT_NONAT_MAP_UPDATE_RETURN_ERROR;
		}
	}

	packet_info->next_hop_is_local = HOST_IP_IS_LOCAL(packet_info->next_hop_host_ip);
	packet_info->class_number = 2;
	ibpf_printk("next hop tip %pI4 ip %pI4 sport %d - host ip %pI4 mac %llx\n", &packet_info->next_hop_tip, &packet_info->next_hop_ip, 
			nonat_connection_key.remote_port, &packet_info->next_hop_host_ip, packet_info->next_hop_host_mac.mac_64);

	// === Get the ifindex of the next hop if it is local to this host
	if (packet_info->next_hop_is_local) {
		struct tip_value *tip_info = get_tip_value(packet_info->next_hop_tip);
		if (tip_info == NULL) {
			return NAT_NONAT_MAP_UPDATE_RETURN_ERROR;
		}
		packet_info->next_hop_ifindex = tip_info->uvm_ifindex;
		packet_info->next_hop_mac.mac_64 = tip_info->uvm_mac.mac_64;
	}

	return new_connection ? NAT_NONAT_MAP_UPDATE_RETURN_SUCCESS_NEW_CONNECTION : NAT_NONAT_MAP_UPDATE_RETURN_SUCCESS;
}

static int send_packet_to_correct_host(struct packet_host_context *packet_ctx) __attribute__((noinline)) {
	if (packet_ctx == NULL || packet_ctx->ctx == NULL || packet_ctx->eth_header == NULL || packet_ctx->ip_header == NULL 
			|| packet_ctx->packet_info == NULL) {
		return TC_ACT_SHOT;
	}
	if (ttl_decr_and_report_okay(packet_ctx->ctx, packet_ctx->ip_header, sizeof(struct ethhdr)) != 0) {
		return TC_ACT_SHOT;
	}
	VALIDATE_ETH_PACKET(packet_ctx->ctx, packet_ctx->eth_header, return TC_ACT_SHOT);
	VALIDATE_IP_PACKET(packet_ctx->ctx, packet_ctx->eth_header, packet_ctx->ip_header, return TC_ACT_SHOT);

	if (packet_ctx->packet_info->is_vxlan_encapped == 0) {
		mac_addr_t local_host_mac = {
			.mac_64 = LOCAL_HOST_ETH_MAC,
		};
		CREATE_ENCAP_ETH(local_host_mac.mac, packet_ctx->packet_info->next_hop_host_mac.mac);
		CREATE_ENCAP_IP(LOCAL_HOST_ETH_IP, packet_ctx->packet_info->next_hop_host_ip, IPPROTO_UDP);
		CREATE_ENCAP_ROUTINGHDR(packet_ctx->packet_info->packet_type, packet_ctx->packet_info->metadata, 
				packet_ctx->packet_info->source_tip, 
				packet_ctx->packet_info->next_hop_tip, packet_ctx->packet_info->lor_host_lb_ip, 
				packet_ctx->packet_info->url_id, packet_ctx->packet_info->url_id_type);
		if (encap_with_routinghdr(packet_ctx->ctx, &encap_ethhdr, &encap_iphdr, &encap_routinghdr) != 0) {
			return TC_ACT_SHOT; 
		}
		packet_ctx->packet_info->is_vxlan_encapped = 1;
	} else {

		// set dest mac to be the destination UVM/router's host mac 
		set_mac(packet_ctx->eth_header->h_dest, &packet_ctx->packet_info->next_hop_host_mac);

		// set source mac to be the true host mac
		mac_addr_t host_mac = { .mac_64 = LOCAL_HOST_ETH_MAC };
		set_mac(packet_ctx->eth_header->h_source, &host_mac);

		// set the source IP to be the true host IP and the dest IP to be destination UVM/router's host IP
		__be32 original_dip = packet_ctx->ip_header->daddr;
		__be32 original_sip = packet_ctx->ip_header->saddr;
		packet_ctx->ip_header->daddr = packet_ctx->packet_info->next_hop_host_ip;
		packet_ctx->ip_header->saddr = LOCAL_HOST_ETH_IP;
		__u16 ip_header_size = IP_SIZE(packet_ctx->ip_header);
		if (update_ip_checksum(packet_ctx->ctx, sizeof(struct ethhdr), original_sip, LOCAL_HOST_ETH_IP,
					ip_header_size, get_ip_l4_checksum_offset(MICRO_SEG_UDP)) != 0) {
			return TC_ACT_SHOT;
		} else if (update_ip_checksum(packet_ctx->ctx, sizeof(struct ethhdr), original_dip, 
					packet_ctx->packet_info->next_hop_host_ip, ip_header_size, 
					get_ip_l4_checksum_offset(MICRO_SEG_UDP)) != 0) {
			return TC_ACT_SHOT;
		}
	}
	return bpf_redirect(LOCAL_HOST_ETH_INDEX, 0);
}

struct broadcast_context {
	struct __sk_buff *ctx;
	struct sbtip_ifindex_value *uvm_ifindices;
	mac_addr_t source_mac;
	__be32 sbtip;
};

static long send_broadcast_to_uvm(__u32 index, struct broadcast_context* broadcast_context) __attribute__((noinline)) {
	if (broadcast_context == NULL || broadcast_context->ctx == NULL || broadcast_context->uvm_ifindices == NULL || 
			index >= NUM_IFINDICES_PER_KEY || index < 0) {
		return 1;
	}
	struct sbtip_ifindex_entry ifindex_entry = broadcast_context->uvm_ifindices->ifindices[index];
	if (ifindex_entry.ifindex == 0 || ifindex_entry.mac == broadcast_context->source_mac.mac_64) {
		return 0;
	} else if (ifindex_entry.ifindex == 0xFFFF) {
		return 1;
	}
	bpf_clone_redirect(broadcast_context->ctx, ifindex_entry.ifindex, BPF_F_INGRESS);
	return 0;
}
static long send_broadcast_to_subnet(__u32 index, struct broadcast_context* broadcast_context) __attribute__((noinline)) {
	if (broadcast_context == NULL || broadcast_context->ctx == NULL) {
		return 1;
	}
	struct sbtip_ifindex_key sbtip = { 
		.sbtip = broadcast_context->sbtip, 
		.index = index,
		.unused = 0,
	};
	broadcast_context->uvm_ifindices = bpf_map_lookup_elem(&sbtip_ifindex_map, &sbtip);
	if (broadcast_context->uvm_ifindices == NULL) {
		return 1;
	}
	bpf_loop(NUM_IFINDICES_PER_KEY, send_broadcast_to_uvm, broadcast_context, 0);
	return !broadcast_context->uvm_ifindices->more;
}

static void send_broadcast(struct packet_host_context *packet_ctx) __attribute__((noinline)) {
	if (packet_ctx == NULL || packet_ctx->eth_header == NULL || packet_ctx->packet_info == NULL) {
		return;
	}
	mac_addr_t broadcast_mac = { .mac_64 = 0xFFFFFFFFFFFFFFFF };
	set_mac(packet_ctx->eth_header->h_dest, &broadcast_mac);

	struct broadcast_context broadcast_context = { 
		.ctx = packet_ctx->ctx,
		.uvm_ifindices = NULL,
		.source_mac = packet_ctx->packet_info->source_mac,
		.sbtip = packet_ctx->packet_info->next_hop_tip,
	};
	ebpf_printk("send broadccast to uvms");
	bpf_loop(MIN(MAX_UVMS/NUM_IFINDICES_PER_KEY + 1, 1 << 16), send_broadcast_to_subnet, &broadcast_context, 0);
}

static __be32 get_load_balancer_backed_ip(struct packet_host_context *packet_ctx, __be32 *backed_ip) __attribute__((noinline)) {
	if (packet_ctx == NULL || packet_ctx->packet_info == NULL || backed_ip == NULL || packet_ctx->load_balancer_info == NULL) {
		return -1;
	}
	struct host_packet_context_value *packet_info = packet_ctx->packet_info;
	__u8 is_tcp = (packet_info->protocol == MICRO_SEG_TCP || packet_info->protocol == MICRO_SEG_HTTP || packet_info->protocol == MICRO_SEG_HTTPS);
	__u8 is_new_tcp_connection = is_tcp && packet_ctx->packet_info->tcp_syn && !packet_ctx->packet_info->tcp_ack;
	__u64 current_time = bpf_ktime_get_ns();
	__be16 server_port = packet_info->protocol == MICRO_SEG_UDP ? packet_info->dport : 0;

	struct load_balancer_connection_key key = {
		.load_balancer_ip = packet_info->lor_host_lb_ip,
		.client_ip = packet_info->source_ip,
		.client_port = is_tcp ? 0 : (packet_info->protocol == MICRO_SEG_ICMP ? packet_info->dport : packet_info->sport),
	};

	if (!is_new_tcp_connection) {
		struct load_balancer_connection_value *existing_backed_ip = bpf_map_lookup_elem(&load_balancer_connection_map, &key);
		if (existing_backed_ip != NULL && existing_backed_ip->server_port == server_port &&
				((existing_backed_ip->timestamp + LOAD_BALANCER_BACKEND_PERSIST_TIME) > current_time)) {
			// If the existing_backed_ip->server_ip is unavailable because the backend VM/Container died, we expect the cleanup handler
			// to remove the backend IP from the load_balancer_connection_map entry
			*backed_ip = existing_backed_ip->server_ip;
			return 0;
		}
	}

	assign_backend_load_balancer(packet_ctx->load_balancer_info, key.client_ip, backed_ip);

	ibpf_printk("creating lb connection: client %pI4:%d lb %pI4 server %pI4:%d\n", &key.client_ip, key.client_port, 
			&key.load_balancer_ip, backed_ip, server_port);
	struct load_balancer_connection_value value = {
		.server_ip = *backed_ip,
		.server_port = server_port,
		.policy = packet_ctx->load_balancer_info->policy,
		.timestamp = bpf_ktime_get_ns(),
	};
	bpf_map_update_elem(&load_balancer_connection_map, &key, &value, BPF_ANY);

	return 0;
}

static __u8 handle_nonat_with_load_balancer(struct packet_host_context *packet_ctx) __attribute__((noinline)) {
	if (packet_ctx == NULL || packet_ctx->ctx == NULL || packet_ctx->ip_header == NULL || packet_ctx->packet_info == NULL) {
		return -1;
	}

	struct host_packet_context_value *packet_info = packet_ctx->packet_info;

	struct nonat_connection_key nonat_connection_key = {
		.nonat_ip = packet_info->nat_nonat_ip,
		.remote_ip = packet_ctx->ip_header->daddr,
		.remote_port = packet_info->dport,
		.unused = 0,
	};
	struct nonat_connection_value *nonat_connection_value = bpf_map_lookup_elem(&nonat_connection_map, &nonat_connection_key);
	if (nonat_connection_value == NULL || nonat_connection_value->load_balancer_ip == 0) {
		return 0;
	}

	packet_info->lor_host_lb_ip = nonat_connection_value->load_balancer_ip;
	packet_info->has_lb_ip = 1;

	if (update_ip_saddr(packet_ctx->ctx, packet_ctx->ip_header, packet_info->lor_host_lb_ip, sizeof(struct ethhdr),
				get_ip_l4_checksum_offset(packet_info->protocol)) != 0) {
		return -1;
	}

	VALIDATE_ETH_PACKET(packet_ctx->ctx, packet_ctx->eth_header, return -1);
	VALIDATE_IP_PACKET(packet_ctx->ctx, packet_ctx->eth_header, packet_ctx->ip_header, return -1);
	return 0;
}

static __u8 set_dip_to_next_hop_ip(struct packet_host_context *packet_ctx) __attribute__((noinline)) {
	if (packet_ctx == NULL || packet_ctx->ctx == NULL || packet_ctx->ip_header == NULL || packet_ctx->packet_info == NULL) {
		return -1;
	}

	if (update_ip_daddr(packet_ctx->ctx, packet_ctx->ip_header, packet_ctx->packet_info->next_hop_ip, sizeof(struct ethhdr),
				get_ip_l4_checksum_offset(packet_ctx->packet_info->protocol)) != 0) {
		return -1;
	}

	VALIDATE_ETH_PACKET(packet_ctx->ctx, packet_ctx->eth_header, return -1);
	VALIDATE_IP_PACKET(packet_ctx->ctx, packet_ctx->eth_header, packet_ctx->ip_header, return -1);
	return 0;
}

static __u8 should_send_nat_nonat_metadata(enum ROUTING_HDR_METADATA_TYPE metadata) {
	return metadata == ROUTING_HDR_METADATA_MACVTAP_HOST_NEW_NAT_NONAT_CONNECTION ||
		metadata == ROUTING_HDR_METADATA_MACVTAP_HOST_REQUEST_NAT_NONAT_REFRESH ||
		metadata == ROUTING_HDR_METADATA_HOST_HOST_REQUEST_NAT_NONAT_REFRESH;
}

static int handle_non_local_packet(struct packet_host_context *packet_ctx) __attribute__((noinline)) {
	if (packet_ctx == NULL || packet_ctx->ctx == NULL || packet_ctx->packet_info == NULL) {
		return TC_ACT_SHOT;
	}
	__u8 send_to_router = 0;
	mac_addr_t host_mac = { .mac_64 = LOCAL_HOST_ETH_MAC };
	packet_ctx->packet_info->next_hop_host_mac.mac_64 = get_l2_aware_host_mac(packet_ctx->packet_info->next_hop_host_ip, LOCAL_HOST_ETH_IP, host_mac,
			LOCAL_HOST_ETH_L2_CIDR, LOCAL_UNDERLAY_GW_IP, &send_to_router);
	if (packet_ctx->packet_info->next_hop_host_mac.mac_64 == 0) {
		return arp_for_host(packet_ctx->ctx, send_to_router ? LOCAL_UNDERLAY_GW_IP : packet_ctx->packet_info->next_hop_host_ip,
				LOCAL_HOST_ETH_IP, host_mac, LOCAL_HOST_ETH_INDEX, false /* clone_redirect */);
	}
	if (packet_ctx->packet_info->metadata == ROUTING_HDR_METADATA_ADMIN_HOST_DNS_REPLY_PROCESSED) {
		packet_ctx->packet_info->metadata = ROUTING_HDR_METADATA_NO_METADATA;
	}
	// Case 2/5: if the packet destination UVM/router is not local to this host, send the packet E/W
	// Case 1/3/6/9: if the NAT/NO-NAT IP is not hosted by us, send packet E/W
	// Case 4-non-broadcast: if the destination UVM is not local to this host, send the packet E/W
	// Case 8-non-vxlan-encap: if the load balancer IP is not hosted by us, send packet E/W
	if (packet_ctx->packet_info->class_number == 2 || 
			packet_ctx->packet_info->class_number == 3 || 
			(packet_ctx->packet_info->class_number == 4 && packet_ctx->packet_info->packet_type != PACKET_UVM_BROADCAST_EW) || 
			packet_ctx->packet_info->class_number == 5 || 
			packet_ctx->packet_info->class_number == 6 ||
			(packet_ctx->packet_info->class_number == 8 && packet_ctx->packet_info->is_vxlan_encapped == 1) ||
			(packet_ctx->packet_info->class_number == 9 && packet_ctx->packet_info->is_vxlan_encapped == 1)
	   ) {
		return send_packet_to_correct_host(packet_ctx);
	}
	// Case 7: if the return packet's NAT/NO-NAT IP is not hosted by us, encap the packet and send it E/W
	else if (packet_ctx->packet_info->class_number == 7) {
		if (packet_ctx->ctx != NULL && packet_ctx->ip_header != NULL) {
			__be16 prev_frag_off = packet_ctx->ip_header->frag_off;
			__be16 new_frag_off = IP_DF; //packet_ctx->ip_header->frag_off | IP_DF;
			packet_ctx->ip_header->frag_off = new_frag_off;
			bpf_l3_csum_replace(packet_ctx->ctx, sizeof(struct ethhdr) + offsetof(struct iphdr, check), prev_frag_off, new_frag_off, sizeof(__u16)); 
		}

		mac_addr_t host_mac = { .mac_64 = LOCAL_HOST_ETH_MAC };
		CREATE_ENCAP_ETH(host_mac.mac, packet_ctx->packet_info->next_hop_host_mac.mac);
		CREATE_ENCAP_IP(LOCAL_HOST_ETH_IP, packet_ctx->packet_info->next_hop_host_ip, IPPROTO_UDP);
		CREATE_ENCAP_ROUTINGHDR(packet_ctx->packet_info->packet_type == PACKET_TYPE_NAT_REPLY_INGRESS ? 
				PACKET_NAT_INGRESS_EW : PACKET_NONAT_INGRESS_EW, ROUTING_HDR_METADATA_NO_METADATA,
				0, 0, NO_LOR_IP, packet_ctx->packet_info->url_id, packet_ctx->packet_info->url_id_type);
		if (encap_with_routinghdr(packet_ctx->ctx, &encap_ethhdr, &encap_iphdr, &encap_routinghdr) != 0) {
			return TC_ACT_SHOT;
		}
		return bpf_redirect(LOCAL_HOST_ETH_INDEX, 0);
	}
	// Class 8: if the public load balancer IP is not hosted by us, encap thet packet and send it E/W
	// Class 9: if the NAT/NO-NAT IP is not hosted by us, encap thet packet and send it E/W
	else if (packet_ctx->packet_info->class_number == 8 || packet_ctx->packet_info->class_number == 9) {
		mac_addr_t host_mac = { .mac_64 = LOCAL_HOST_ETH_MAC };
		CREATE_ENCAP_ETH(host_mac.mac, packet_ctx->packet_info->next_hop_host_mac.mac);
		CREATE_ENCAP_IP(LOCAL_HOST_ETH_IP, packet_ctx->packet_info->next_hop_host_ip, IPPROTO_UDP);
		CREATE_ENCAP_ROUTINGHDR(packet_ctx->packet_info->packet_type, ROUTING_HDR_METADATA_NO_METADATA, 
				packet_ctx->packet_info->source_tip, 0, 
				packet_ctx->packet_info->lor_host_lb_ip, packet_ctx->packet_info->url_id, 
				packet_ctx->packet_info->url_id_type);
		if (encap_with_routinghdr(packet_ctx->ctx, &encap_ethhdr, &encap_iphdr, &encap_routinghdr) != 0) {
			return TC_ACT_SHOT;
		}
		return bpf_redirect(LOCAL_HOST_ETH_INDEX, 0);
	}
	return TC_ACT_SHOT;
}

static int send_nat_nonat_to_different_host(struct packet_host_context *packet_ctx) {
	if (packet_ctx == NULL || packet_ctx->packet_info == NULL || packet_ctx->nat_nonat_host_group == NULL) {
		return TC_ACT_SHOT;
	}
	struct host_packet_context_value *packet_info = packet_ctx->packet_info;
	for (__u8 retry_count = 0; retry_count < 2; ++retry_count) {
		if (get_nat_nonat_host_ip(packet_ctx->nat_nonat_host_group, &packet_info->next_hop_host_ip) >= MAX_NAT_NONAT_HOSTS) {
			return TC_ACT_SHOT;
		}
		packet_info->next_hop_is_local = HOST_IP_IS_LOCAL(packet_info->next_hop_host_ip);
		if (!packet_info->next_hop_is_local) {
			break;
		}
	}
	if (packet_info->next_hop_is_local) { // the function must ensure we pick a different host from ourselves; if we can't do that, shoot the packet
		return TC_ACT_SHOT;
	}
	return handle_non_local_packet(packet_ctx);
}

static void refresh_nonat_connection_map(struct host_packet_context_value *packet_info) {
	if (packet_info == NULL) {
		return;
	}
	update_nonat_connection_map(packet_info);
}

static void refresh_nat_connection_map(struct host_packet_context_value *packet_info) {
	if (packet_info == NULL) {
		return;
	}
	struct nat_source_translation_key nat_source_translation_key = {
		.remote_ip = packet_info->packet_path == EGRESS_PATH ? packet_info->destination_ip : packet_info->source_ip,
		.source_ip = packet_info->source_tip,
		.remote_port = 0,
		.source_port = packet_info->packet_path == EGRESS_PATH ? packet_info->sport : packet_info->dport,
	};
	struct nat_source_translation_value nat_ip_port = {
		.nat_ip = packet_info->nat_nonat_ip,
		.nat_port = packet_info->nat_port,
	};
	bpf_map_update_elem(&nat_source_translations_map, &nat_source_translation_key, &nat_ip_port, BPF_ANY);

	struct nat_connection_key nat_key = {
		.remote_ip = nat_source_translation_key.remote_ip,
		.nat_ip = nat_ip_port.nat_ip,
		.remote_port = 0,
		.nat_port = nat_ip_port.nat_port,
	};
	__u8 next_hop_router = (packet_info->packet_type == PACKET_NAT_EGRESS_WITH_ROUTER ||
			packet_info->packet_type == PACKET_LOR_NAT_EGRESS_WITH_ROUTER ||
			packet_info->packet_type == PACKET_DENAT_INGRESS_WITH_UVM_ROUTER);
	struct nat_connection_value nat_connection_value = {
		.state = {
			.next_hop_host_mac.mac_64     = packet_info->next_hop_host_mac.mac_64,
			.next_hop_host_ip             = packet_info->next_hop_host_ip,
			.next_hop_tip                 = packet_info->next_hop_tip,
			.source_uvm_tip               = packet_info->source_tip,
			.source_uvm_ip                = packet_info->packet_path == EGRESS_PATH ? packet_info->source_ip : packet_info->destination_ip,
			.source_uvm_port              = packet_info->packet_path == EGRESS_PATH ? packet_info->sport : packet_info->dport,
			.url_id_type	  	      = packet_info->url_id_type,
			.url_id			      = packet_info->url_id,
			.next_hop_type                = next_hop_router ? NEXT_HOP_ROUTER : NEXT_HOP_UVM,
			.unused                       = 0,
		},
		.timestamp                          = bpf_ktime_get_ns(),
	};
	bpf_map_update_elem(&nat_connection_map, &nat_key, &nat_connection_value, BPF_ANY);
}

static int convert_to_lb_closing_connection_metadata(struct __sk_buff* ctx,
		struct lb_closing_connection_metadata *lb_closing_connection_metadata) __attribute__((noinline)) {
	if (ctx == NULL || lb_closing_connection_metadata == NULL) {
		return -1;
	}
	if (resize_packet(ctx, MIN_MTU /* TODO: fetch device mtu */, sizeof(struct lb_closing_connection_metadata)) < 0) {
		return -1;
	}
	void *data_end = (void *)(__u64)ctx->data_end;
	void *data = (void *)(__u64)ctx->data;

	if ((data + sizeof(struct lb_closing_connection_metadata)) > data_end) {
		return -1;
	}
	__builtin_memcpy(data, lb_closing_connection_metadata, sizeof(struct lb_closing_connection_metadata));
	return 0;
}

static __u8 close_connection_at_lb_host(struct packet_host_context *packet_ctx, __be32 host_ip, __be32 lb_backed_ip) {
	if (packet_ctx == NULL || packet_ctx->ctx == NULL || packet_ctx->ip_header == NULL || packet_ctx->packet_info == NULL) {
		return -1;
	}

	struct host_packet_context_value *packet_info = packet_ctx->packet_info;
	struct lb_closing_connection_metadata lb_closing_connection_metadata = {
		.lb_backed_ip = packet_info->nat_nonat_ip,
	};

	mac_addr_t host_mac = { .mac_64 = LOCAL_HOST_ETH_MAC };
	mac_addr_t remote_mac = { .mac_64 = get_host_mac(LOCAL_UNDERLAY_GW_IP, LOCAL_HOST_ETH_IP, host_mac), };

	if (convert_to_lb_closing_connection_metadata(packet_ctx->ctx, &lb_closing_connection_metadata) < 0) {
		return -1;
	}

	CREATE_ENCAP_ETH(host_mac.mac, remote_mac.mac);
	CREATE_ENCAP_IP(LOCAL_HOST_ETH_IP, host_ip, IPPROTO_UDP); 
	CREATE_ENCAP_ROUTINGHDR(PACKET_TYPE_HOST_HOST_METADATA, ROUTING_HDR_METADATA_HOST_HOST_LB_CLOSE_CONNECTION, 0, 
			0, packet_ctx->packet_info->lor_host_lb_ip, packet_ctx->packet_info->url_id,
			packet_ctx->packet_info->url_id_type);
	if (encap_with_routinghdr(packet_ctx->ctx, &encap_ethhdr, &encap_iphdr, &encap_routinghdr) != 0) { 
		return -1;
	}

	return 0;
}

static int adjust_tcp_mss(struct __sk_buff *ctx, struct packet_host_context* packet_ctx, __u16 fragment_sz) {
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
	__u16 tcp_checksum_offset = sizeof(struct ethhdr) + IP_SIZE(packet_ctx->ip_header); //(__u8 *)(tcp_header+1) - (__u8 *)(__u64)ctx->data;
	tcp_checksum_offset += offsetof(struct tcphdr, check);
	// Make sure mss is something we can handle after account for encap overheads
	ebpf_printk("old mss %d new mss %d old csum %x", mss_value, fragment_sz, tcp_header->check);
	bpf_l4_csum_replace(ctx, tcp_checksum_offset, bpf_htons(mss_value), bpf_htons(fragment_sz), sizeof(__u16));

	VALIDATE_ETH_PACKET(ctx, packet_ctx->eth_header, return -1);
	VALIDATE_IP_PACKET(ctx, packet_ctx->eth_header, packet_ctx->ip_header, return -1);
	VALIDATE_TCP_PACKET(ctx, packet_ctx->ip_header, tcp_header, return -1);
	ebpf_printk("new csum %x", tcp_header->check);
	return 0;
}
