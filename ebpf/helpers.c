#define IP_IN_TIP_SPACE(ip) ((ip & LOCAL_TIP_MASK) == ip) 
#define TIP_OFFSET(tip) bpf_htonl(tip & LOCAL_TIP_OFFSET_MASK)
#define OFFSET_IN_TIP_SPACE(tip_offset) (tip_offset < MAX_UVMS)

#if HOST == 1
#define RETURN_FROM_MAIN(packet_ctx, ret_value) do {											\
	__u8 __ret_val = ret_value;													\
	packet_ctx.packet_info->packet_info_in_use = 0;											\
	bpf_skb_change_tail(packet_ctx.ctx, packet_ctx.ctx->len, 0);									\
	return __ret_val;														\
} while(0)
#else
#define RETURN_FROM_MAIN(packet_info, ret_value) do {											\
	packet_info->packet_info_in_use = 0;												\
	return ret_value;														\
} while(0)
#endif

#define RETURN_SHOT_FROM_MAIN(str, packet_info) do {											\
	ebpf_printk1(-1, str);														\
	RETURN_FROM_MAIN(packet_info, TC_ACT_SHOT);											\
} while(0)

#define RETURN_OK_FROM_MAIN(packet_info) RETURN_FROM_MAIN(packet_info, TC_ACT_OK)
#define SET_LPM_KEY_PREFIXLEN(key) 8*(sizeof(key) - sizeof(key.prefixlen))

static inline __u8 lpm_key_value_match(__be32 key_ip_or_id, __be32 value_ip_or_id, __u8 id_match, __u8 value_cidr_size) {
	if (id_match) {
		return key_ip_or_id == value_ip_or_id;
	} 
	__be32 mask = (value_cidr_size == 0) ? 0 : (0xFFFFFFFF >> (32 - value_cidr_size));
	__be32 input_masked = key_ip_or_id & mask;
	__be32 value_masked = value_ip_or_id & mask;
	return input_masked == value_masked;
}

static struct tip_value* get_tip_value(__be32 tip) {
	if (!IP_IN_TIP_SPACE(tip)) {
		return NULL;
	}
	__be32 tip_offset = TIP_OFFSET(tip);
	if (!OFFSET_IN_TIP_SPACE(tip_offset)) {
		return NULL;
	}
	return bpf_map_lookup_elem(&tip_map, &tip_offset);
}

static __be32 get_uvm_host_ip(__be32 tip) {
	struct tip_value *tip_value = get_tip_value(tip);
	if (tip_value == NULL) {
		return 0;
	}
	return tip_value->host_ip;
}

static int macs_equal(mac_addr_t *mac1, mac_addr_t *mac2) {
	return ! ((mac1->mac_64 & bpf_cpu_to_be64(0xFFFFFFFFFFFF0000)) == (mac2->mac_64 & bpf_cpu_to_be64(0xFFFFFFFFFFFF0000)));
}

static void set_mac(unsigned char *copy_to, const mac_addr_t *copy_from) {
	__builtin_memcpy(copy_to, copy_from->mac, 6);
}

static struct ethhdr* validate_ethernet_packet(const struct __sk_buff *ctx) {
	void *data_end = (void *)(__u64)ctx->data_end;
	void *data = (void *)(__u64)ctx->data;
	struct ethhdr *eth_header;

	// check for ethernet packet
	eth_header = data;
	if ((void *)(eth_header + 1) > data_end) {
		BPF_LOG_BAD_ETH_HEADER_PACKETS("EGR:INFO, Dropping malformed ethernet packet.");
		return NULL;
	}
	return eth_header;
}

static struct host_nat_nonat_metadata* validate_host_nat_nonat_metadata_packet(const struct __sk_buff *ctx) {
	void *data_end = (void *)(__u64)ctx->data_end;
	void *data = (void *)(__u64)ctx->data;
	struct host_nat_nonat_metadata *host_nat_nonat_metadata;

	// check for host_nat_nonat_metadata packet
	host_nat_nonat_metadata = data;
	if ((void *)(host_nat_nonat_metadata + 1) > data_end) {
		return NULL;
	}
	return host_nat_nonat_metadata;
}

static struct lb_closing_connection_metadata* validate_lb_closing_connection_metadata(const struct __sk_buff *ctx) {
	void *data_end = (void *)(__u64)ctx->data_end;
	void *data = (void *)(__u64)ctx->data;
	struct lb_closing_connection_metadata *lb_closing_connection_metadata;

	// check for lb_closing_connection_metadata packet
	lb_closing_connection_metadata = data;
	if ((void *)(lb_closing_connection_metadata + 1) > data_end) {
		return NULL;
	}
	return lb_closing_connection_metadata;
}

static struct arpdata* validate_arp_packet(const struct __sk_buff *ctx, __u32 arp_header_offset, struct arphdr **arp_header) {
	struct arpdata *arp_data = NULL;
	void *data_end = (void *)(__u64)ctx->data_end;
	void *data = (void *)(__u64)ctx->data;
	if ((data + arp_header_offset + sizeof(struct arphdr)) > data_end) {
		BPF_LOG_BAD_ARP_HEADER_PACKETS("INFO, Packet too small for ARP header");
		return NULL;
	}
	*arp_header = (struct arphdr *)((void*)(__u64)ctx->data + arp_header_offset);
	if (bpf_ntohs((*arp_header)->ar_hrd) != ARPHRD_ETHER || (*arp_header)->ar_hln != ETH_ALEN ||
			(*arp_header)->ar_pro != bpf_htons(ETH_P_IP) || (*arp_header)->ar_pln != 4) {
		// Make sure the arp packet passes sanity checks
		BPF_LOG_BAD_ARP_HEADER_PACKETS("INFO, ARP headers are insane");
		return NULL;
	}
	arp_data = (struct arpdata *)((*arp_header) + 1);
	if ((void*)(arp_data + 1) <= data_end) {
		return arp_data;
	}
	BPF_LOG_BAD_ARP_HEADER_PACKETS("INFO, Packet too small for ARP data");
	return NULL;
}

static struct iphdr* validate_ip_packet(const struct __sk_buff *ctx, struct ethhdr *eth) {
	if (ctx == NULL || eth == NULL) {
		return NULL;
	}
	void *data_end = (void *)(__u64)ctx->data_end;
	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		return NULL;
	}

	struct iphdr *ip_header = (struct iphdr *)(eth + 1);

	if ((void*)(ip_header + 1) > data_end) {
		BPF_LOG_BAD_IP_HEADER_PACKETS("EGR: INFO, Dropping malformed ip packet.");
		return NULL;
	}
	return ip_header;
}

static struct udphdr* validate_udp_packet(const struct __sk_buff *ctx, struct iphdr* ip) {
	void *data_end = (void *)(__u64)ctx->data_end;
	if (ip->protocol != IPPROTO_UDP) {
		return NULL;
	}

	struct udphdr *udp_header = (struct udphdr *)(ip->ihl*4 + (__u8 *)ip);

	if ((void*)(udp_header + 1) > data_end) {
		return NULL;
	}
	return udp_header;
}

static struct vxlanhdr* validate_vxlan_packet(const struct __sk_buff *ctx, struct udphdr* udp) {
	void *data_end = (void *)(__u64)ctx->data_end;
	if (udp->dest != bpf_htons(IANA_VXLAN_UDP_PORT)) {
		return NULL;
	}

	struct vxlanhdr *vxlan_header = (struct vxlanhdr *)(udp + 1);

	if ((void*)(vxlan_header + 1) > data_end) {
		return NULL;
	}
	if (vxlan_header->vx_flags != bpf_htonl(1 << 27)) {
		return NULL;
	}
	if (vxlan_header->vx_vni != bpf_htonl(ENCAP_VNI_ID << 8)) {
		return NULL;
	}
	return vxlan_header;
}

static struct dhcphdr* validate_dhcp_packet(const struct __sk_buff *ctx, struct udphdr* udp) {
	void *data_end = (void *)(__u64)ctx->data_end;
	if (udp->source != DHCP_CLIENT_PORT && udp->source != DHCP_SERVER_PORT) {
		return NULL;
	} else if (udp->dest != DHCP_CLIENT_PORT && udp->dest != DHCP_SERVER_PORT) {
		return NULL;
	}

	struct dhcphdr *dhcp_header = (struct dhcphdr *)(udp + 1);

	if ((void*)(dhcp_header + 1) > data_end) {
		return NULL;
	}
	return dhcp_header;
}


static struct routinghdr* validate_routing_packet(const struct __sk_buff *ctx, struct vxlanhdr* vxlan) {
	void *data_end = (void *)(__u64)ctx->data_end;

	struct routinghdr *routing_header = (struct routinghdr *)(vxlan + 1);

	if ((void*)(routing_header + 1) > data_end) {
		return NULL;
	}
	return routing_header;
}

static struct tcphdr* validate_tcp_packet(const struct __sk_buff *ctx, struct iphdr* ip) {
	void *data_end = (void *)(__u64)ctx->data_end;
	if (ip->protocol != IPPROTO_TCP) {
		return NULL;
	}

	struct tcphdr *tcp_header = (struct tcphdr *)(ip->ihl*4 + (__u8 *)ip);

	if ((void*)(tcp_header + 1) > data_end) {
		return NULL;
	}
	return tcp_header;
}

static inline struct icmphdr* validate_icmp_packet(const struct __sk_buff *ctx, struct iphdr* ip) {
	void *data_end = (void *)(__u64)ctx->data_end;
	if (ip->protocol != IPPROTO_ICMP) {
		return NULL;
	}

	struct icmphdr *icmp_header = (struct icmphdr *)(ip->ihl*4 + (__u8 *)ip);

	if ((void*)(icmp_header + 1) > data_end) {
		return NULL;
	}
	return icmp_header;
}

static inline __u32 load_word_overriden(unsigned char *buffer, __u32 offset) {
	return *(__u32*)(buffer + offset);
}

static inline __u16 load_half_overriden(unsigned char *buffer, __u32 offset) {
	return *(__u16*)(buffer + offset);
}

static __u16 recalculate_ip_checksum(unsigned char *ip_header) {
	// Calculate one's complement sum of IP header except checksum word at
	// offset 10.
	__u64 checksum = 0;
	checksum += load_half_overriden(ip_header, 0);
	checksum += load_word_overriden(ip_header, 2);
	checksum += load_word_overriden(ip_header, 6);
	checksum += load_word_overriden(ip_header, 12);
	checksum += load_word_overriden(ip_header, 16);

	checksum = (checksum & 0xffff) + (checksum >> 16);
	checksum = (checksum & 0xffff) + (checksum >> 16);
	checksum = (checksum & 0xffff) + (checksum >> 16);

	return ~checksum;
}

static long update_ip_checksum(struct __sk_buff *ctx, int ip_header_offset, __be32 original_ip, 
		__be32 new_ip, __u16 ip_header_size, __u16 l4_type) {
	if (ctx == NULL) {
		return -1;
	}
	if (original_ip == new_ip) {
		return 0;
	}
	if (bpf_l3_csum_replace(ctx, ip_header_offset + offsetof(struct iphdr, check), original_ip, 
				new_ip, sizeof(__be32)) != 0) {
		return -1;
	} else if (l4_type != (__u16)-1) {
		return bpf_l4_csum_replace(ctx, ip_header_offset + ip_header_size + l4_type, 
				original_ip, new_ip, sizeof(__be32));
	}
	return 0;
}

static __u16 get_ip_l4_checksum_offset(enum MICRO_SEG_PROTOCOL protocol) {
	if (protocol == MICRO_SEG_TCP || protocol == MICRO_SEG_HTTP || protocol == MICRO_SEG_HTTPS) {
		return offsetof(struct tcphdr, check);
	} else if (protocol == MICRO_SEG_UDP) {
		return offsetof(struct udphdr, check);
	}
	return -1;
}

static long update_ip_saddr(struct __sk_buff *ctx, struct iphdr *ip_header, __be32 new_saddr, 
		int ip_header_offset, __u16 l4_type) {
	if (ctx == NULL) {
		return -1;
	}
	__be32 original_sip = ip_header->saddr;
	ip_header->saddr = new_saddr;
	return update_ip_checksum(ctx, ip_header_offset, original_sip, new_saddr, 
			IP_SIZE(ip_header), l4_type);
}

static long update_ip_daddr(struct __sk_buff *ctx, struct iphdr *ip_header, __be32 new_daddr, 
		int ip_header_offset, __u16 l4_type) {
	if (ctx == NULL) {
		return -1;
	}
	__be32 original_dip = ip_header->daddr;
	ip_header->daddr = new_daddr;
	return update_ip_checksum(ctx, ip_header_offset, original_dip, new_daddr,
			IP_SIZE(ip_header), l4_type);
}

static long update_ip_addrs(struct __sk_buff *ctx, struct packet_context *packet_ctx, __be32 new_saddr, 
		__be32 new_daddr, int ip_header_offset) {
	if (packet_ctx == NULL || ctx == NULL || packet_ctx->ip_header == NULL || 
			packet_ctx->packet_info == NULL) {
		return -1;
	}

	__u16 l4_type = (packet_ctx->packet_info->update_l4_csum == 1) ? 
		get_ip_l4_checksum_offset(packet_ctx->packet_info->protocol) : -1;

	__be32 original_sip = packet_ctx->ip_header->saddr;
	__be32 original_dip = packet_ctx->ip_header->daddr;
	packet_ctx->ip_header->saddr = new_saddr; 
	packet_ctx->ip_header->daddr = new_daddr; 
	__u8 ip_header_size = IP_SIZE(packet_ctx->ip_header);
	if (update_ip_checksum(ctx, ip_header_offset, original_sip, new_saddr, ip_header_size,
				l4_type) != 0) {
		return -1;
	} else if (update_ip_checksum(ctx, ip_header_offset, original_dip, new_daddr, ip_header_size,
				l4_type) != 0) {
		return -1;
	}
	return 0;
}

static enum MICRO_SEG_PROTOCOL get_packet_coarse_protocol(struct iphdr* ip_header) {
	switch (ip_header->protocol) {
		case IPPROTO_ICMP:
			return MICRO_SEG_ICMP;
		case IPPROTO_UDP:
			return MICRO_SEG_UDP;
		case IPPROTO_TCP:
			return MICRO_SEG_TCP;
		default:
			return MICRO_SEG_IP;
	}
}

#define REDIRECT_PKT(ifindex, is_ingress) bpf_redirect(ifindex, is_ingress ? BPF_F_INGRESS : BPF_F_EGRESS)
#define REDIRECT_PKT_EGRESS(ifindex) bpf_redirect(ifindex, BPF_F_EGRESS)
#define REDIRECT_PKT_INGRESS(ifindex) bpf_redirect(ifindex, BPF_F_INGRESS)

static int encap_with_eth_ip(struct __sk_buff *ctx, struct ethhdr *encap_ethhdr, struct iphdr *encap_iphdr) {
	if (ctx == NULL || encap_ethhdr == NULL || encap_iphdr == NULL) {
		return -1;
	}

	int packet_extend_ret =	0;
	if ((packet_extend_ret = bpf_skb_change_head(ctx, sizeof(struct ethhdr) + sizeof(struct iphdr), 0)) != 0) {
		BPF_LOG_BAD_ENCAP("ERR, encap with eth&ip\n");
		return -1;
	}

	void* data = (void*)(__u64)ctx->data;
	void* data_end = (void*)(__u64)ctx->data_end;
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
		return -1;
	}
	__builtin_memcpy(data, encap_ethhdr, sizeof(struct ethhdr));
	__builtin_memcpy(data + sizeof(struct ethhdr), encap_iphdr, sizeof(struct iphdr));


	return 0;
}

static int encap_with_routinghdr(struct __sk_buff *ctx, struct ethhdr *encap_ethhdr, struct iphdr *encap_iphdr, 
		struct routinghdr *encap_routinghdr) __attribute__((always_inline)) {
	if (ctx == NULL || encap_ethhdr == NULL || encap_iphdr == NULL || encap_routinghdr == NULL) {
		return -1;
	}

	int packet_extend_ret =	0;
	__u16 encap_header_size = ENCAP_HDR_SZ;
	__u16 original_len = ctx->len;
	encap_iphdr->tot_len = bpf_htons(original_len + encap_header_size - sizeof(struct ethhdr));
	encap_iphdr->check = recalculate_ip_checksum((unsigned char*)encap_iphdr);
	if ((packet_extend_ret = bpf_skb_change_head(ctx, encap_header_size, 0)) != 0) {
		return -1;
	}

	void* data = (void*)(__u64)ctx->data;
	void* data_end = (void*)(__u64)ctx->data_end;
	if (data + encap_header_size > data_end) {
		return -1;
	}
	__builtin_memcpy(data, encap_ethhdr, sizeof(struct ethhdr));
	data += sizeof(struct ethhdr);

	__builtin_memcpy(data, encap_iphdr, sizeof(struct iphdr));
	data += sizeof(struct iphdr);

	struct udphdr encap_udphdr = {
		.source = bpf_htons(IANA_VXLAN_UDP_PORT),
		.dest = bpf_htons(IANA_VXLAN_UDP_PORT),
		.len = bpf_htons(original_len + encap_header_size - sizeof(struct ethhdr) - sizeof(struct iphdr)),
		.check = 0,
	};
	__builtin_memcpy(data, &encap_udphdr, sizeof(struct udphdr));
	data += sizeof(struct udphdr);

	struct vxlanhdr encap_vxlanhdr = {
		.vx_flags = bpf_htonl(1 << 27), // denotes the vx vni is valid
		.vx_vni = bpf_htonl(ENCAP_VNI_ID << 8),
	};
	__builtin_memcpy(data, &encap_vxlanhdr, sizeof(struct vxlanhdr));
	data += sizeof(struct vxlanhdr);

	__builtin_memcpy(data, encap_routinghdr, sizeof(struct routinghdr));
	data += sizeof(struct routinghdr);

	return 0;
}

static __u32 hash_u16(__u16 num_to_hash, __u32 starting_hash) {
	starting_hash = (starting_hash << 5) + starting_hash + (num_to_hash >> 8);
	starting_hash = (starting_hash << 5) + starting_hash + ((num_to_hash & 0x00FF));
	return starting_hash;
}

static __u32 hash_u32(__u32 num_to_hash, __u32 starting_hash) {
	starting_hash = (starting_hash << 5) + starting_hash + (num_to_hash >> 24);
	starting_hash = (starting_hash << 5) + starting_hash + ((num_to_hash & 0x00FF0000) >> 16);
	starting_hash = (starting_hash << 5) + starting_hash + ((num_to_hash & 0x0000FF00) >> 8);
	starting_hash = (starting_hash << 5) + starting_hash + ((num_to_hash & 0x000000FF));
	return starting_hash;
}

static __u32 hash_src_ip_port_dest_ip(__be32 saddr, __be16 sport, __be32 daddr) {
	__u32 hash = hash_u32(saddr, 256);
	hash = hash_u16(daddr, hash);
	return hash_u32(daddr, hash);
}

static int is_timestamp_expired(__u64 timestamp, __u64 current_time) {
	return current_time > MAX_TIMESTAMP_LIFE + timestamp;
}

static __be64 get_host_mac(__be32 search_ip, __be32 local_host_ip, mac_addr_t local_host_mac) {
	ibpf_printk1(-1, "lookup mac of %pI4, local ip %pI4 local mac %llx", &search_ip, &local_host_ip, local_host_mac.mac_64);
	if (local_host_ip == search_ip) {
		return local_host_mac.mac_64;
	}
	struct host_value *host_mac_value = bpf_map_lookup_elem(&host_map, &search_ip);
	if (host_mac_value == NULL || host_mac_value->host_mac.mac_64 == 0UL) {
		ibpf_printk1(-1, "mac not found");
		return 0UL;
	}
	return host_mac_value->host_mac.mac_64;
}

static __be64 get_l2_aware_host_mac(__be32 lookup_host_ip, __be32 caller_host_ip, mac_addr_t caller_host_mac, __be32 l2_cidr, 
		__be64 underlay_router_ip, __u8 *send_to_router) {
	__be32 lookup_cidr = (lookup_host_ip & l2_cidr);
	__be32 caller_cidr = (caller_host_ip & l2_cidr);
	if (lookup_cidr != caller_cidr) {
		if (send_to_router != NULL) { *send_to_router = 1; }
		return get_host_mac(underlay_router_ip, caller_host_ip, caller_host_mac);
	}
	if (send_to_router != NULL) { *send_to_router = 0; }
	return get_host_mac(lookup_host_ip, caller_host_ip, caller_host_mac);
}

static struct local_to_tip_value* get_local_information_impl(const __u16 vpcid, const mac_addr_t* mac, 
		__be32 ip_or_subnet_ip, __u8 is_mac_lookup) {
	if (is_mac_lookup == 1 && mac == NULL) {
		return NULL;
	}

	struct local_to_tip_key key = {0};
	key.ip = ip_or_subnet_ip;
	key.vpc_or_mac.dmac_info.mac_lookup = is_mac_lookup;
	if (is_mac_lookup) {
		key.vpc_or_mac.dmac_info.dmac = mac->mac_64;
	} else {
		key.vpc_or_mac.dip_info.vpc_id = vpcid;
	}
	return bpf_map_lookup_elem(&local_to_tip_map, &key);
}

static struct local_to_tip_value* get_local_information(const __u16 vpcid, 
		const mac_addr_t* mac, __be32 ip, __be32 subnet_ip) {
	struct local_to_tip_value* tip_value = get_local_information_impl(vpcid, mac, subnet_ip, 1);
	if (tip_value != NULL) {
		return tip_value;
	}
	return get_local_information_impl(vpcid, NULL, ip, 0);
}

static __u8 get_nat_nonat_host_ip(struct nat_nonat_host_group *host_ips, __be32 *host_ip) __attribute__((noinline)) {
	if (host_ips == NULL || host_ip == NULL) {
		return MAX_NAT_NONAT_HOSTS;
	}
	__u32 index = bpf_get_prandom_u32() % host_ips->host_ips_length;
	if (index >= MAX_NAT_NONAT_HOSTS || index < 0) {
		ibpf_printk1(-1, "invalid index %d 1\n", index);
		return MAX_NAT_NONAT_HOSTS;
	}
	__be32 *host_ips_ptr = host_ips->host_ips + index;
	if (host_ips_ptr < host_ips->host_ips || host_ips_ptr >= (host_ips->host_ips + MAX_NAT_NONAT_HOSTS)) {
		ibpf_printk1(-1, "invalid index %d 2\n", index);
		return MAX_NAT_NONAT_HOSTS;
	}
	*host_ip = *host_ips_ptr;
	ibpf_printk1(-1, "got host ip %pI4\n", host_ip);
	return index;
}

static struct nat_nonat_host_group* get_nat_nonat_host_group(__be32 nat_nonat_ip, __u8 is_nat, __u16 *vpcid) {
	struct nat_nonat_host_group *host_ips = NULL;
	struct nat_nonat_cidr_host_key key = {
		.prefixlen = 8*(sizeof(key) - sizeof(key.prefixlen)),
		.data = { .nat_nonat_ip = nat_nonat_ip },
	};
	if (is_nat) {
		struct nat_cidr_host_value *value = bpf_map_lookup_elem(&nat_cidr_host_map, &key);
		if (value == NULL) {
			return NULL;
		}
		host_ips = &value->host_ips;
	} else {
		struct nonat_cidr_host_value *value = bpf_map_lookup_elem(&nonat_cidr_host_map, &key);
		if (value == NULL) {
			return NULL;
		}
		if (vpcid) {
			*vpcid = value->vpcid;
		}
		host_ips = &value->host_ips;
	}
	return host_ips;
}

static __u8 get_preferred_nat_nonat_host(struct nat_nonat_host_group *host_ips, __be32 preferred_host_ip, __be32 *host_ip) __attribute__((noinline)) {
	if (host_ips == NULL || host_ip == NULL) {
		return MAX_NAT_NONAT_HOSTS;
	}
	for (__u32 index = 0; index < MAX_NAT_NONAT_HOSTS; ++index) {
		if (host_ips->host_ips[index] == preferred_host_ip) {
			*host_ip = preferred_host_ip;
			return index;
		}
	}
	if (get_nat_nonat_host_ip(host_ips, host_ip) >= MAX_NAT_NONAT_HOSTS) {
		return MAX_NAT_NONAT_HOSTS;
	}
	return 0;
}

struct find_port_ranges_intersection_context {
	struct port_range *ranges;
	__u16 sport;
	__u16 rport;
};
static long find_port_ranges_intersection_impl(__u32 index, struct find_port_ranges_intersection_context *context) {
	if (context == NULL || index >= MAX_PORT_RANGES_PER_KEY) {
		return 1;
	}
	struct port_range range = context->ranges[index];
	if (range.source_port_start > context->sport || range.source_port_end < context->sport) {
		return 0;
	}
	if (range.remote_port_start > context->rport || range.remote_port_end < context->rport) {
		return 0;
	}
	return 1;
}
static __u8 find_port_ranges_intersection(struct port_range *ranges, __u16 sport, __u16 rport) {
	struct find_port_ranges_intersection_context context = {
		.ranges = ranges,
		.sport = sport,
		.rport = rport
	};
	if (bpf_loop(MAX_PORT_RANGES_PER_KEY + 1, find_port_ranges_intersection_impl, &context, 0) <= MAX_PORT_RANGES_PER_KEY) {
		return 1;
	}
	return 0;
}

struct find_single_port_ranges_intersection_context {
	struct single_port_range *ranges;
	__u16 port;
	__u8 found_match;
};
static long find_single_port_ranges_intersection_impl(__u32 index, struct find_single_port_ranges_intersection_context *context) {
	if (context == NULL || index >= MAX_PORT_RANGES_PER_KEY) {
		return 1;
	}
	struct single_port_range range = context->ranges[index];
	if (range.port_start == 0 && range.port_end == 0) {
		return 1;
	}
	if (range.port_start > context->port || range.port_end < context->port) {
		return 0;
	}
	context->found_match = 1;
	return 1;
}
static __u8 find_single_port_ranges_intersection(struct single_port_range *ranges, __be16 port) {
	struct find_single_port_ranges_intersection_context context = {
		.ranges = ranges,
		.port = bpf_ntohs(port),
		.found_match = 0,
	};
	bpf_loop(MAX_PORT_RANGES_PER_KEY + 1, find_single_port_ranges_intersection_impl, &context, 0);
	if (context.found_match) {
		return 1;
	}
	return 0;
}

static int ttl_decr_and_report_okay(struct __sk_buff *ctx, struct iphdr *ip_header, __u32 ip_header_offset) __attribute__((noinline)) {
	if (ip_header == NULL) {
		return 0;
	}
	if (ip_header->ttl <= 0) {
		return -1;
	}
	__u16 old_ttl_protocol = 0;
	__builtin_memcpy(&old_ttl_protocol, &ip_header->ttl, 2);
	--ip_header->ttl;
	__u16 new_ttl_protocol = 0;
	__builtin_memcpy(&new_ttl_protocol, &ip_header->ttl, 2);
	return bpf_l3_csum_replace(ctx, ip_header_offset + offsetof(struct iphdr, check), old_ttl_protocol, new_ttl_protocol, 
			sizeof(__u16));
}

static inline int resize_packet(struct __sk_buff* ctx, __u32 mtu, __u32 requested_pkt_size) {
	if (ctx == NULL) {
		return -1;
	}
	__u32 pkt_size = ctx->len;
	__u32 needed_size = MIN_PACKET_SIZE > requested_pkt_size ? MIN_PACKET_SIZE : requested_pkt_size;

	ebpf_printk1(-1, "resz pkt mtu %d pkt sz %d", mtu, pkt_size);
	if (requested_pkt_size <= MIN_PACKET_SIZE && requested_pkt_size <= pkt_size && pkt_size <= mtu) {
		return 0;
	}

	if (pkt_size != needed_size) {
		ebpf_printk1(-1, "resz pkt try: %d->%d", pkt_size, needed_size);
		int ret = bpf_skb_change_tail(ctx, needed_size, 0);
		if (ret < 0) {
			ebpf_printk1(-1, "resz pkt fail: %d->%d", pkt_size, needed_size);
			return -1;
		}
		ebpf_printk1(-1, "resz pkt success: %d->%d", pkt_size, needed_size);
		ebpf_printk1(-1, "new ctx len: %d", ctx->len);
	}
	void *data_end = (void *)(__u64)ctx->data_end;
	void *data = (void *)(__u64)ctx->data;
	if ((data + needed_size) > data_end) {
		return -1;
	}
	return 0;
}

static int convert_to_arp_request(struct __sk_buff* ctx, __u32 mtu, __be32 arp_ip, __be32 source_ip, 
		mac_addr_t source_mac) __attribute__((noinline)) {
	if (ctx == NULL) {
		return -1;
	}
	__u32 needed_size = sizeof(struct ethhdr) + sizeof(struct arphdr) + sizeof(struct arpdata);
	if (resize_packet(ctx, mtu, needed_size) < 0) {
		return -1;
	}

	struct ethhdr *eth_header = NULL;
	VALIDATE_ETH_PACKET(ctx, eth_header, return -1);

	mac_addr_t broadcast_mac = { .mac_64 = 0xFFFFFFFFFFFFFFFF };
	__builtin_memcpy(eth_header->h_dest, broadcast_mac.mac, ETH_ALEN);
	set_mac(eth_header->h_source, &source_mac);
	eth_header->h_proto = bpf_htons(ETH_P_ARP);

	void *data_end = (void *)(__u64)ctx->data_end;
	void *data = (void *)(__u64)ctx->data;

	if ((data + needed_size) > data_end) {
		ebpf_printk1(-1, "data sz check fail 1\n");
		return -1;
	}

	struct arphdr *arp_hdr = (struct arphdr*)(eth_header + 1);
	if ((void*)(arp_hdr + 1) >= data_end) {
		ebpf_printk1(-1, "data sz check fail 2\n");
		return -1;
	}
	arp_hdr->ar_hrd = bpf_htons(ARPHRD_ETHER);
	arp_hdr->ar_hln = ETH_ALEN;
	arp_hdr->ar_pro = bpf_htons(ETH_P_IP);
	arp_hdr->ar_pln = 4;
	arp_hdr->ar_op = bpf_htons(ARPOP_REQUEST);

	struct arpdata *arp_data = (struct arpdata*)(arp_hdr + 1);
	__builtin_memcpy(arp_data->ar_sha, source_mac.mac, ETH_ALEN);
	__builtin_memcpy(arp_data->ar_dha, broadcast_mac.mac, ETH_ALEN);

	__builtin_memcpy(arp_data->ar_sip, &source_ip, 4);
	__builtin_memcpy(arp_data->ar_dip, &arp_ip, 4);

	return 0;
}

static int arp_for_host(struct __sk_buff* ctx, __be32 arp_ip, __be32 source_ip,
		mac_addr_t source_mac, __u32 host_ifindex, __u8 clone_redirect) __attribute__((noinline)) {
	ebpf_printk1(-1, "ARP %pI4\n", &arp_ip);
	__u32 mtu_len = 0;
	int ret = bpf_check_mtu(ctx, host_ifindex, &mtu_len, 0, BPF_MTU_CHK_SEGS);
	if (ret != 0 && mtu_len == 0) {
		ebpf_printk1(-1, "no mtu-arp");
		return TC_ACT_SHOT;
	}

	if (convert_to_arp_request(ctx, mtu_len, arp_ip, source_ip, source_mac) != 0) {
		ebpf_printk1(-1, "ARP failed\n");
		return TC_ACT_SHOT;
	}
	return clone_redirect ? bpf_clone_redirect(ctx, host_ifindex, BPF_F_EGRESS) : REDIRECT_PKT_EGRESS(host_ifindex);
}

static struct load_balancer_value* get_public_load_balancer_info(__be32 candidate_lb_ip) __attribute__((noinline)) {
	// get the list of server ips frontended by load balancer
	struct load_balancer_key lb_key = {0};
	lb_key.vpc_id = PUBLIC_LOAD_BALANCER_VPC_ID;
	lb_key.load_balancer_ip = candidate_lb_ip;
	return bpf_map_lookup_elem(&load_balancer_map, &lb_key);
}

struct get_least_connection_lb_server_ctx {
	struct load_balancer_value* load_balancer_info;
	__u32 server_index;
	__u32 min_open_connections;

};
static __u32 get_least_connection_lb_server(__u32 index, struct get_least_connection_lb_server_ctx *ctx) {
	if (index < 0 || index >= MAX_LOAD_BALANCER_SERVERS || ctx == NULL) {
		return 1;
	}
	struct load_balancer_value* load_balancer_info = ctx->load_balancer_info;
	if (index >= load_balancer_info->length) {
		return 1;
	}
	__u32 open_connections = load_balancer_info->server_ips[index].open_connections;
	if (ctx->min_open_connections == -1 || ctx->min_open_connections > open_connections) {
		ctx->min_open_connections = open_connections;
		ctx->server_index = index;
	}
	return 0;
}

static __u32 get_lb_backed_ip_index(struct load_balancer_value *load_balancer_info, __be32 lb_backed_ip) __attribute__((noinline)) {
	if (load_balancer_info == NULL) {
		return MAX_LOAD_BALANCER_SERVERS;
	}
	__u32 length = load_balancer_info->length;
	if (load_balancer_info->length > MAX_LOAD_BALANCER_SERVERS) {
		length = MAX_LOAD_BALANCER_SERVERS;
	}
	for (__u32 i = 0; i <= length; ++i) {
		if (load_balancer_info->server_ips[i].server_ip == lb_backed_ip) {
			return i;
		}
	}
	return MAX_LOAD_BALANCER_SERVERS;	
}

static __u8 assign_backend_load_balancer(struct load_balancer_value* load_balancer_info, __be32 sip, __be32 *server_ip_ret) __attribute__((noinline)) {
	if (load_balancer_info == NULL || server_ip_ret == NULL) {
		return -1;
	}

	// randomly pick a server ip to use for this connection. We will store this server ip in our connection map
	// so that future packets from the same source port will be sent to the same server ip
	volatile __be32 server_index = 0;
	if (load_balancer_info->policy == LOAD_BALANCER_ROUND_ROBIN) {
		server_index = bpf_get_prandom_u32() % load_balancer_info->length;
	} else if (load_balancer_info->policy == LOAD_BALANCER_LEAST_CONNECTIONS) {
		struct get_least_connection_lb_server_ctx ctx = {
			.load_balancer_info = load_balancer_info,
			.server_index = 0,
			.min_open_connections = -1
		};
		bpf_loop(MAX_LOAD_BALANCER_SERVERS, &get_least_connection_lb_server, &ctx, 0);
		server_index = ctx.server_index;
	} else {
		server_index = hash_src_ip_port_dest_ip(sip, 0, 0) % load_balancer_info->length;
	}

	if (server_index >= MAX_LOAD_BALANCER_SERVERS || server_index < 0) {
		return -1;
	}
	struct load_balancer_server *server_info = load_balancer_info->server_ips + server_index;
	if (server_info >= (load_balancer_info->server_ips + MAX_LOAD_BALANCER_SERVERS)) {
		return -1;
	}
	if (load_balancer_info->policy == LOAD_BALANCER_LEAST_CONNECTIONS) {
		__sync_fetch_and_add(&server_info->open_connections, 1);
	}
	*server_ip_ret = server_info->server_ip;
	return 0;
}

static void close_load_balancer_connection(struct load_balancer_value *load_balancer_info, __be32 lb_backed_ip)  __attribute__((noinline)) {
	if (load_balancer_info == NULL || load_balancer_info->policy != LOAD_BALANCER_LEAST_CONNECTIONS) {
		return;
	}
	__u32 server_index = get_lb_backed_ip_index(load_balancer_info, lb_backed_ip);
	if (server_index >= MAX_LOAD_BALANCER_SERVERS || server_index < 0) {
		return;
	}
	volatile struct load_balancer_server *server_info = load_balancer_info->server_ips + server_index;
	if (server_info >= (load_balancer_info->server_ips + MAX_LOAD_BALANCER_SERVERS)) {
		return;
	}
	if (server_info->open_connections == 0) {
		ibpf_printk1(-1, "ERROR: open connections on %pI4 (index %d) is 0\n", &server_info->server_ip, server_index);
		return;
	}
	__sync_fetch_and_sub(&(server_info->open_connections), 1);
	return;
}

struct fragment_pkt_context {
	struct __sk_buff *ctx;
	__u32 fragment_l4_payload_sz;
	__u16 ifindex;
	__u16 remaining_l4_payload_sz;
	__u16 l4_header_size;
};

static int fragment_pkt_impl(__u32 index, struct fragment_pkt_context *context) __attribute__((noinline)) {
	if (context == NULL || context->ctx == NULL) {
		return 1;
	}
	struct __sk_buff *ctx = context->ctx;
	struct ethhdr *eth_header = NULL;
	struct iphdr *ip_header = NULL;
	VALIDATE_ETH_PACKET(ctx, eth_header, return 1);
	VALIDATE_IP_PACKET(ctx, eth_header, ip_header, return 1);
	__u32 ip_header_offset = sizeof(struct ethhdr);
	__u32 ip_header_size = ip_header->ihl*4;
	__u32 l4_header_offset = ip_header_offset + ip_header_size;
	__u8 last_fragment = 0;


	// Determine the new size of the L4 payload
	__u16 new_l4_payload = context->fragment_l4_payload_sz;
	if (context->remaining_l4_payload_sz == 0) {
		return 1;
	} else if (context->remaining_l4_payload_sz < context->fragment_l4_payload_sz) {
		last_fragment = 1;
		new_l4_payload = context->remaining_l4_payload_sz;
	}
	context->remaining_l4_payload_sz -= new_l4_payload;

	// Determine the new size of the ip packet
	__be16 old_ip_tot_len = ip_header->tot_len;
	__u16 new_ip_tot_len = new_l4_payload + context->l4_header_size + ip_header_size;
	ip_header->tot_len = bpf_htons(new_ip_tot_len);

	if (ip_header->protocol == IPPROTO_UDP) {
		// Save the udp header so we can copy it to the fragment
		struct udphdr udp_header;
		bpf_skb_load_bytes(ctx, l4_header_offset, &udp_header, sizeof(struct udphdr));
		// Shrink the packet from L3 header such that ip payload is new_ip_tot_len
		if (index > 0) {
			__s32 shrink_len = context->fragment_l4_payload_sz;
			int ret = bpf_skb_adjust_room(ctx, -shrink_len, BPF_ADJ_ROOM_NET, 0);
			if (ret != 0) {
				return 1;
			}
		}
		// Update udp header length, checksum, aand then copy the header back into the fragment
		udp_header.len = bpf_htons(new_l4_payload);
		udp_header.check = 0;
		bpf_skb_store_bytes(ctx, l4_header_offset, &udp_header, sizeof(struct udphdr), 0);

		VALIDATE_ETH_PACKET(ctx, eth_header, return 1);
		VALIDATE_IP_PACKET(ctx, eth_header, ip_header, return 1);
	}

	// Increment IP fragment offset for non-TCp packets and IP ID for TCP packets
	__u16 org_frag_off = ip_header->frag_off;
	__u16 frag_off = bpf_ntohs(ip_header->frag_off) >> 3;
	frag_off += context->fragment_l4_payload_sz + ip_header_size;
	frag_off = frag_off << 3;
	if (!last_fragment) {
		frag_off |= 0x4;
	} else {
		frag_off &= ~0x0007;
	}
	ip_header->frag_off = bpf_htons(frag_off);
	if (bpf_l3_csum_replace(ctx, ip_header_offset + offsetof(struct iphdr, check), 
				org_frag_off, ip_header->frag_off, sizeof(__u16)) != 0) {
		return 1;
	}

	ip_header_offset = sizeof(struct ethhdr);
	// Update ip length related checksum
	if (bpf_l3_csum_replace(ctx, ip_header_offset + offsetof(struct iphdr, check), 
				old_ip_tot_len, bpf_htons(new_ip_tot_len), sizeof(__u16)) != 0) {
		return 1;
	}
	bpf_clone_redirect(ctx, context->ifindex, 0);
	return last_fragment ? 1 : 0;
}

#define MAX_FRAGMENTS 10
static __u8 fragment_pkt(struct __sk_buff *ctx, __u16 fragment_sz, __u16 ifindex, 
		mac_addr_t *smac) __attribute__((always_inline)) {
	if (ctx == NULL || smac == NULL) {
		return 0;
	}

	struct ethhdr *eth_header = NULL;
	struct iphdr *ip_header = NULL;
	VALIDATE_ETH_PACKET(ctx, eth_header, return 0);
	VALIDATE_IP_PACKET(ctx, eth_header, ip_header, return 0);
	__u16 l3_header_sz = ip_header->ihl*4;
	__u16 fragment_ip_payload_sz = fragment_sz - l3_header_sz;

	if (bpf_ntohs(ip_header->frag_off) & 0x4) { 
		// Don't fragment bit is set in IP, so we should not fragment the packet
		return -1;
	} else if (bpf_ntohs(ip_header->tot_len) > fragment_ip_payload_sz*MAX_FRAGMENTS) {
		return -1;
	} else if (ip_header->protocol == IPPROTO_TCP) {
		// We don't support fragmenting TCP packets as we cannot compute its checksum
		ebpf_printk1(-1, "no tcp frag suppot");
		return -1;
	}

	set_mac(eth_header->h_source, smac);
	set_mac(eth_header->h_dest, smac);

	struct fragment_pkt_context context = {
		.ctx = ctx,
		.fragment_l4_payload_sz = 0,
		.ifindex = ifindex,
		.remaining_l4_payload_sz = 0,
		.l4_header_size = 0,
	};
	if (ip_header->protocol == IPPROTO_UDP) {
		context.l4_header_size = sizeof(struct udphdr);
	}
	context.remaining_l4_payload_sz = bpf_ntohs(ip_header->tot_len) - context.l4_header_size - l3_header_sz;
	context.fragment_l4_payload_sz = fragment_ip_payload_sz - context.l4_header_size;
	bpf_loop(MAX_FRAGMENTS, fragment_pkt_impl, &context, 0);
	return 0;
}

static __u8 get_ip_url_id(__be32 uvm_tip, __u16 vpc_id, __be32 url_ip, __be32 *url_id, __u8 lru_lookup) __attribute__((noinline)) {
	if (url_id == NULL) {
		return false;
	}
	struct url_ip_id_key key = {
		.uvm_tip = uvm_tip,
		.url_ip = url_ip,
	};
	struct url_ip_id_value *value = NULL;
	if (lru_lookup) {
		value = bpf_map_lookup_elem(&lru_url_ip_id_map, &key);
	} else {
		value = bpf_map_lookup_elem(&url_ip_id_map, &key);
	}
	if (value == NULL) {
		return false;
	}
	*url_id = value->url_id;
	return true;
}

static __u16 admin_interface_index() {
	__u32 admin_index = ADMIN_INDEX;
	__u32 *admin_ifindex_index = bpf_map_lookup_elem(&host_constants_map, &admin_index);
	if (admin_ifindex_index != NULL) {
		return (__u16)(*admin_ifindex_index);
	} else {
		return 1;
	}
}

static struct pbr_router_source_value* get_pbr_router_source(__be32 source_ip, __be32 vpc_id, __u8 uvm_level_lookup) __attribute__((noinline)) {
	struct pbr_router_source_key key = {
		.prefixlen = SET_LPM_KEY_PREFIXLEN(key),
		.data = {
			.vpc_id = vpc_id,
			.uvm_level = uvm_level_lookup,
			.unused = 0,
			.source_ip = source_ip,
		},
	};
	struct pbr_router_source_value *value = bpf_map_lookup_elem(&pbr_router_source_map, &key);
	if (value == NULL || !lpm_key_value_match(source_ip, value->source_cidr_base, !FETCH_REMOTE_ID, value->source_cidr_size)) {
		return NULL;
	}
	return value;
}

static struct pbr_router_destination_value* get_pbr_router_destination(__be32 remote_ip_id, __u16 source_id, 
		__u8 remote_id_lookup) __attribute__((noinline)) {
	struct pbr_router_destination_key key = {
		.prefixlen = SET_LPM_KEY_PREFIXLEN(key),
		.data = {
			.remote_id_lookup = remote_id_lookup,
			.unused = 0,
			.source_id = source_id,
			.remote_ip_id = remote_ip_id,
		},
	};
	struct pbr_router_destination_value *value = bpf_map_lookup_elem(&pbr_router_destination_map, &key);
	if (value == NULL || value->source_id != source_id ||
			!lpm_key_value_match(remote_ip_id, value->remote_cidr_base_or_remote_id, remote_id_lookup, 
				value->remote_cidr_size)) {
		return NULL;
	}
	return value;
}

static struct pbr_router_chain_value* get_pbr_router_chain(__be32 source_ip, __be32 vpc_id, __be32 remote_ip_id, 
		__u8 remote_id_lookup) __attribute__((noinline)) {
	struct pbr_router_destination_value* destination_value = NULL;
	struct pbr_router_source_value* source_value = get_pbr_router_source(source_ip, vpc_id, FETCH_UVM_LEVEL_PBR);
	if (source_value != NULL) {
		destination_value = get_pbr_router_destination(remote_ip_id, source_value->source_id, remote_id_lookup);
	}

	if (source_value == NULL || destination_value == NULL) {
		source_value = get_pbr_router_source(source_ip, vpc_id, !FETCH_UVM_LEVEL_PBR);
		if (source_value == NULL) {
			return NULL;
		}
		destination_value = get_pbr_router_destination(remote_ip_id, source_value->source_id, remote_id_lookup);
	}

	if (destination_value == NULL) {
		return NULL;
	}

	struct pbr_router_chain_key key = {
		.etcd_rule_id = destination_value->etcd_rule_id,
	};
	return bpf_map_lookup_elem(&pbr_router_chain_map, &key);
}

static inline __u8 pbr_chain_ended(struct pbr_router* router) {
	return !router || (router->ingress_tip == PBR_CHAIN_END_ENTRY_TIP && router->egress_tip == PBR_CHAIN_END_ENTRY_TIP);
}

struct get_last_pbr_router_ctx {
	struct pbr_router_chain_value* pbr_chain;
	struct pbr_router* router;
};
static long get_last_pbr_router_impl(__u32 i, struct get_last_pbr_router_ctx* ctx) {
	if (ctx == NULL || ctx->pbr_chain == NULL || i >= MAX_ROUTERS_IN_PBR_CHAIN) {
		return 1;
	}
	if (pbr_chain_ended(&ctx->pbr_chain->routers[i])) {
		ctx->router = &ctx->pbr_chain->routers[i];
		return 1;
	}
	return 0;
}
static struct pbr_router* get_last_pbr_router(__be32 source_ip, __be32 vpc_id, __be32 remote_ip_id, 
		__u8 remote_id_lookup) __attribute__((noinline)) {
	struct pbr_router_chain_value* pbr_chain = get_pbr_router_chain(source_ip, vpc_id, remote_ip_id, remote_id_lookup);
	if (pbr_chain == NULL || pbr_chain_ended(&pbr_chain->routers[0])) {
		return NULL;
	}
	struct get_last_pbr_router_ctx ctx = {
		.pbr_chain = pbr_chain,
		.router = NULL,
	};
	bpf_loop(MAX_ROUTERS_IN_PBR_CHAIN, get_last_pbr_router_impl, &ctx, 0);
	return ctx.router;
}

static inline __u8 covert_arp_request_to_reply(struct ethhdr* eth_header, struct arphdr *arp_header, struct arpdata* arp_data, mac_addr_t source_mac) {
	if (eth_header == NULL || arp_data == NULL) {
		return -1;
	}
	__builtin_memcpy(eth_header->h_dest, eth_header->h_source, 6);
        __builtin_memcpy(eth_header->h_source, source_mac.mac, 6);

	__be32 dest_ip;
        __builtin_memcpy(&dest_ip, arp_data->ar_dip, sizeof(__be32));

        arp_header->ar_op = bpf_htons(ARPOP_REPLY);
        __builtin_memcpy(arp_data->ar_dha, arp_data->ar_sha, 6);
        __builtin_memcpy(arp_data->ar_dip, arp_data->ar_sip, 4);

        __builtin_memcpy(arp_data->ar_sha, source_mac.mac, 6);
        __builtin_memcpy(arp_data->ar_sip, &dest_ip, 4);
	return 0;
}
