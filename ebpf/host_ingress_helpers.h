#ifndef HOST_INGRESS_HELPERS

#define HOST_INGRESS_HELPERS

enum PACKET_ENCAPPED {
	ENCAPPED = 0,
	NOT_ENCAPPED,
};

enum HOST_TYPE {
	LOCAL_HOST = 0,
	REMOTE_HOST,
};

enum INNER_PACKET_TYPE {
	SOURCE_UVM_ENCAPPED = 0,
	NOT_SOURCE_UVM_ENCAPPED,
};

struct packet_host_context {
	struct ethhdr	 	*eth_header;				// - outermost ethernet header
	struct iphdr	 	*ip_header;				// - outermost ip header
	struct iphdr		*inner_ip_header;			// - if the packet was vxlan encapped by us (class 1-4, one case of 
									//   class 5, class 6), the ip header after the vxlan encap
	struct __sk_buff 	*ctx;
	struct load_balancer_value *load_balancer_info;			// - if packet destination is load balancer IP, this field is set to the
	struct nat_nonat_host_group *nat_nonat_host_group;
	struct host_packet_context_value *packet_info;			// - pointer to value from host_packet_context_map; used to store packet
									//   metadata
};

struct try_nat_ip_port_reuse_context { 
	struct nat_connection_value 		*source_value;
	struct nat_source_translation_key 	*source_dest_to_nat;
	__u16 					port_index;
	__u32 					daddr;
	__u8 					zero_nat_port;
	__be32 					nat_ip;

	__be16 					*nat_port;
	__u8 					found_nat;
};

struct set_l4_ports_context {
	struct iphdr *ip_header;
	__be16 sport;
	__be16 dport;
	enum PACKET_PATH packet_path;
	enum MICRO_SEG_PROTOCOL protocol;
	__be32 addr;
};

#endif
