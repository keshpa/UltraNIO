#ifndef USER_MAPS_H
#define USER_MAPS_H

#define MAX_UVMS 			50000
#define MAX_HOSTS 			100
#define MAX_URLS 			1000
#define MAX_IPS_PER_URL 		5
#define MAX_ROUTERS_IN_PBR_CHAIN	32 + 1
#define LIBBPF_PIN_BY_NAME 		1
#define SBTIP_BROADCAST       		0xFFFF
#define TIP_PEDESTAL			50
#define MAX_LOAD_BALANCER_SERVERS	100
#define MAX_OUTSTANDING_PACKETS		10000		// On a host, let's say we can't have more than these many packets queued
							// up in the eBPF chains, between all UVMs. If there are more packets, we start dropping them.
							// This is an arbitrary number for now and can be bumped up
#define UVM_LOCATION_STRING_MAX		16
#define MAX_PORT_RANGES_PER_KEY 	64
#define MAX_NAT_NONAT_HOSTS		10
#define RESYNC_NAT_NONAT_HOST_INTERVAL  100 		// - after these many packets, we send a metadata packet to all NAT/noNAT hosts asking them
							//   refresh their NAT/noNAT connections maps
#define REPORT_PACKET_CONNECTION_STAT_INTERVAL  100 	// - after these many packets, we report packet connection statistics to user
#define DROP_PRIORITY			255

// Revelant indexes in host_constants_map
#define ADMIN_INDEX     0

struct single_port_range {
	__u16 port_start;
	__u16 port_end;
};

struct port_range {
	__u16 source_port_start;
	__u16 source_port_end;
	__u16 remote_port_start;
	__u16 remote_port_end;
};

enum SPECIAL_PACKET_ID {
	// Packet types used by host ingress for classification
	PACKET_TYPE_GARBAGE = 0,
	PACKET_TYPE_UNDERLAY_RAW = 1,
	PACKET_TYPE_UNDERLAY_BCAST = 2,
	PACKET_TYPE_UNDERLAY_IP = 3,

	PACKET_TYPE_NAT_REPLY_INGRESS = 4,
	PACKET_TYPE_NONAT_REQUEST_REPLY_INGRESS = 5,

	PACKET_TYPE_PUBLIC_LOAD_BALANCER = 6,
	PACKET_TYPE_LOAD_BALANCER_NONAT_REQUEST_REPLY_INGRESS = 7,
	PACKET_TYPE_HOST_HOST_METADATA = 8,

	// Packet types used by host ingress and macvtap for classification
	PACKET_NAT_EGRESS_WITHOUT_ROUTER = 9,
	PACKET_NAT_EGRESS_WITH_ROUTER = 10,
	PACKET_NONAT_EGRESS_WITHOUT_ROUTER = 11,
	PACKET_NONAT_EGRESS_WITH_ROUTER = 12,

	PACKET_LOR_NAT_EGRESS_WITHOUT_ROUTER = 13,
	PACKET_LOR_NAT_EGRESS_WITH_ROUTER = 14,
	PACKET_LOR_NONAT_EGRESS_WITHOUT_ROUTER = 15,
	PACKET_LOR_NONAT_EGRESS_WITH_ROUTER = 16,

	PACKET_DENAT_INGRESS_WITHOUT_UVM_ROUTER = 17,
	PACKET_DENAT_INGRESS_WITH_UVM_ROUTER = 18,
	PACKET_DENONAT_INGRESS_WITHOUT_UVM_ROUTER = 19,
	PACKET_DENONAT_INGRESS_WITH_UVM_ROUTER = 20,

	PACKET_NAT_INGRESS_EW = 21,
	PACKET_NONAT_INGRESS_EW = 22,

	PACKET_MAC_ROUTED_EW = 23,
	PACKET_UVM_BROADCAST_EW = 24,
	PACKET_IP_ROUTED_EW = 25,
};

typedef char mac_t[6];

typedef union mac_addr {
	mac_t mac;
	__u64 mac_64;
} mac_addr_t;

enum MICRO_SEG_DEFAULT_POLICY {
	MICRO_SEG_DEF_ALLOW 	= 0,
	MICRO_SEG_DEF_DENY 	= 1,
};

enum MICRO_SEG_POLICY {
	MICRO_SEG_CONTINUE 	= 0,
	MICRO_SEG_ALLOW 	= 1,
	MICRO_SEG_DENY 		= 2,
};

enum NEXT_HOP_TYPE {
	NEXT_HOP_UVM 			= 0,
	NEXT_HOP_ROUTER 		= 1,
};

struct local_to_tip_key {
	union {
		struct {
			__be64	mac_lookup: 8,
				unused:     8,
				dmac:       48;
		} dmac_info;
		struct {
			__be64	mac_lookup: 8,
				unused:     40,
				vpc_id:     16;
		} dip_info;
	} vpc_or_mac;
	__be32  ip;			// can be destination IP in IP header or subnet broadcast TIP for mac-routed packets
	__be32  padding;
};

struct local_to_tip_value {
	__be32 		host_ip;
	__be32 		designated_router_host_ip;
	__be32		tip;
	__be32 		sb_tip;
	__be32 		designated_router_tip;
	__be32		category: 			6,
			designated_router_enabled:	1,
			location_id:			7,
			pbr_router_enabled:		1,
			unused:				5,
			uvm_lor_router_enabled:		1,
			sb_lor_router_enabled:		1,
			security_group_egress_enabled: 	1,	// - indiciates if ingress microsegmentation for uvm is enabled 
			security_group_egress_policy:	1,	// - value comes from enum MICRO_SEG_DEFAULT_POLICY
			security_group_ingress_enabled:	1,	// - indiciates if ingress security group is enbaled for uvm subnet
			security_group_ingress_policy:	1,	// - value comes from enum MICRO_SEG_DEFAULT_POLICY
			micro_seg_egress_enabled:  	1,  	// - indiciates if egress microsegmentation for uvm is enabled 
			micro_seg_egress_policy:   	1,  	// - value comes from enum MICRO_SEG_DEFAULT_POLICY
			micro_seg_ingress_enabled:  	1,	// - indiciates if egress security group is enbaled for uvm subnet
			micro_seg_ingress_policy:   	1,	// - value comes from enum MICRO_SEG_DEFAULT_POLICY
			vpc_category_policy:   		1,	// - value comes from enum MICRO_SEG_DEFAULT_POLICY
			default_nat:             	1;  	// - 1 if packets outside VPC should be NATed by default; if 0, 
								//   packets are NO-NATed by default
};

enum MICRO_SEG_PROTOCOL {
	MICRO_SEG_UDP = 0x01,
	MICRO_SEG_TCP = 0x02,
	MICRO_SEG_IP = 0x04,
	MICRO_SEG_ICMP = 0x08,
	MICRO_SEG_HTTP = 0x10,
	MICRO_SEG_HTTPS = 0x20,
	MICRO_SEG_NOTA = 0x40,
};

struct qos_key {
	__u32 prefixlen;
	struct {
		__u16   remote_id_lookup:       1,      // - set to 1 if remote_ip_id is the destination IP's URL ID. Else set to 0
							//   and perform lookup using destination IP itself
			unused:                 15;
		__be32  local_tip;
		__be32  remote_ip_id;                   // - the destination IP or the destination IP's URL ID in the packet to route
	} data;
} __attribute__((packed));

struct qos_value {
	__be32  remote_cidr_base_or_remote_id;          // - an IP in destination CIDR or destination IP's URL ID
        __u8    remote_cidr_size;
	__u32   etcd_rule_id;
	__u32 	level;
};

enum MICRO_SEG_NO_NAT_TYPE {
	UDP_EGRESS_MICRO_SEG_LOOKUP = 0x00,
	TCP_EGRESS_MICRO_SEG_LOOKUP = 0x01,
	IP_EGRESS_MICRO_SEG_LOOKUP = 0x02,
	ICMP_EGRESS_MICRO_SEG_LOOKUP = 0x03,
	HTTP_EGRESS_MICRO_SEG_LOOKUP = 0x04,
	HTTPS_EGRESS_MICRO_SEG_LOOKUP = 0x05,
	NOTA_EGRESS_MICRO_SEG_LOOKUP = 0x06,

	UDP_INGRESS_MICRO_SEG_LOOKUP = 0x07,
	TCP_INGRESS_MICRO_SEG_LOOKUP = 0x08,
	IP_INGRESS_MICRO_SEG_LOOKUP = 0x09,
	ICMP_INGRESS_MICRO_SEG_LOOKUP = 0x0a,
	HTTP_INGRESS_MICRO_SEG_LOOKUP = 0x0b,
	HTTPS_INGRESS_MICRO_SEG_LOOKUP = 0x0c,
	NOTA_INGRESS_MICRO_SEG_LOOKUP = 0x0d,

	NAT_NO_NAT_LOOKUP = 0x0e,
};

struct micro_seg_and_no_nat_key {
	__u32 prefixlen;
	struct {
		__u16	remote_id_lookup:	1,	// - set to 1 if remote_ip_id is the destination IP's URL ID. Else set to 0
							//   and perform lookup using destination IP itself
                        unused:			15;
		__u8    lookup_type;			// - value from enum MICRO_SEG_NO_NAT_TYPE
		__u8	increment;			// - NOTE: this cannot be a bit-field as we invoke sizeof(increment) to 
							//   get the maximum value of increment
		__be32  local_tip;
		__be32  remote_ip_id;			// - the destination IP or the destination IP's URL ID in the packet to route
	} data;
} __attribute__((packed));

#define NO_ETCD_RULE_ID 0
struct micro_seg_and_no_nat_value {
	struct single_port_range local_port_ranges[MAX_PORT_RANGES_PER_KEY];
	struct single_port_range remote_port_ranges[MAX_PORT_RANGES_PER_KEY];
	__be32  remote_cidr_base_or_remote_id;		// - an IP in destination CIDR or destination IP's URL ID
        __u8    remote_cidr_size;
	__u32 	etcd_rule_id;				// - maps to an ID in ETCD microseg/security grp map; this eBPF map is an instance of the 
							//   microseg/security grp rule in ETCD. Multiple pbr_router_destination_value may share 
							//   the same ETCD microseg/security grp ID
	__u8 	lookup_type;				// - value from enum MICRO_SEG_NO_NAT_TYPE
	__u8	stateful;
	__u8	action: 	2,			// - value from enum MICRO_SEG_POLICY
		unused:		6;
};

struct category_rules_key {
	__u16	vpc_id;
	__u16 	scategory;
	__u16 	dcategory;
	__u8 	lookup_type;				// - value from enum MICRO_SEG_NO_NAT_TYPE
	__u8	increment;				// - NOTE: this cannot be a bit-field as we invoke sizeof(increment) to 
							//   get the maximum value of increment
};

struct category_rules_value {
	struct single_port_range source_port_ranges[MAX_PORT_RANGES_PER_KEY];
	struct single_port_range destination_port_ranges[MAX_PORT_RANGES_PER_KEY];
};

struct nat_connection_key {
	uint32_t remote_ip;
	uint32_t nat_ip;
	uint16_t remote_port;
	uint16_t nat_port;
};

struct nat_nonat_connection_state {
	mac_addr_t 	next_hop_host_mac;		// - host mac of the source UVM or the source UVM's router or pbr chain / lor router
	uint32_t 	next_hop_host_ip;		// - host IP of the source UVM or the source UVM's router or pbr chain / lor router
	uint32_t 	next_hop_tip;			// - next hop taken when packet re-enters VPC. If source UVM hass router (ex. 
							//   designated/pbr/lor uvm), set to router TIP; else set to source UVM TIP 
	uint32_t 	source_uvm_tip;
	uint32_t	source_uvm_ip;
	uint64_t	source_uvm_port:	16,
			next_hop_type:		1,	// - value from enum NEXT_HOP_TYPE
			url_id_type:		2,	// - value from enum URL_ID_TYPE
			url_id:			32,	// - ID of URL associated with source/destination IP
			unused:			13;
};

struct nat_connection_value {
	struct nat_nonat_connection_state state;
	uint64_t   		timestamp;
	struct bpf_spin_lock 	lock;
}; 

struct nonat_connection_key {
	uint32_t nonat_ip;
	uint32_t remote_ip;
	uint16_t remote_port;				// We keep the [out of VPC] client port so that if a client initiates multiple
							// connections to a noNAT, one directly and another via a LB, we can tease them
							// apart and only change the source IP of packet going to out of VPC client to
							// LB for LB initiated connections.
	uint16_t unused;
};

struct nonat_connection_value {
	struct nat_nonat_connection_state state;
	__be32 load_balancer_ip;			// - the load balancer IP backed by the no-nat IP; used for when a 
							//   outside world pacaket reaches the load balancer IP; set to 0
							//   is there is no load balancer IP programmed
};

struct nat_source_translation_key {
	uint32_t remote_ip;
	uint32_t source_ip;
	uint16_t remote_port;
	uint16_t source_port;
};

struct nat_source_translation_value {
	uint32_t nat_ip;
	uint16_t nat_port;
};

struct sbtip_ifindex_key {
	__be64  sbtip:  32,
		index:  16,
		unused: 16;
};

#define NUM_IFINDICES_PER_KEY 63
struct sbtip_ifindex_entry {
	__u64 ifindex: 16,
	      mac:     48;
};

struct sbtip_ifindex_value {
	struct  sbtip_ifindex_entry ifindices[NUM_IFINDICES_PER_KEY];   // each element stores ifindex of a macvtap in subnet and its mac
	__u16   more;
};

struct tip_value {
	__be32 		uvm_ip;
	__u16 		uvm_ifindex;    // - if the tip is a subnet broadcast tip, uvm_ifindex = SBTIP_BROADCAST,
					//   else, this is the ifindex of uvm macvtap in host
	__u16		uvm_vpc_id;
	mac_addr_t	uvm_mac;        // - the mac of the uvm; this allows for true (consistent) mac learning within uvm subnet
	__be32		host_ip;	// - the IP of the host the UVM resides on
	__be32 		sb_tip;		// - the subnet broadcast tip
};

#define NUM_NAT_IPS		512

struct vpc_nat_entries_key {
	uint16_t vpcid;
};

struct vpc_nat_entry_host {
	uint32_t nat_ip;
};

struct vpc_nat_entries_value {
	struct vpc_nat_entry_host ip_entry[NUM_NAT_IPS];
	uint16_t length;
};

struct host_key {
	__be32 host_ip;
};

struct host_value {
	mac_addr_t host_mac;
};

enum NAT_NONAT_EGRESS_POLICY {
        NAT_NONAT_EGRESS_INVALID = 0,
	NAT_NONAT_EGRESS_ROUND_ROBIN = 1,
	NAT_NONAT_EGRESS_HOST_PERSIST = 2,
};

struct nat_nonat_host_group {
	__be32 host_ips[MAX_NAT_NONAT_HOSTS];
	__u16 host_ips_length;
	__u16 nat_nonat_egress_policy;			// - value from enum NAT_NONAT_EGRESS_POLICY
};

struct nat_nonat_cidr_host_key {
	__u32 prefixlen;
	struct {
		uint32_t nat_nonat_ip;
	} data;
};

struct nat_cidr_host_value {
	struct nat_nonat_host_group host_ips;
};

struct nonat_cidr_host_value {
	struct nat_nonat_host_group host_ips;
	__u16 	vpcid;
};

struct stateful_connections_key {
	uint32_t client_ip;
	uint16_t client_port;
	uint32_t remote_ip;
	uint16_t remote_port;
	uint16_t uvm_vpcid; 				// - this is the VPC id of the uvm that created the stateful connection entry
	uint32_t uvm_ip;
	uint8_t  protocol;
	uint8_t  unused;
};

struct stateful_connections_value {
	__be32 		remote_ip; 			// - true remote IP as it appears in the daddr of egress IP packets
	__be32 		local_tip;			// - STIP of the packet; for non-routers, this the same as TIP of uvm_ip;
							//   for routers, this is the TIP of the source IP in the packet

	__be32 		lb_ip;				// - load balancer IP
	__be32 		lb_backend_ip;			// - the backend IP choosen to server packets meant from lb_ip

	__u64 		timestamp;			// - time the connection entry was last updated
	__u64 		time_established;		// - time the connection entry was first established
	mac_addr_t 	next_hop_host_mac;		// - host mac of destination UVM/router host or host responsible 
							//   for nat/no-nat IP
	__be32 		next_hop_tip;			// - TIP of router or destination UVM
	__be32 		next_hop_host_ip;		// - host ip destination UVM/router host or host responsible 
                                                        //   for nat/no-nat IP

	struct nat_nonat_host_group host_ips;		// - macvtap can choose from any of the hosts in this array for NAT/noNAT packet egress
	__u64		num_pkts;			// - number of packets between client and remote ip
	__u64		xmit_bytes;			// - bytes transmitted from local to remote
	__u64		rmit_bytes;			// - bytes recieved from remote to local
	__be32		nat_ip;

	__be32		tcp_seq_number;

	__be16		remote_port;			// - true remote port after destination "accepts" the TCP connection
	__u8 		packet_type;			// - value from enum SPECIAL_PACKET_ID
	__u8		is_dest_lb_backend: 	1,
			is_next_hop_router:	1,
			is_within_vpc:		1,
			next_hop_evaluated:	1,
			client_fin_ack_done:	1,
			remote_fin_ack_done:	1,
			remote_has_id:		1,
			local_has_id:		1;

	__be32		remote_id;
	__be32		local_id;
};

enum PKT_ACTION_REASON {
	ACTION_REASON_UNAVAILABLE = 0,
	ACTION_REASON_CATEGORY_DENY = 1,
	ACTION_REASON_MICRO_SEG_DENY = 2,
	ACTION_REASON_SECURITY_GROUP_DENY = 3,
	ACTION_REASON_ROUTER_BYPASS = 4,
	ACTION_REASON_CATEGORY_ALLOW = 5,
	ACTION_REASON_MICRO_SEG_ALLOW = 6,
	ACTION_REASON_SECURITY_GROUP_ALLOW = 7,
	ACTION_REASON_NO_RULES = 8,
	ACTION_REASON_CATEGORY_NOACTION = 9,
	ACTION_REASON_MICRO_SEG_NOACTION = 10,
	ACTION_REASON_SECURITY_GROUP_NOACTION = 11,
};

enum PACKET_ACTION {
	PACKET_ACTION_UNKNOWN = 0,
	PACKET_ACTION_DEFAULT_ALLOW = 1,
        PACKET_ACTION_ALLOWED = 2,
        PACKET_ACTION_DROPPED = 3,
	PACKET_ACTION_DEFAULT_DROP = 4,
};

enum PACKET_PATH {
	INGRESS_PATH    = 0,
	EGRESS_PATH     = 1,
};

struct pkt_security_stat_value {
	__u64	timestamp;		// - value from bpf_ktime_get_ns -- nanoseconds since system boottime
	__u64 	rule_evaluation_time;	// - time taken to evaluate rule related to this pkt_stat_log
	__be32  local_uvm_ip;		// - IP of the UVM currently processing the packet
	__u32   etcd_rule_id;		// - Rule id of micro seg/security group/category rule that processed this packet
					//   (set to NO_ETCD_RULE_ID for default rule)
	__be32 	sip;			// - source IP in packet
	__be32 	dip;			// - destination IP in packet
	__be32 	sid;			// - URL ID of the source IP in packet
	__be32 	did;			// - URL ID of the destination IP in packet
	__be16 	sport;			// - source port in the packet
	__be16 	dport;			// - destination port in the packet
	__u8	protocol; 		// - the value will come from enum MICRO_SEG_PROTOCOL
	__u16	packet_protocol;	// - protocol stored in packet (i.e. for ip-packets, this is iphdr->protocol)
	__u8 	action: 	  3,	// - the value vill come from enum PACKET_ACTION
		packet_direction: 1,	// - the value will come from enum PACKET_PATH
		action_reason: 	  4;	// - the value will come from enum PKT_ACTION_REASON
};

struct pkt_connection_stat_value {
	__u64	timestamp;		// - value from bpf_ktime_get_ns -- nanoseconds since system boottime
	__u64	connection_open_time;	// - time when connection was opened (set to 0 for non-IP packets)
	__u64	connection_close_time;	// - time when connection entry was removed (set to 0 for active connections
					//   and non-IP packets)
	__be32  local_uvm_ip;		// - IP of the UVM currently processing the packet
	__be32 	sip;			// - source IP in packet
	__be32 	dip;			// - destination IP in packet
	__be32 	sid;			// - URL ID of the source IP in packet
	__be32 	did;			// - URL ID of the destination IP in packet
	__be16 	sport;			// - source port in the packet
	__be16 	dport;			// - destination port in the packet
	__u8	protocol; 		// - the value will come from enum MICRO_SEG_PROTOCOL
	__u16	packet_protocol;	// - protocol stored in packet (i.e. for ip-packets, this is iphdr->protocol)
	__u64	xmit_bytes;		// - bytes egress by local_uvm_ip in this connection 
	__u64	rmit_bytes;		// - bytes ingress by local_uvm_ip in this connection
};

#define PUBLIC_LOAD_BALANCER_VPC_ID	0xFFFF

struct load_balancer_key {
	__u16  vpc_id;			// - if the load balancer ip is private (i.e. used only by UVMs/containers controlled by eBPF) 
					//   then this is the VPC that configured the load balancer. Otherwise, vpc_id is set to 
					//   PUBLIC_LOAD_BALANCER_VPC_ID
	__be32 load_balancer_ip;	
};

enum LOAD_BALANCER_POLICY {
	LOAD_BALANCER_ROUND_ROBIN,
	LOAD_BALANCER_PERSIST,
	LOAD_BALANCER_LEAST_CONNECTIONS
};

struct load_balancer_server {
	__be32 server_ip;
	__u32  open_connections;
};

struct load_balancer_value {
	struct load_balancer_server server_ips[MAX_LOAD_BALANCER_SERVERS];
	__be32  host_ip;		// - if vpc_id == PUBLIC_LOAD_BALANCER_VPC_ID, the load balancer IP is owned by a host. This is the IP of
					//   that host. If vpc_id != PUBLIC_LOAD_BALANCER_VPC_ID, this field is not read/interpreted and could 
					//   contain any value
	__u8	length;
	__u8	policy;			// - value from enum LOAD_BALANCER_POLICY
};

struct load_balancer_connection_key {
	__be32 load_balancer_ip;	// - public load balancer IP
	__be32 client_ip;		// - IP that sent the first packet to the load_balancer_ip
	__be16 client_port;		// - for UDP, the sport in the packet and for ICMP, the sequence number in the packet. For all other
					//   protocols, this field is set to 0
};

struct load_balancer_connection_value {
	__be32 server_ip;		// - the backend server IP associated with a given load balancer and client IP
	__be16 server_port;		// - for UDP, the backend server port client sent a connection to; for all other protocols, this field is
					//   set to 0
	__u8 policy;			// - value from enum LOAD_BALANCER_POLICY
	uint64_t timestamp;		// - if we reached this backend more than LOAD_BALANCER_BACKEND_PERSIST_TIME, we look for a new lb backend ip
};

enum PACKET_ROUTING_TYPE {
	PACKET_ROUTING_BROADCAST 	= 0,
	PACKET_ROUTING_MAC		= 1,
	PACKET_ROUTING_IP 		= 2,
};

enum NEXT_HOP_ROUTER_TYPE {
	// The final type of the next hop router
	NEXT_HOP_ROUTER_NONE 		= 0,
	NEXT_HOP_ROUTER_UVM 		= 1,
	NEXT_HOP_ROUTER_HOST 		= 2,

	// The potential type of next hop router -- needed to perform map lookup
	// to confirm type and convert the type to NEXT_HOP_ROUTER_NONE/UVM/HOST
	NEXT_HOP_ROUTER_LOR_UVM 	= 3,
	NEXT_HOP_ROUTER_LOR_SUBNET 	= 4,
	NEXT_HOP_ROUTER_LOR_HOST 	= 5,
	NEXT_HOP_ROUTER_DESIGNATED 	= 6,
	NEXT_HOP_ROUTER_PBR_DESTINATION	= 7,
	NEXT_HOP_ROUTER_PBR_SOURCE	= 8,
	NEXT_HOP_ROUTER_DESIGNATED_OR_PBR_DESTINATION 	= 9,
	NEXT_HOP_ROUTER_LOR_UVM_OR_PBR_SOURCE 		= 10,
	NEXT_HOP_ROUTER_LOR_SUBNET_OR_PBR_SOURCE 	= 11,
};

enum UVM_PKT_RELATION_TYPE {
	UVM_PKT_RELATION_UNKNOWN 		= 0,
	UVM_PKT_RELATION_SRC 			= 1,
	UVM_PKT_RELATION_SRC_DESIGNATED 	= 2,
	UVM_PKT_RELATION_DEST_DESIGNATED 	= 3,
	UVM_PKT_RELATION_SRC_INTERNAL_PBR 	= 4,
	UVM_PKT_RELATION_DEST_INTERNAL_PBR 	= 5,
	UVM_PKT_RELATION_SRC_LAST_PBR 		= 6,
	UVM_PKT_RELATION_DEST_LAST_PBR 		= 7,
	UVM_PKT_RELATION_SRC_LOR 		= 8,
	UVM_PKT_RELATION_DEST_LOR 		= 9,
	UVM_PKT_RELATION_DEST			= 10,
};

enum ROUTING_HDR_METADATA_TYPE {
	ROUTING_HDR_METADATA_NO_METADATA				= 0,
	ROUTING_HDR_METADATA_MACVTAP_HOST_NEW_NAT_NONAT_CONNECTION 	= 1, // - macvtap indicates this packet is the first in the new connection and thus,
									     //   host needs to distribute a metadata packet to everyone
	ROUTING_HDR_METADATA_MACVTAP_HOST_REQUEST_NAT_NONAT_REFRESH	= 2, // - macvtap requests a re-distribution of the metadata packet to everyone 
	ROUTING_HDR_METADATA_HOST_HOST_REQUEST_NAT_NONAT_REFRESH	= 3, // - one host request a re-distribution of the metadata packet to everyone 
	ROUTING_HDR_METADATA_HOST_HOST_NAT_NONAT_REFRESH 		= 4, // - this is a metadata packet from one host to others, updating the NAT/noNAT
									     //   connection state
	ROUTING_HDR_METADATA_HOST_HOST_LB_CLOSE_CONNECTION		= 5, // - one noNAT host detects a TCP reset in an egress packet with load balancer
									     //   and sends a metadata packet to load balancer's host to indicate a
									     //   connection closed
	ROUTING_HDR_METADATA_ADMIN_HOST_DNS_REPLY_PROCESSED		= 6, // - indicates that the packet contains a DNS reply packet; further, the packet
									     //   has aleady been processed by the admin-ultra interface present on the same
									     //   host that is currently receiving this packet. The packet is outside-vpc,
									     //   ip-routed, de-NAT/noNAT (i.e. case 2) for such metadata packets
};

struct packet_context_value {
	mac_addr_t      next_hop_host_mac;				// - host mac of destination UVM host or router or host responsible 
									//   for nat/no-nat IP
	mac_addr_t      local_host_mac;					// - mac of local host
	mac_addr_t      local_uvm_mac;					// - mac of local uvm
	__u64		num_pkts;					// - number of packets between client and remote ip
	__u64		xmit_bytes;					// - bytes transmitted from local to remote
	__u64		rmit_bytes;					// - bytes recieved from remote to local
	__u64 		time_connection_established;			// - if the packet is part of an established connection, this sets the 
									//   time the connection was established. Time is reported in nanoseconds 
									//   since boot
	__be32      	next_hop_host_ip;				// - host IP of destination UVM host or router or host responsible 
									//   for nat/no-nat IP
	__be32      	local_host_ip;					// - IP of local host

	__be32          sip;						// - source IP as recorded in the packet
	__be32          stip;						// - TIP of source ip in packet
	__be32          dip;						// - final destination IP as recorded in the packet or 0xFFFFFFFF for
									//   for broadcast packets
	__be32 		dtip;						// - TIP of the final destination IP or INVALID_TIP for broadcast packets
	__be32		nat_ip;						// - if the packet is NATed, the NAT IP we should use when egressing 
	__be32 		lor_host_ip;					// - if the packet will be routed to a LOR host before sending to 
									//   final destination, this will record the IP of the LOR host 

	__be32 		underlay_gw_ip;					// - underlay router IP
	__be32          intermediary_gw_ip;				// - UVM subnet overlay gateway IP (i.e. subnet .1)
	__be32		intermediary_tip;				// - derived from compile time constant LOCAL_UVM_TIP
	__be32		intermediary_ip;				// - derived from compile time constant LOCAL_UVM_IP
	__be32		intermediary_subnet_mask;			// - derived from compile time constant LOCAL_UVM_SUB_MASK

	__be32		src_bcast_tip;
	__be32		dest_bcast_tip;

	__be32		next_hop_ip;					// - for non-loadbalancer case, same as DIP (i.e. destination UVM/outside 
									//   VPC IP) or load-balancer backend IP
	__be32          next_hop_tip;					// - TIP of destination UVM or router 

	__be16          dport;
	__be16          sport;

	__u16		source_category;
	__u16		dest_category;

	__u16		vpcid;
	__u16		src_location;

	__u16		local_uvm_ifindex;
	__u16		local_host_ifindex;
	__u16 		loopback_egress_ifindex;			// - used only for internal testing; packets coming into router's ingress
									//   are redirected to egress of this ifindex

	__u16 		check_dingress_policy:			1,	// - indicates if we should confirm the destination ingress rules
									//   allow our packet before we send it; the check is disabled if
									//   next hop is a router or destination is not within VPC
			is_within_subnet:			1,	// - indicates if the packet's next hop is within the subnet
			is_within_vpc:				1,	// - indicates if the packet's next hop is within the vpc

			is_dest_lb_backend:			1,
			update_dest_ip:				1,

			local_micro_seg_enabled:               	1,
                        local_micro_seg_policy:			1,	// - value from enum MICRO_SEG_DEFAULT_POLICY
			local_default_nat:			1,
			update_l4_csum:				1, 	// - if update_dest_ip == 1, the controls if we should update the
									//   checksums of L4 after updating destination IP

                        local_security_group_enabled:		1,
                        local_security_group_policy:		1,	// - value from enum MICRO_SEG_DEFAULT_POLICY
			send_proxy_arp_reply:			1,	// - if set, we send a proxy arp reply; should NOT be set if VTEP exists
			intermediary_is_router:			1,	// - if set, the UVM is configured as a router; value from compile time 
									//   constant
			create_est_connection:			1,	// - boolean to indicate if we should create a new established connection
									//   entry using this packet info
			allow_rule_stateful:			1,
			vpc_category_policy:			1;	// - value from enum MICRO_SEG_DEFAULT_POLICY

	__u32		tcp_seq_number;					// - initial sequence number in the SYN packet sent during TCP handshake
	__u32		tcp_ack_number;					// - acknowledgement number in the SYN-ACK packet sent during TCP handshake

	__u16		packet_info_in_use:			1,	// - set to 1 if this struct is being used by some eBPF to maintain state;
									//   if set to 0, none is using this so another eBPF is free to re-use this
			dhcp_request:				1,	// - set to 1 if packet is a DHCP request
			source_router_type:			4,	// - value from enum NEXT_HOP_ROUTER_TYPE
			destination_router_type:		4,	// - value from enum NEXT_HOP_ROUTER_TYPE
			source_must_be_nonat:			1,	// - set to true if the source UVM must be part of a NO-NAT subnet, 
									//   otherwise, this packet is invalid and should be dropped
			src_dest_check_enabled:			1,
			uvm_pkt_relation:			4;	// - for egress, value from enum UVM_PKT_RELATION_TYPE

	__u8		remote_ingress_micro_seg_enabled:	1,
                        remote_ingress_micro_seg_policy:	1,	// - value from enum MICRO_SEG_DEFAULT_POLICY
                        remote_ingress_security_group_enabled:	1,
                        remote_ingress_security_group_policy:	1,	// - value from enum MICRO_SEG_DEFAULT_POLICY
                        remote_egress_micro_seg_enabled:	1,
                        remote_egress_micro_seg_policy:		1,	// - value from enum MICRO_SEG_DEFAULT_POLICY
                        remote_egress_security_group_enabled:	1,
                        remote_egress_security_group_policy:	1;	// - value from enum MICRO_SEG_DEFAULT_POLICY
	__u8 		protocol;					// - value from enum MICRO_SEG_PROTOCOL

	__u8		tcp_syn_ack_connection:			1,	// - indicates that a new TCP session is established and the ports for
									//   server has been fixed as well. We can now update the connection map
									//   with the server port 
			tcp_syn_connection:			1,	// - indicates that a TCP handshake was initiated and we just saw the
									//   SYN packet. We can create a connection map for this packet however,
									//   server port is not yet finanlized -- we will need to analzye the
									//   corresponding SYN-ACK packet to identify the server port 
			loopback_packet:			1,	// - used only in ingress for routers; set to true during testing if we 
									//   want to look any ingress packet to egress
			router_packet:				1,	// - used only in ingress; indicates if the packet is only being routed
									//   by us and is not destined for us
			end_tcp_connection:			1,
			reset_tcp_connection:			1,
			is_veth_pair:				1,	// - if set, indicates that the ebpf is attached to one end of a veth pair
									//   this is typically set for container networking
			dest_within_subnet:			1;	// - indicates if the final destination is within the subnet


	__u8		tail_call_return;				// - value returned by the eBPF tail call
	__u8 		packet_type;					// - value from enum SPECIAL_PACKET_ID
	__u8		destination_has_url:			1,	// - set if the destination IP maps to a known URL
			source_has_url:				1,	// - set if the source IP maps to a known URL
			closed_connection:			1,	// - set if we connection map entry for this packet was reaped while
									//   processing this packet
			unused:					5;
	__be32 		destination_id;					// - if the destination IP maps to known URL, this is the ID of the URL
	__be32 		source_id;					// - if the source IP maps to known URL, this is the ID of the URL
	enum ROUTING_HDR_METADATA_TYPE	macvtap_host_metadata;		// - any hints that macvtap needs to send to host are kept here
	struct nat_nonat_host_group host_ips;           		// - macvtap can choose from any of the hosts in this array for NAT/noNAT 
									//   packet egress
};

struct lor_routing_key {
	__u32 prefixlen;
	struct {
		__be32 sb_or_uvm_tip;
		__be16 source_location;
		__be32 destination_cidr;
	} data;
};

struct lor_routing_value {
	__be32 	router_tip;
	__be32 	router_host_ip;
	__be32 	destination_cidr;
	__u8 	destination_cidr_size;
	__u8	is_router_uvm;
};

struct uvm_location_key {
	char string_location[UVM_LOCATION_STRING_MAX];
};

struct uvm_location_value {
	uint16_t location_id;
};

#define NO_URL_ID 0
enum URL_ID_TYPE {
        URL_ID_TYPE_NONE        = 0,
        URL_ID_TYPE_SOURCE      = 1,
        URL_ID_TYPE_DESTINATION = 2,
};
struct url_ip_id_key {
	__be32 uvm_tip;							// - TIP of UVM that performed DNS lookup that returned this IP
	__be32 url_ip;							// - URLs that act as a remote URL for PBR are given a unique ID
									//   -- IDs are unique at the VPC level. All IPs that correspond 
									//   to the URL must use that URL ID to correctly find the PBR 
									//   chain. This field is an IP that may potentially map to a 
									//   URL and thus we want to lookup its URL ID.
};

struct url_ip_id_value {
	__be32  url_id;							// - ID given to the URL that maps to the IP in key
	__u8	qos_url_category_id;					// - ID given the qos category the URL belongs to (ex. 
									//   www.instagram.com belongs to 'social sites' qos category and 
									//   will the ID associated with 'social sites')
	__u8 	uvm_url_counter;					// - A generation count assigned to every URL IP to ID mapping
									//   ownered by a given UVM. This is used to determine and 
									//   prune out older entries from the map.
};

#define FETCH_UVM_LEVEL_PBR 1
#define FETCH_REMOTE_ID 1
#define FETCH_EGRESS_PBR 1

struct pbr_router_source_key {
	__u32 prefixlen;
	struct {
		__u16	vpc_id;
		__u16	uvm_level:	1,
			unused:		15;
		__be32 	source_ip;					// - the source IP in the packet to route
	} data;
};


struct pbr_router_source_value {
	__be32 	source_cidr_base;
	__u16	source_id;
	__u8	source_cidr_size;
};

struct pbr_router_destination_key {
	__u32 prefixlen;
	struct {
		__u16	remote_id_lookup: 	1,			// - set to 1 if remote_ip_id is the destination IP's URL ID. Else set to 0
									//   and perform lookup using destination IP itself
			unused:			15;
		__u16 	source_id;					// - id from pbr_router_source_value
		__be32 	remote_ip_id;					// - the destination IP or the destination IP's URL ID in the packet to route
	} data;
};

struct pbr_router_destination_value {
	__be32 	remote_cidr_base_or_remote_id;				// - an IP in destination CIDR or destination IP's URL ID
	__u8	remote_cidr_size;
	__u8	etcd_source_cidr_size;					// - used only by watcher when programming rules
	__u16 	source_id;						// - id from pbr_router_source_value
	__u32 	etcd_rule_id;						// - maps to an ID in ETCD PBR map; this eBPF map is an instance of the PBR rule in ETCD
									//   Multiple pbr_router_destination_value may share the same ETCD PBR ID
};

struct pbr_router_chain_key {
	__u32 etcd_rule_id;
};

struct pbr_router {
	__be32 ingress_tip;						// - when packet flows from source to destination, the packet will ingress into the router
									//   entity from this TIP's endpoint
	__be32 egress_tip;						// - when packet flows from source to destination, the packet will egress from the router
									//   entity from this TIP's endpoint
	__be32 host_ip;							// - IP of the host where router entity resides. Note that all endpoints (& thus TIPs)
									//   of a given router reside on the same host
};

struct pbr_router_chain_value {
	struct pbr_router routers[MAX_ROUTERS_IN_PBR_CHAIN];
};

struct subnet_secondary_ip_key {
        __be32 sb_tip;
        __be32 secondary_ip;
};

struct subnet_secondary_ip_value {
        __be32 hosted_uvm_tip;
};

struct host_packet_context_value {
        __u8                    packet_path:                    1,      // - value from enum PACKET_PATH
                                packet_type:                    5,      // - value from enum SPECIAL_PACKET_ID
                                next_hop_is_local:              1,      // - set to true if the next hop is on this host; if false, the packet
                                                                        //   must be sent E/W to the correct host
                                is_vxlan_encapped:              1;      // - set to true if the packet came with our vxlan encap; if set,
                                                                        //   we remove the encap before sending the packet to the next hop
        __u16                   class_number:                   4,      // - we have 10 classes
                                packet_info_in_use:             1,	// - set to indicate if a host is using this structure
                                has_lb_ip:                      1,	// - set if the packet source/dest is No-NAT and the connection goes
									//   through a public load balancer
                                tcp_fin:			1,	// - indicates if tcp fin bit is set
                                tcp_rst:			1,	// - indicates if tcp reset bit is set
                                tcp_syn:			1,	// - indicates if tcp syn bit is set 
				tcp_ack:			1,	// - indicates if tcp ack is set
				nat_nonat_host_id:		4,	// - for case 1-3/6-7/9/11-13, if the host is part of a NAT/noNAT host 
									//   group, record the index of host ip in the host_ips array
                                unused:				2;

        __u16                   next_hop_ifindex;                       // - ifindex of destination UVM/router if it resides on this host; its
                                                                        //   0xFFFF for broadcast TIPs
        __be32                  next_hop_tip;                           // - the router or UVM TIP extracted from routinghdr or for class 5
                                                                        //   non-vxlan packet, the destination IP; for class 3/7, this is 0;
                                                                        //   for class 8, this is the UVM TIP corresponding to load balancer
                                                                        //   backend IP
        __be32                  next_hop_ip;                            // - the raw IP associted with next_hop_tip or for class 3/7, the
                                                                        //   destination IP which will be a NAT/NO-NAT IP; for class 8, this
                                                                        //   will be load balancer backend IP
        __be32                  next_hop_host_ip;                       // - the host IP where next_hop_tip resides; for class 3/7, the host
                                                                        //   responsible the NAT/NO-NAT IP in packet destination IP; for class
                                                                        //   1, this is 0
        mac_addr_t              next_hop_host_mac;                      // - the host mac of next_hop_host_ip
        mac_addr_t              next_hop_mac;                           // - the raw MAC associted with next_hop_tip
        __be32                  next_hop_sbtip;                         // - set only for case 5, indicates the subnet broadcast TIP of the next
                                                                        //   hop UVM. Used in conjuction with source UVM's sbtip to identify
                                                                        //   across subnet packets

        __be32                  source_tip;                             // - the source UVM TIP extracted from routinghdr or for class 5
                                                                        //   non-vxlan packet, the source IP; for class 3/7, this is 0
        __be32                  source_ip;                              // - the raw IP associted with source_tip or for class 3/7, the raw source
                                                                        //   IP
        __be32                  destination_ip;                         // - the raw destination IP. For class 5, this will be destition TIP and for class
									//   4, will be 0
        mac_addr_t              source_mac;                             // - the raw MAC associted with source_mac; for class 3/7, this is 0

        __be32                  lor_host_lb_ip;                         // - for class 6, the IP of underlay host to whom we should L2 route the
                                                                        //   packet; for case 1, the lor router we should forward reply packets;
                                                                        //   for case 8, the original destination load balancer IP; for other
                                                                        //   classes, this is 0
        __be32                  nat_nonat_ip;                           // - for class 1/6, the source IP of the inner IP packet; for class 3,
                                                                        //   the destiantion IP of the inner IP; for class 7, the destination IP

        __be16                  sport;
        __be16                  dport;
	__be16			nat_port;
        __u16                   d_vpcid;                                // - VPCID of the destination UVM
        enum MICRO_SEG_PROTOCOL protocol;
	enum ROUTING_HDR_METADATA_TYPE metadata;			// - metadata flag from routing header
	__be32 			url_id;					// - if the source or destination IP of the inner IP packet maps belongs to a
									//   URL, we note the unique ID given to the URL. We store this in url_ip_to_id
									//   map and it will be used to control routing decisions to the URL
	enum URL_ID_TYPE	url_id_type;				// - Indicates if url_id is set and if set, indicates whether the source or 
									//   destination IP belongs to URL. Source and destination IPs cannot both
									//   have a URL ID set; only one of them (or none) can have a URL ID
};

#endif // USER_MAPS_H
