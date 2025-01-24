#ifndef HELPERS_H
#define HELPERS_H
#include "user_maps.h"

/* Misc helper macros. */
#define __section(x) __attribute__((section(x), used))
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

/* Object pinning settings */
#define PIN_NONE       0
#define PIN_OBJECT_NS  1
#define PIN_GLOBAL_NS  2

/* ELF map definition */
struct bpf_elf_map {
	__u32 type;
	__u32 size_key;
	__u32 size_value;
	__u32 max_elem;
	__u32 flags;
	__u32 id;
	__u32 pinning;
	__u32 inner_id;
	__u32 inner_idx;
};

/* Some used BPF intrinsics. */
unsigned long long load_byte(void *skb, unsigned long long off)
	asm ("llvm.bpf.load.byte");
unsigned long long load_half(void *skb, unsigned long long off)
	asm ("llvm.bpf.load.half");
unsigned long long load_word(void *skb, unsigned long long off)
	asm ("llvm.bpf.load.word");


struct bpf_map;

#define BROADCAST_IP 0xFFFFFFFF

#define ETH_P_IP 0x0800

#define NAT_EXPIRATION_THRESHOLD (350 * 1000 * 1000 * 1000UL)
#define STARTING_NAT_PORT 1024

#define REPORT_MALFORMED_ETHERNET_PACKETS  		1
#define REPORT_FAILED_ARP_ENCAP_PACKETS  		1
#define REPORT_MALFORMED_ARP_PACKETS  			1
#define REPORT_FAILURE_TO_WRITE_SKB  			1
#define REPORT_FAILURE_TO_REDIRECT_SKB  		1
#define REPORT_MALFORMED_IP_PACKETS 			1

#define LOAD_BALANCER_BACKEND_PERSIST_TIME	(30 * 1000 * 1000 * 1000UL)

#define BPF_LOG_BAD_ETH_HEADER_PACKETS(string, ...)     \
{                                                       \
	if (REPORT_MALFORMED_ETHERNET_PACKETS) {        \
		bpf_printk(string, ##__VA_ARGS__);      \
	}                                               \
}

#define BPF_LOG_BAD_ENCAP(string, ...)                  \
{                                                       \
	if (REPORT_FAILED_ARP_ENCAP_PACKETS) {          \
		bpf_printk(string, ##__VA_ARGS__);      \
	}                                               \
}

#define BPF_LOG_BAD_ARP_HEADER_PACKETS(string, ...)     \
{                                                       \
	if (REPORT_MALFORMED_ARP_PACKETS) {             \
		bpf_printk(string, ##__VA_ARGS__);      \
	}                                               \
}

#define BPF_LOG_BAD_WRITE_TO_SKB(string, ...)           \
{                                                       \
	if (REPORT_FAILURE_TO_WRITE_SKB) {              \
		bpf_printk(string, ##__VA_ARGS__);      \
	}                                               \
}

#define BPF_LOG_REDIRECT_PACKET_FAILED(string, ...)     \
{                                                       \
	if (REPORT_FAILURE_TO_REDIRECT_SKB) {           \
		bpf_printk(string, ##__VA_ARGS__);      \
	}                                               \
}

#define BPF_LOG_BAD_IP_HEADER_PACKETS(string, ...)     	\
{                                                       \
	if (REPORT_MALFORMED_IP_PACKETS) {        	\
		bpf_printk(string, ##__VA_ARGS__);      \
	}                                               \
}

struct arpdata {
	__u8 ar_sha[ETH_ALEN];
	__u8 ar_sip[4];
	__u8 ar_dha[ETH_ALEN];
	__u8 ar_dip[4];
};

// Define the DNS header structure
struct dnshdr {
	__u16 id;        // Transaction ID (2 bytes)

	// Flags (2 bytes)
#if defined(__LITTLE_ENDIAN_BITFIELD)
		__u16	rcode : 4,   // Response Code (4 bits)
			z : 3,       // Reserved (3 bits, should be 0)
			ra : 1,      // Recursion Available (1 bit)
			rd : 1,      // Recursion Desired (1 bit)
			tc : 1,      // Truncated (1 bit)
			aa : 1,      // Authoritative Answer (1 bit)
			opcode : 4,  // Operation Code (4 bits)
			qr : 1;      // Query/Response flag (1 bit)
#elif defined (__BIG_ENDIAN_BITFIELD)
		__u16	qr : 1,      // Query/Response flag (1 bit)
			opcode : 4,  // Operation Code (4 bits)
			aa : 1,      // Authoritative Answer (1 bit)
			tc : 1,      // Truncated (1 bit)
			rd : 1,      // Recursion Desired (1 bit)
			ra : 1,      // Recursion Available (1 bit)
			z : 3,       // Reserved (3 bits, should be 0)
			rcode : 4;   // Response Code (4 bits)
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__u16 qdcount;    // Number of questions (2 bytes)
	__u16 ancount;    // Number of answer records (2 bytes)
	__u16 nscount;    // Number of authority records (2 bytes)
	__u16 arcount;    // Number of additional records (2 bytes)
};

enum DHCP_PACKET_TYPE {
	DHCP_DISCOVER = 1,
	DHCP_OFFER = 2,
	DHCP_REQUEST = 1,
	DHCP_REPLY = 2,
};

struct dhcp_lease_time_option {
	__u8 	type;
	__u8	length;
	__u16	duration[2];
};

struct dhcp_router_ip_option {
	__u8 	type;
	__u8	length;
	__u16	router_ip[2];
};

struct dhcp_subnet_mask_option {
	__u8 	type;
	__u8	length;
	__u16	subnet_mask[2];
};

struct dhcp_options_end {
	__u8    type;
	__u8	length;
};

#define DHCP_SERVER_NAME	"Ultra-NIO DHCP Server"
#define DHCP_CLIENT_PORT	bpf_htons(68)
#define DHCP_SERVER_PORT	bpf_htons(67)

struct dhcphdr {
	__u8	op_code;		//  Always set to 1 (BOOTP_REQUEST)
	__u8	htype;			//  Hardware type (e.g., Ethernet = 1)
	__u8	hlen;			//  Length of MAC address
	__u8	hops;			//  Number of hops
	__u32	tx_id;			//  Unique transaction identifier 
	__u16	secs;			//  Seconds since client started looking for server 
	__u16	flags;			//  Flags (e.g., broadcast flag) 
	__u32	client_ip;		//  Client's IP address (usually 0.0.0.0) 
	__u32	your_ip;		//  Server's IP address (usually 0.0.0.0) 
	__u32	server_ip;		//  Relay agent IP address (if used) 
	__u32	gateway_ip;		//  Relay agent IP address (if used) 
	__u8	chaddr[16];		//  Client's MAC address 
	__u8	sname[64];		//  Set to "Ultra NIO server"
	__u8	file[128];		//  Boot file and path
    
	//  DHCP Options
	union {
		uint8_t  options[64];	//  Array to hold variable-length options 
		struct {
			__u32 dhcp_magic;
			struct dhcp_lease_time_option lease_option;
			struct dhcp_router_ip_option router_ip_option;
			struct dhcp_subnet_mask_option subnet_mask_option;
			struct dhcp_options_end end_marker;
		} offer_options;
	};
};

struct packet_context {
	struct ethhdr *eth_header;
	struct iphdr *ip_header;
	struct packet_context_value *packet_info;
};

#define IANA_VXLAN_UDP_PORT     4789
struct vxlanhdr {
	__be32 vx_flags;
	__be32 vx_vni;
};

struct routinghdr {
	__u8 	case_number;				// - value from enum SPECIAL_PACKET_ID
	__u8 	metadata;				// - macvtap to host or host to host metadata
	__u16 	url_id_type: 	2,
		unused:		14;			
	__be32	uvm_tip;				// - TIP of ther source UVM who sent the packet
	__be32	next_hop_tip;				// - TIP of the UVM who should receive the packet
							//   on the packet's reverse journey (ex. if 
							//   packet goes from UVM->router UVM->google,
							//   UVM will record its TIP here when sending
							//   packet to the router UVM & the router UVM 
							//   will record its TIP here before it sends 
							//   the packet for NAT/noNAT to google)
	__be32 	lor_host_lb_ip;				// - if the packet should be sent to a LOR host,
							//   this records the LOR host's (underlay) IP.
							//   If the packet is/was meant for a load
							//   balancer (LB), record the LB's IP here.
	__be32  url_id;					// - if the destination IP in the packet belongs
							//   to a URL, record the ID of the URL here. This
							//   will be used to program the lru_url_ip_id_map
};

enum GET_ROUTER_RETURN {
	GET_ROUTER_ERROR = -1,
	GET_ROUTER_FOUND = 0,
	GET_ROUTER_NO_ROUTER = 1,
	GET_ROUTER_PBR_END = 2,
};
struct pbr_router_destination_info {
	struct pbr_router_destination_key dest_key;
	struct pbr_router_destination_value *dest_value;
	__u16 sport;
	__u16 dport;

	__u8 sport_matched;
	__u8 dport_matched;

	__u16 ifindex;
};

struct host_nat_nonat_metadata {
        __be32 nat_nonat_ip;
        __be32 destination_ip;
        __be32 source_ip;
        __be16 nat_port;
        __be16 destination_port;
        __be16 source_port;
        __be16 unused;
};

struct lb_closing_connection_metadata {
	__be32 lb_backed_ip;
};

#define BPF_F_EGRESS 0
#endif
