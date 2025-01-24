#ifndef ULTRA_ADMIN_INGRESS_HELPERS

#define ULTRA_ADMIN_INGRESS_HELPERS

struct packet_ultra_admin_context {
	struct ethhdr	 	*eth_header;				// - outermost ethernet header
	struct iphdr	 	*ip_header;				// - outermost ip header
	struct __sk_buff 	*ctx;
};

#endif
