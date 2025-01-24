#ifndef MAPS_H
#define MAPS_H

#include "user_maps.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct host_key);
	__type(value, struct host_value);
	__uint(max_entries, MAX_HOSTS);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} host_map __section(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct local_to_tip_key);
	__type(value, struct local_to_tip_value);
	__uint(max_entries, MAX_UVMS);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} local_to_tip_map __section(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct micro_seg_and_no_nat_key);
	__type(value, struct micro_seg_and_no_nat_value);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 10000000);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} micro_seg_and_no_nat_map __section(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct qos_key);
	__type(value, struct qos_value);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 10000000);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} qos_map __section(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct pbr_router_destination_key);
	__type(value, struct pbr_router_destination_value);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, MAX_UVMS);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} pbr_router_destination_map __section(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct pbr_router_source_key);
	__type(value, struct pbr_router_source_value);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, MAX_UVMS);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} pbr_router_source_map __section(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct pbr_router_chain_key);
	__type(value, struct pbr_router_chain_value);
	__uint(max_entries, MAX_UVMS);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} pbr_router_chain_map __section(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lor_routing_key);
	__type(value, struct lor_routing_value);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, MAX_UVMS);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} lor_routing_map __section(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct nat_connection_key);
	__type(value, struct nat_connection_value);
	__uint(max_entries, MAX_UVMS);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} nat_connection_map __section(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct nat_source_translation_key);
	__type(value, struct nat_source_translation_value);
	__uint(max_entries, MAX_UVMS);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} nat_source_translations_map __section(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct sbtip_ifindex_key);
	__type(value, struct sbtip_ifindex_value);
	__uint(max_entries, MAX_UVMS);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} sbtip_ifindex_map __section(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct vpc_nat_entries_key);
	__type(value, struct vpc_nat_entries_value);
	__uint(max_entries, MAX_UVMS);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} vpc_nat_entries_map __section(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);                     // key: transit ip 
	__type(value, struct tip_value);
	__uint(max_entries, MAX_UVMS);  // this limits the total number of ips across all VPCs
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} tip_map __section(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct nat_nonat_cidr_host_key);
	__type(value, struct nat_cidr_host_value);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, MAX_UVMS);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} nat_cidr_host_map __section(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct nonat_connection_key);
	__type(value, struct nonat_connection_value);
	__uint(max_entries, MAX_UVMS);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} nonat_connection_map __section(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct stateful_connections_key);
	__type(value, struct stateful_connections_value);
	__uint(max_entries, MAX_UVMS);  // this is the total number of NAT ips that we will support accross all VPCs
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} stateful_connections_map __section(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct nat_nonat_cidr_host_key);
	__type(value, struct nonat_cidr_host_value);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, MAX_UVMS); 
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} nonat_cidr_host_map __section(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	// value will be pkt_security_stat_value
	__uint(max_entries, MAX_UVMS); 
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} pkt_security_stat_map __section(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	// value will be pkt_connection_stat_value
	__uint(max_entries, MAX_UVMS); 
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} pkt_connection_stat_map __section(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct category_rules_key);
	__type(value, struct category_rules_value);
	__uint(max_entries, MAX_UVMS); 
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} category_rules_map __section(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct load_balancer_key);
	__type(value, struct load_balancer_value);
	__uint(max_entries, MAX_UVMS);  // can't have more load balancers than UVMs
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} load_balancer_map __section(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __type(key, struct load_balancer_connection_key);
        __type(value, struct load_balancer_connection_value);
        __uint(max_entries, MAX_UVMS);  // can't have more load balancer connections than UVMs
        __uint(pinning, LIBBPF_PIN_BY_NAME);
} load_balancer_connection_map __section(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct uvm_location_key);
	__type(value, struct uvm_location_value);
	__uint(max_entries, MAX_UVMS);  // can't have more locations than UVMs
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} uvm_location_map __section(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct packet_context_value);
	__uint(max_entries, MAX_OUTSTANDING_PACKETS);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} packet_context_map __section(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} packet_ids_map __section(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct host_packet_context_value);
	__uint(max_entries, MAX_OUTSTANDING_PACKETS);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} host_packet_context_map __section(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} host_packet_ids_map __section(".maps");

enum ETAIL_CALL_ENTRY {
	PARSE_MVTAP_EPROCESS = 0,
	PARSE_MVTAP_ESEND = 1,
};

enum ITAIL_CALL_ENTRY {
	PARSE_MVTAP_IPROCESS = 0,
	PARSE_MVTAP_ISEND = 1,
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct subnet_secondary_ip_key);
	__type(value, struct subnet_secondary_ip_value);
	__uint(max_entries, MAX_UVMS);  
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} subnet_secondary_ip_map __section(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 5);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} host_constants_map __section(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct url_ip_id_key);
	__type(value, struct url_ip_id_value);
	__uint(max_entries, MAX_URLS*MAX_IPS_PER_URL);  
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} lru_url_ip_id_map __section(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct url_ip_id_key);
	__type(value, struct url_ip_id_value);
	__uint(max_entries, MAX_URLS*MAX_IPS_PER_URL);  
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} url_ip_id_map __section(".maps");

#endif
