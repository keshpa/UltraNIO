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

enum RULE_EVALUATION_ACTION {
        RULE_EVALUATION_ACTION_NO_ACTION,
        RULE_EVALUATION_ACTION_ALLOW,
        RULE_EVALUATION_ACTION_DENY,
        RULE_EVALUATION_ACTION_DENY_DEFAULT
};

enum RULE_TYPE {
        RULE_TYPE_NO_RULES,
        RULE_TYPE_MICRO_SEG,
        RULE_TYPE_CATEGORY,
        RULE_TYPE_SECURITY_GROUP,
        RULE_TYPE_ROUTER_BYPASS
};

struct security_action_reason {
        enum RULE_EVALUATION_ACTION action;
        __u32 etcd_rule_id;
};

static char rule_evaluation_action_to_char(enum RULE_EVALUATION_ACTION action) {
	switch (action) {
		case RULE_EVALUATION_ACTION_DENY_DEFAULT:
		case RULE_EVALUATION_ACTION_DENY:
			return 'D';
		case RULE_EVALUATION_ACTION_ALLOW:
			return 'A';
		default:
			return 'N';
	}
}

static enum PACKET_ACTION rule_evaluation_action_to_pkt_action(enum RULE_EVALUATION_ACTION action) {
	if (action == RULE_EVALUATION_ACTION_DENY) {
		return PACKET_ACTION_DROPPED;
	} else if (action == RULE_EVALUATION_ACTION_NO_ACTION) {
		return PACKET_ACTION_DEFAULT_ALLOW;
	} else if (action == RULE_EVALUATION_ACTION_DENY_DEFAULT) {
		return PACKET_ACTION_DEFAULT_DROP;
	} else {
		return PACKET_ACTION_ALLOWED;
	}
}

static enum PKT_ACTION_REASON get_pkt_action_reason(enum RULE_EVALUATION_ACTION action, enum RULE_TYPE rule_type) {
	if (rule_type == RULE_TYPE_NO_RULES) {
		return ACTION_REASON_NO_RULES;
	}
	if (action == RULE_EVALUATION_ACTION_DENY || action == RULE_EVALUATION_ACTION_DENY_DEFAULT) {
		if (rule_type == RULE_TYPE_MICRO_SEG) {
			return ACTION_REASON_MICRO_SEG_DENY;
		} else if (rule_type == RULE_TYPE_CATEGORY) {
			return ACTION_REASON_CATEGORY_DENY;
		} else if (rule_type == RULE_TYPE_SECURITY_GROUP) {
			return ACTION_REASON_SECURITY_GROUP_DENY;
		}
	} else if (action == RULE_EVALUATION_ACTION_ALLOW) {
		if (rule_type == RULE_TYPE_MICRO_SEG) {
			return ACTION_REASON_MICRO_SEG_ALLOW;
		} else if (rule_type == RULE_TYPE_CATEGORY) {
			return ACTION_REASON_CATEGORY_ALLOW;
		} else if (rule_type == RULE_TYPE_SECURITY_GROUP) {
			return ACTION_REASON_SECURITY_GROUP_ALLOW;
		} else if (rule_type == RULE_TYPE_ROUTER_BYPASS) {
			return ACTION_REASON_ROUTER_BYPASS;
		}
	} else if (action == RULE_EVALUATION_ACTION_NO_ACTION) {
		if (rule_type == RULE_TYPE_MICRO_SEG) {
			return ACTION_REASON_MICRO_SEG_NOACTION;
		} else if (rule_type == RULE_TYPE_CATEGORY) {
			return ACTION_REASON_CATEGORY_NOACTION;
		} else if (rule_type == RULE_TYPE_SECURITY_GROUP) {
			return ACTION_REASON_SECURITY_GROUP_NOACTION;
		}
	}
	return ACTION_REASON_NO_RULES;
}

static void update_pkt_stat_log(struct __sk_buff *ctx, struct packet_context *packet_ctx, struct security_action_reason *reason, 
		enum RULE_TYPE rule_type, __u8 packet_direction, __u64 rule_evaluation_time) __attribute__((noinline)) {
	if (packet_ctx->packet_info == NULL || ctx == NULL || reason == NULL || packet_ctx->eth_header == NULL) {
		return;
	}

	struct packet_context_value *packet_info = packet_ctx->packet_info;
	struct pkt_security_stat_value *log_event = bpf_ringbuf_reserve(&pkt_security_stat_map, 
			sizeof(struct pkt_security_stat_value), 0);
	if (log_event == NULL) {
		return;
	}

	log_event->action = PACKET_ACTION_UNKNOWN;
	log_event->action_reason = ACTION_REASON_UNAVAILABLE;
	log_event->etcd_rule_id = NO_ETCD_RULE_ID;
	if (reason != NULL) {
		log_event->action = rule_evaluation_action_to_pkt_action(reason->action);
		log_event->action_reason = get_pkt_action_reason(reason->action, rule_type);
		log_event->etcd_rule_id = reason->etcd_rule_id;
	}
	log_event->timestamp = bpf_ktime_get_ns();
	log_event->rule_evaluation_time = rule_evaluation_time;
	log_event->local_uvm_ip = packet_info->intermediary_ip;
	log_event->packet_direction = packet_direction;
	log_event->sip = packet_info->sip;
	log_event->sid = packet_info->source_id;
	log_event->dip = packet_info->dip;
	log_event->did = packet_info->destination_id;
	log_event->sport = packet_info->sport;
	log_event->dport = packet_info->dport;
	log_event->protocol = packet_info->protocol;
	log_event->packet_protocol = (packet_ctx->ip_header == NULL) ? 
		bpf_ntohs(packet_ctx->eth_header->h_proto) : packet_ctx->ip_header->protocol;
	bpf_ringbuf_submit(log_event, 0);
}

static __u8 evaluate_rule_ports_protocol(enum MICRO_SEG_PROTOCOL protocol) {
	return (protocol == MICRO_SEG_UDP || protocol == MICRO_SEG_TCP || protocol == MICRO_SEG_HTTP || protocol == MICRO_SEG_HTTPS);
}

static __u8 evaluate_rule_ports_no_nat_type(enum MICRO_SEG_NO_NAT_TYPE protocol) {
	return (protocol == TCP_EGRESS_MICRO_SEG_LOOKUP || protocol == TCP_INGRESS_MICRO_SEG_LOOKUP ||
			protocol == UDP_EGRESS_MICRO_SEG_LOOKUP || protocol == UDP_INGRESS_MICRO_SEG_LOOKUP);
}


struct category_rule_info {
	struct category_rules_key key;
	enum RULE_EVALUATION_ACTION default_action;
	enum RULE_EVALUATION_ACTION action;
	__u16 sport;
	__u16 dport;

	__u8 sport_matched;
	__u8 dport_matched;
};
static long evaluate_category_rule(__u32 index, struct category_rule_info *category_rule_info) {
	if (category_rule_info == NULL) {
		return 1;
	}
	struct category_rules_value *category_value = bpf_map_lookup_elem(&category_rules_map, &category_rule_info->key);
	if (category_value == NULL) {
		return 1;
	}
	category_rule_info->sport_matched = (!evaluate_rule_ports_protocol(category_rule_info->key.lookup_type) || 
			category_rule_info->sport_matched) ? 
		1 : 
		find_single_port_ranges_intersection(category_value->source_port_ranges, 
				category_rule_info->sport);
	category_rule_info->dport_matched = (!evaluate_rule_ports_protocol(category_rule_info->key.lookup_type) || 
			category_rule_info->dport_matched) ? 
		1 : 
		find_single_port_ranges_intersection(category_value->destination_port_ranges, 
				category_rule_info->dport);
	if (category_rule_info->sport_matched && category_rule_info->dport_matched) {
		category_rule_info->action = (category_rule_info->default_action == RULE_EVALUATION_ACTION_ALLOW) ? 
			RULE_EVALUATION_ACTION_DENY : RULE_EVALUATION_ACTION_ALLOW; 
		return 1;
	}
	++category_rule_info->key.increment;
	return 0;
}

static void should_drop_category(const struct packet_context_value *packet_info,
							struct security_action_reason* reason) __attribute__((noinline)) {
	if (packet_info == NULL || reason == NULL) {
		return;
	}
	reason->action = RULE_EVALUATION_ACTION_NO_ACTION;
	reason->etcd_rule_id = NO_ETCD_RULE_ID;
	if (packet_info->source_category == 0 || packet_info->dest_category == 0) { // valid categories have values >= 1
		reason->action = RULE_EVALUATION_ACTION_NO_ACTION;
		return;
	} else if (packet_info->source_category == packet_info->dest_category) {
		reason->action = RULE_EVALUATION_ACTION_NO_ACTION;
		return;
	}
	enum RULE_EVALUATION_ACTION default_action = packet_info->vpc_category_policy == MICRO_SEG_DEF_DENY ?
		RULE_EVALUATION_ACTION_DENY_DEFAULT : RULE_EVALUATION_ACTION_ALLOW;
	struct category_rule_info category_rule_info = {
		.key = {0},
		.default_action = default_action,
		.action = default_action,
		.sport = packet_info->sport,
		.dport = packet_info->dport,
		.sport_matched = 0,
		.dport_matched = 0,
	};
	category_rule_info.key.vpc_id 		= packet_info->vpcid;
	category_rule_info.key.scategory 	= packet_info->source_category;
	category_rule_info.key.dcategory 	= packet_info->dest_category;
	category_rule_info.key.lookup_type	= packet_info->protocol;

	bpf_loop(1 << (8 * sizeof(category_rule_info.key.increment)), &evaluate_category_rule, &category_rule_info, 0);
	if (category_rule_info.action == RULE_EVALUATION_ACTION_ALLOW || packet_info->protocol != MICRO_SEG_NOTA) {
		reason->action = category_rule_info.action;
		return;
	}

	// For NOTA (ex. ARP request and reply), if there is a rule allowing packets from dest_category to reach to source_category, 
	// allow this packet -- thereby, miciking a stateful connection for NOTA packets. This is necessary for ARPs where the 
	// destination may have sent a APR request, and we are trying to respond to it here. 
	category_rule_info.key.dcategory = packet_info->source_category;
	category_rule_info.key.scategory = packet_info->dest_category;
	bpf_loop(1 << (8 * sizeof(category_rule_info.key.increment)), &evaluate_category_rule, &category_rule_info, 0);
	reason->action =  category_rule_info.action;
	return;
}

inline static enum MICRO_SEG_NO_NAT_TYPE get_micro_seg_lookup_type(enum PACKET_PATH packet_path, enum MICRO_SEG_PROTOCOL protocol) {
	switch (protocol) {
		case MICRO_SEG_UDP:
			return (packet_path == EGRESS_PATH) ? UDP_EGRESS_MICRO_SEG_LOOKUP   : UDP_INGRESS_MICRO_SEG_LOOKUP;
		case MICRO_SEG_TCP:
			return (packet_path == EGRESS_PATH) ? TCP_EGRESS_MICRO_SEG_LOOKUP   : TCP_INGRESS_MICRO_SEG_LOOKUP;
		case MICRO_SEG_IP:
			return (packet_path == EGRESS_PATH) ? IP_EGRESS_MICRO_SEG_LOOKUP    : IP_INGRESS_MICRO_SEG_LOOKUP;
		case MICRO_SEG_ICMP:
			return (packet_path == EGRESS_PATH) ? ICMP_EGRESS_MICRO_SEG_LOOKUP  : ICMP_INGRESS_MICRO_SEG_LOOKUP;
		case MICRO_SEG_HTTP:
			return (packet_path == EGRESS_PATH) ? HTTP_EGRESS_MICRO_SEG_LOOKUP  : HTTP_INGRESS_MICRO_SEG_LOOKUP;
		case MICRO_SEG_HTTPS:
			return (packet_path == EGRESS_PATH) ? HTTPS_EGRESS_MICRO_SEG_LOOKUP : HTTPS_INGRESS_MICRO_SEG_LOOKUP;
		case MICRO_SEG_NOTA:
		default:
			return (packet_path == EGRESS_PATH) ? NOTA_EGRESS_MICRO_SEG_LOOKUP  : NOTA_INGRESS_MICRO_SEG_LOOKUP;
	}
}

struct security_rule_info {
	struct micro_seg_and_no_nat_key *key;
	enum RULE_EVALUATION_ACTION default_action;
	enum RULE_EVALUATION_ACTION action;
	__be32 remote_ip_id;
	__u16 packet_local_port;
	__u16 packet_remote_port;
	__u8 rule_is_stateful;
	__u8 local_port_match;
	__u8 remote_port_match;
	__u8 remote_id_lookup: 	1,
	     unused:		7;
	__u32 etcd_rule_id;
};
#define RETURN_NO_ACTION(security_rule_info) 												\
	security_rule_info->action = RULE_EVALUATION_ACTION_NO_ACTION;									\
	security_rule_info->rule_is_stateful = 1;											\
	return 1;
static long evaluate_security_rule(__u32 index, struct security_rule_info *security_rule_info) {
	if (security_rule_info == NULL || security_rule_info->key == NULL) {
		return 1;
	}
	struct micro_seg_and_no_nat_value *micro_seg_value = bpf_map_lookup_elem(&micro_seg_and_no_nat_map, security_rule_info->key);
	if (micro_seg_value == NULL) { // there is no rule for the local UVM -- follow default action
		RETURN_NO_ACTION(security_rule_info);
	} else if (micro_seg_value->lookup_type != security_rule_info->key->data.lookup_type) { 
		// this should almost never happen; the only justification is the map key was programmed with an incorrect 
		// prefixlen such that the prefixlens doesn't include lookup
		security_rule_info->action = RULE_EVALUATION_ACTION_DENY;
		return 1;
	}
	ebpf_printk1(-1, "microseg val - remote_cidr_base_or_remote_id %pI4 eval ports %d", 
			&micro_seg_value->remote_cidr_base_or_remote_id, 
			evaluate_rule_ports_no_nat_type(security_rule_info->key->data.lookup_type));

	// === Check if the remote IP in key fits within the remote CIDR in value
	if (!lpm_key_value_match(security_rule_info->remote_ip_id, micro_seg_value->remote_cidr_base_or_remote_id,
				security_rule_info->remote_id_lookup, micro_seg_value->remote_cidr_size)) {
		RETURN_NO_ACTION(security_rule_info);
	}

	// === For TCP/UDP protocols, check if the local/remote port of packet fit within the range specified in value
	if (evaluate_rule_ports_no_nat_type(security_rule_info->key->data.lookup_type)) {
		security_rule_info->local_port_match = (security_rule_info->local_port_match == 1) ? 1 : 
			find_single_port_ranges_intersection(micro_seg_value->local_port_ranges, 
					security_rule_info->packet_local_port);
		security_rule_info->remote_port_match = (security_rule_info->remote_port_match == 1) ? 1 : 
			find_single_port_ranges_intersection(micro_seg_value->remote_port_ranges, 
					security_rule_info->packet_remote_port);

		if (!security_rule_info->local_port_match || !security_rule_info->remote_port_match) {
			security_rule_info->key->data.remote_ip_id = micro_seg_value->remote_cidr_base_or_remote_id;
			++security_rule_info->key->data.increment;
			ebpf_printk1(-1, "no match");
			return 0;
		}
	}

	// We found a matching security rule for the local UVM/remote IP pair. Thus, we should take the opposite of default action for this
	// packet
	if (micro_seg_value->action == MICRO_SEG_ALLOW) {
		security_rule_info->action = RULE_EVALUATION_ACTION_ALLOW;
		ebpf_printk1(-1, "return allow");
	} else if (micro_seg_value->action == MICRO_SEG_DENY) {
		security_rule_info->action = RULE_EVALUATION_ACTION_DENY;
		ebpf_printk1(-1, "return deny");
	} else {
		security_rule_info->action = security_rule_info->default_action == RULE_EVALUATION_ACTION_ALLOW ?
			RULE_EVALUATION_ACTION_DENY : RULE_EVALUATION_ACTION_ALLOW;
		ebpf_printk1(-1, "return opposite of default; default: %c", security_rule_info->default_action == RULE_EVALUATION_ACTION_ALLOW ? 'A' : 'D');
	}
	security_rule_info->rule_is_stateful = micro_seg_value->stateful;
	security_rule_info->etcd_rule_id = micro_seg_value->etcd_rule_id;
	return 1;
}

#define GET_DEFAULT_ACTION(local_rules, rule_type)								\
	if (local_rules == 1) { /* check local (egress or ingress) */						\
		is_##rule_type##_enabled = packet_info->local_##rule_type##_enabled;				\
		default_action = packet_info->local_##rule_type##_policy == MICRO_SEG_DEF_DENY ?		\
		RULE_EVALUATION_ACTION_DENY_DEFAULT : RULE_EVALUATION_ACTION_ALLOW;				\
	} else if (packet_path == INGRESS_PATH) { /* check remote ingress */					\
		is_##rule_type##_enabled = packet_info->remote_ingress_##rule_type##_enabled;			\
		default_action = packet_info->remote_ingress_##rule_type##_policy == MICRO_SEG_DEF_DENY ?	\
		RULE_EVALUATION_ACTION_DENY_DEFAULT : RULE_EVALUATION_ACTION_ALLOW;				\
	} else { /* check remote egress	*/									\
		is_##rule_type##_enabled = packet_info->remote_egress_##rule_type##_enabled;			\
		default_action = packet_info->remote_egress_##rule_type##_policy == MICRO_SEG_DEF_DENY ?	\
		RULE_EVALUATION_ACTION_DENY_DEFAULT : RULE_EVALUATION_ACTION_ALLOW;				\
	}

static void should_drop_microseg(struct packet_context_value *packet_info, enum PACKET_PATH packet_path,
									struct security_action_reason *reason, __u8 local_rules) {
	if (reason == NULL) {
		return;
	}
	reason->action = RULE_EVALUATION_ACTION_NO_ACTION;
	reason->etcd_rule_id = NO_ETCD_RULE_ID;
	if (packet_info == NULL) {
		reason->action = RULE_EVALUATION_ACTION_DENY_DEFAULT;
		return;
	}
	enum RULE_EVALUATION_ACTION default_action;
	__u8 is_micro_seg_enabled;
	GET_DEFAULT_ACTION(local_rules, micro_seg);
	if (!is_micro_seg_enabled) {
		reason->action = (default_action == RULE_EVALUATION_ACTION_DENY_DEFAULT) ? 
			RULE_EVALUATION_ACTION_DENY_DEFAULT : RULE_EVALUATION_ACTION_NO_ACTION;
		return;
	}

	struct micro_seg_and_no_nat_key micro_seg_key = {0};
	micro_seg_key.prefixlen = SET_LPM_KEY_PREFIXLEN(micro_seg_key);
	micro_seg_key.data.lookup_type = get_micro_seg_lookup_type(packet_path, packet_info->protocol); // not NAT/noNAT lookup type
	micro_seg_key.data.local_tip = (packet_path == EGRESS_PATH) ? packet_info->stip : packet_info->next_hop_tip;

	__be32 remote_ip = (packet_path == EGRESS_PATH) ? packet_info->dip : packet_info->sip;
	__be32 remote_id = (packet_path == EGRESS_PATH) ? packet_info->destination_id : packet_info->source_id;
	micro_seg_key.data.remote_id_lookup = (packet_path == EGRESS_PATH) ? packet_info->destination_has_url : packet_info->source_has_url;
	micro_seg_key.data.remote_ip_id = micro_seg_key.data.remote_id_lookup ? remote_id : remote_ip;

	struct security_rule_info security_rule_info = {
		.key 			= &micro_seg_key,
		.default_action		= default_action,
		.action			= RULE_EVALUATION_ACTION_NO_ACTION, 	// modified by callee to indicate the rule evalution result
		.remote_ip_id		= micro_seg_key.data.remote_ip_id,
		.packet_local_port	= (packet_path == EGRESS_PATH) ? packet_info->sport : packet_info->dport,
		.packet_remote_port	= (packet_path == EGRESS_PATH) ? packet_info->dport : packet_info->sport,
		.rule_is_stateful	= 1, 			// modified by callee to indicate the rule evalution result;
		.local_port_match	= 0,
		.remote_port_match	= 0,
		.remote_id_lookup 	= micro_seg_key.data.remote_id_lookup,
		.etcd_rule_id		= NO_ETCD_RULE_ID,
	};

	bpf_loop(1 << (8 * sizeof(micro_seg_key.data.increment)), &evaluate_security_rule, &security_rule_info, 0);
	packet_info->allow_rule_stateful = packet_info->allow_rule_stateful & security_rule_info.rule_is_stateful;

	if (security_rule_info.action == RULE_EVALUATION_ACTION_NO_ACTION && default_action == RULE_EVALUATION_ACTION_DENY_DEFAULT) {
		reason->action =  RULE_EVALUATION_ACTION_DENY_DEFAULT;
		return;
	}

	reason->action = security_rule_info.action;
	reason->etcd_rule_id = security_rule_info.etcd_rule_id;
	return;
}

static void should_drop_security_group(struct packet_context_value *packet_info, enum PACKET_PATH packet_path, 
		struct security_action_reason* reason, __u8 local_rules) {
	if (packet_info == NULL || reason == NULL) {
		return;
	}
	reason->action = RULE_EVALUATION_ACTION_NO_ACTION;
	reason->etcd_rule_id = NO_ETCD_RULE_ID;

	enum RULE_EVALUATION_ACTION default_action;
	__u8 is_security_group_enabled;
	GET_DEFAULT_ACTION(local_rules, security_group);
	if (!is_security_group_enabled) {
		reason->action = (default_action == RULE_EVALUATION_ACTION_DENY_DEFAULT) ? 
			RULE_EVALUATION_ACTION_DENY_DEFAULT : RULE_EVALUATION_ACTION_NO_ACTION;
		return;
	}

	struct micro_seg_and_no_nat_key micro_seg_key = {0};
	micro_seg_key.prefixlen = SET_LPM_KEY_PREFIXLEN(micro_seg_key);
	micro_seg_key.data.lookup_type = get_micro_seg_lookup_type(packet_path, packet_info->protocol); // not NAT/noNAT lookup type
	micro_seg_key.data.local_tip = (packet_path == EGRESS_PATH) ? packet_info->src_bcast_tip : packet_info->dest_bcast_tip;

	__be32 remote_ip = (packet_path == EGRESS_PATH) ? packet_info->dip : packet_info->sip;
	__be32 remote_id = (packet_path == EGRESS_PATH) ? packet_info->destination_id : packet_info->source_id;
	micro_seg_key.data.remote_id_lookup = (packet_path == EGRESS_PATH) ? packet_info->destination_has_url : packet_info->source_has_url;
	micro_seg_key.data.remote_ip_id = micro_seg_key.data.remote_id_lookup ? remote_id : remote_ip;

	struct security_rule_info security_rule_info = {
		.key                    = &micro_seg_key,
		.default_action         = default_action,
		.action                 = RULE_EVALUATION_ACTION_NO_ACTION,       // modified by callee to indicate the rule evalution result
		.remote_ip_id           = micro_seg_key.data.remote_ip_id,
		.packet_local_port      = (packet_path == EGRESS_PATH) ? packet_info->sport : packet_info->dport,
		.packet_remote_port     = (packet_path == EGRESS_PATH) ? packet_info->dport : packet_info->sport,
		.rule_is_stateful       = 1,                    // modified by callee to indicate the rule evalution result;
		.local_port_match	= 0,
		.remote_port_match	= 0,
		.remote_id_lookup 	= micro_seg_key.data.remote_id_lookup,
		.etcd_rule_id		= NO_ETCD_RULE_ID,
	};

	bpf_loop(1 << (8 * sizeof(micro_seg_key.data.increment)), &evaluate_security_rule, &security_rule_info, 0);
	packet_info->allow_rule_stateful = packet_info->allow_rule_stateful & security_rule_info.rule_is_stateful;

	if (security_rule_info.action == RULE_EVALUATION_ACTION_NO_ACTION) {
		reason->action = default_action;
		return;
	}

	reason->action = security_rule_info.action;
	reason->etcd_rule_id = security_rule_info.etcd_rule_id;
	return;
}

#define EVALUATE_RULE(should_drop_function, return_reason, rule_type, rule_str, packet_path) do {				\
	__u64 timestamp = bpf_ktime_get_ns();											\
	should_drop_function;													\
	update_pkt_stat_log(ctx, &packet_context, return_reason, rule_type, packet_path, bpf_ktime_get_ns() - timestamp);	\
} while(0)

#define HANDLE_RULE_EVALUATION_RESULT(action, evalute_allow, update_stateful, rule_stateful, packet_path) do {			\
	if (action == RULE_EVALUATION_ACTION_DENY || action == RULE_EVALUATION_ACTION_DENY_DEFAULT) { 				\
		RETURN_SHOT_FROM_TAIL(packet_info);                                                                             \
	} else if (action == RULE_EVALUATION_ACTION_ALLOW) {									\
		if (update_stateful) {												\
			packet_info->create_est_connection = (rule_stateful) & packet_info->create_est_connection;		\
		}														\
		if (evalute_allow) {                                                   						\
			if (packet_path == EGRESS_PATH) {									\
				tail_call_egress_ebpf(packet_info, ctx, PARSE_MVTAP_ESEND);					\
			} else {												\
				tail_call_ingress_ebpf(packet_info, ctx, PARSE_MVTAP_ISEND);					\
			}													\
			RETURN_FROM_TAIL(packet_info, packet_info->tail_call_return);						\
		}														\
	}                                                                                                                       \
} while(0)
#define LOCAL   			1
#define REMOTE  			0 
#define UPDATE_CREATE_CONNECTION 	1
#define HANDLE_ALLOW_RESULT 		1
#define RULE_STATEFUL			1
