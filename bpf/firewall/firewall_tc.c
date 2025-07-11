//go:build ignore

#include "common.h"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/pkt_cls.h>
#include "../../lib/libbpf/src/bpf_endian.h"

#define MAX_RULES 1000

// Protocol numbers
#define IPPROTO_ICMP 1
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

// Rule types
#define RULE_TYPE_WHITELIST 0
#define RULE_TYPE_BLACKLIST 1

// Actions
#define ACTION_ALLOW 0
#define ACTION_DENY 1

// Directions
#define DIRECTION_INGRESS 0
#define DIRECTION_EGRESS 1

// 规则结构，支持IP范围、端口和协议
struct tc_rule {
    __u32 ip_start;     // 起始IP (网络字节序)
    __u32 ip_end;       // 结束IP (网络字节序)
    __u16 port;         // 端口 (0表示任意端口)
    __u8 protocol;      // 协议 (0表示任意协议, 1=ICMP, 6=TCP, 17=UDP)
    __u8 rule_type;     // 规则类型: 0=WHITELIST, 1=BLACKLIST
    __u8 action;        // 动作: 0=ALLOW, 1=DENY (主要用于黑白名单外的默认动作)
    __u8 direction;     // 方向: 0=INGRESS, 1=EGRESS
    __u8 reserved[2];   // 保留字段，用于对齐
};

// 统计信息结构
struct firewall_tc_stats {
    __u64 total_packets;
    __u64 allowed_packets;
    __u64 denied_packets;
    __u64 ingress_packets;
    __u64 egress_packets;
};

// BPF Maps for ingress whitelist rules
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_RULES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);
    __type(value, struct tc_rule);
} tc_ingress_whitelist SEC(".maps");

// BPF Maps for ingress blacklist rules
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_RULES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);
    __type(value, struct tc_rule);
} tc_ingress_blacklist SEC(".maps");

// BPF Maps for egress whitelist rules
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_RULES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);
    __type(value, struct tc_rule);
} tc_egress_whitelist SEC(".maps");

// BPF Maps for egress blacklist rules
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_RULES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);
    __type(value, struct tc_rule);
} tc_egress_blacklist SEC(".maps");

// Statistics map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);
    __type(value, struct firewall_tc_stats);
} tc_stats_map SEC(".maps");

// Rule count maps
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);
    __type(value, __u32);
} tc_ingress_whitelist_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);
    __type(value, __u32);
} tc_ingress_blacklist_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);
    __type(value, __u32);
} tc_egress_whitelist_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);
    __type(value, __u32);
} tc_egress_blacklist_count SEC(".maps");

// Helper function to get statistics
static struct firewall_tc_stats* get_stats() {
    __u32 key = 0;
    return bpf_map_lookup_elem(&tc_stats_map, &key);
}

// Helper function to update statistics
static void update_stats(struct firewall_tc_stats *stats, __u8 action, __u8 direction) {
    if (!stats) return;
    
    __sync_fetch_and_add(&stats->total_packets, 1);
    
    if (direction == 0) { // INGRESS
        __sync_fetch_and_add(&stats->ingress_packets, 1);
    } else { // EGRESS
        __sync_fetch_and_add(&stats->egress_packets, 1);
    }
    
    if (action == TC_ACT_SHOT) {
        __sync_fetch_and_add(&stats->denied_packets, 1);
    } else {
        __sync_fetch_and_add(&stats->allowed_packets, 1);
    }
}

// Check if IP is in range (both IPs in network byte order)
static int ip_in_range(__u32 ip, __u32 start, __u32 end) {
    __u32 ip_host = bpf_ntohl(ip);
    __u32 start_host = bpf_ntohl(start);
    __u32 end_host = bpf_ntohl(end);
    
    return (ip_host >= start_host && ip_host <= end_host);
}

// Check if protocol matches (0 means any protocol)
static int protocol_matches(__u8 packet_protocol, __u8 rule_protocol) {
    return (rule_protocol == 0 || packet_protocol == rule_protocol);
}

// Check rules for whitelist (priority over blacklist)
static int check_whitelist_rules(struct __sk_buff *skb, __u32 src_ip, __u32 dst_ip, 
                                __u16 src_port, __u16 dst_port, __u8 packet_protocol, __u8 direction) {
    struct tc_rule *rule;
    __u32 *rule_count;
    __u32 key = 0;
    
    // Get whitelist rule count for the direction
    if (direction == DIRECTION_INGRESS) {
        rule_count = bpf_map_lookup_elem(&tc_ingress_whitelist_count, &key);
    } else {
        rule_count = bpf_map_lookup_elem(&tc_egress_whitelist_count, &key);
    }
    
    if (!rule_count || *rule_count == 0) {
        return -1; // No whitelist rules, continue to blacklist check
    }
    
    // Iterate through whitelist rules
    #pragma unroll
    for (__u32 i = 0; i < MAX_RULES && i < *rule_count; i++) {
        if (direction == DIRECTION_INGRESS) {
            rule = bpf_map_lookup_elem(&tc_ingress_whitelist, &i);
        } else {
            rule = bpf_map_lookup_elem(&tc_egress_whitelist, &i);
        }
        
        if (!rule) continue;
        
        // Check if rule matches
        int ip_match = 0;
        int port_match = 0;
        int protocol_match = protocol_matches(packet_protocol, rule->protocol);
        
        // For ingress: check source IP (external -> internal)
        // For egress: check destination IP (internal -> external)
        if (direction == DIRECTION_INGRESS) {
            ip_match = ip_in_range(src_ip, rule->ip_start, rule->ip_end);
            port_match = (rule->port == 0 || src_port == rule->port || dst_port == rule->port);
        } else {
            ip_match = ip_in_range(dst_ip, rule->ip_start, rule->ip_end);
            port_match = (rule->port == 0 || src_port == rule->port || dst_port == rule->port);
        }
        
        if (ip_match && port_match && protocol_match) {
            bpf_printk("TC: Whitelist ALLOW %s packet: protocol=%u\n",
                      direction == DIRECTION_INGRESS ? "ingress" : "egress", packet_protocol);
            return TC_ACT_OK; // Whitelist match - allow
        }
    }
    
    return -1; // No whitelist match, continue to blacklist check
}

// Check rules for blacklist
static int check_blacklist_rules(struct __sk_buff *skb, __u32 src_ip, __u32 dst_ip, 
                                __u16 src_port, __u16 dst_port, __u8 packet_protocol, __u8 direction) {
    struct tc_rule *rule;
    __u32 *rule_count;
    __u32 key = 0;
    
    // Get blacklist rule count for the direction
    if (direction == DIRECTION_INGRESS) {
        rule_count = bpf_map_lookup_elem(&tc_ingress_blacklist_count, &key);
    } else {
        rule_count = bpf_map_lookup_elem(&tc_egress_blacklist_count, &key);
    }
    
    if (!rule_count || *rule_count == 0) {
        return TC_ACT_OK; // No blacklist rules, default allow
    }
    
    // Iterate through blacklist rules
    #pragma unroll
    for (__u32 i = 0; i < MAX_RULES && i < *rule_count; i++) {
        if (direction == DIRECTION_INGRESS) {
            rule = bpf_map_lookup_elem(&tc_ingress_blacklist, &i);
        } else {
            rule = bpf_map_lookup_elem(&tc_egress_blacklist, &i);
        }
        
        if (!rule) continue;
        
        // Check if rule matches
        int ip_match = 0;
        int port_match = 0;
        int protocol_match = protocol_matches(packet_protocol, rule->protocol);
        
        // For ingress: check source IP (external -> internal)
        // For egress: check destination IP (internal -> external)
        if (direction == DIRECTION_INGRESS) {
            ip_match = ip_in_range(src_ip, rule->ip_start, rule->ip_end);
            port_match = (rule->port == 0 || src_port == rule->port || dst_port == rule->port);
        } else {
            ip_match = ip_in_range(dst_ip, rule->ip_start, rule->ip_end);
            port_match = (rule->port == 0 || src_port == rule->port || dst_port == rule->port);
        }
        
        if (ip_match && port_match && protocol_match) {
            bpf_printk("TC: Blacklist DENY %s packet: protocol=%u\n",
                      direction == DIRECTION_INGRESS ? "ingress" : "egress", packet_protocol);
            return TC_ACT_SHOT; // Blacklist match - deny
        }
    }
    
    return TC_ACT_OK; // No blacklist match, default allow
}

// Main rule checking function with whitelist/blacklist priority
static int check_rules(struct __sk_buff *skb, __u32 src_ip, __u32 dst_ip, 
                      __u16 src_port, __u16 dst_port, __u8 packet_protocol, __u8 direction) {
    // First check whitelist (priority)
    int whitelist_result = check_whitelist_rules(skb, src_ip, dst_ip, src_port, dst_port, packet_protocol, direction);
    if (whitelist_result != -1) {
        return whitelist_result; // Whitelist decision found
    }
    
    // Then check blacklist
    return check_blacklist_rules(skb, src_ip, dst_ip, src_port, dst_port, packet_protocol, direction);
}

// Main packet processing function
static int process_packet(struct __sk_buff *skb, __u8 direction) {
    struct ethhdr eth;
    struct iphdr ip;
    struct tcphdr tcp;
    struct udphdr udp;
    
    __u32 ip_offset = sizeof(eth);
    __u32 l4_offset;
    
    struct firewall_tc_stats *stats = get_stats();
    
    // Parse Ethernet header
    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0) {
        return TC_ACT_OK;
    }
    
    // Only process IPv4 packets
    if (eth.h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }
    
    // Parse IP header
    if (bpf_skb_load_bytes(skb, ip_offset, &ip, sizeof(ip)) < 0) {
        return TC_ACT_OK;
    }
    
    // Validate IP header
    if (ip.version != 4 || ip.ihl < 5) {
        return TC_ACT_OK;
    }
    
    l4_offset = ip_offset + (ip.ihl * 4);
    
    __u32 src_ip = ip.saddr;
    __u32 dst_ip = ip.daddr;
    __u16 src_port = 0;
    __u16 dst_port = 0;
    __u8 packet_protocol = ip.protocol;
    
    // Extract port information if available
    switch (packet_protocol) {
        case IPPROTO_TCP:
            if (bpf_skb_load_bytes(skb, l4_offset, &tcp, sizeof(tcp)) == 0) {
                src_port = bpf_ntohs(tcp.source);
                dst_port = bpf_ntohs(tcp.dest);
            }
            break;
        case IPPROTO_UDP:
            if (bpf_skb_load_bytes(skb, l4_offset, &udp, sizeof(udp)) == 0) {
                src_port = bpf_ntohs(udp.source);
                dst_port = bpf_ntohs(udp.dest);
            }
            break;
        default:
            // For protocols without ports (like ICMP), port will remain 0
            break;
    }
    
    // Check rules with protocol filtering
    int action = check_rules(skb, src_ip, dst_ip, src_port, dst_port, packet_protocol, direction);
    
    // Update statistics
    if (stats) {
        update_stats(stats, action, direction);
    }
    
    return action;
}

// TC ingress program (for incoming traffic)
SEC("tc")
int tc_ingress_filter(struct __sk_buff *skb) {
    return process_packet(skb, DIRECTION_INGRESS);
}

// TC egress program (for outgoing traffic)
SEC("tc")
int tc_egress_filter(struct __sk_buff *skb) {
    return process_packet(skb, DIRECTION_EGRESS);
}

char _license[] SEC("license") = "GPL";