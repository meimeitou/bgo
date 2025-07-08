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
#include "src/bpf_endian.h"

#define MAX_BLOCKED_IPS 1000
#define MAX_BLOCKED_PORTS 100
#define MAX_ALLOWED_IPS 100

// Protocol numbers (not always defined in kernel headers for eBPF)
#define IPPROTO_ICMP 1
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

// 防火墙规则结构
struct firewall_rule {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;  // TCP=6, UDP=17, ICMP=1
    __u8 action;    // 0=DROP, 1=ACCEPT
};

// 统计信息结构
struct fw_stats {
    __u64 total_packets;
    __u64 dropped_packets;
    __u64 accepted_packets;
    __u64 tcp_packets;
    __u64 udp_packets;
    __u64 icmp_packets;
    __u64 other_packets;
};

// BPF Maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BLOCKED_IPS);
    __type(key, __u32);    // IP地址
    __type(value, __u8);   // 1=blocked
} blocked_ips SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BLOCKED_PORTS);
    __type(key, __u16);    // 端口号
    __type(value, __u8);   // 1=blocked
} blocked_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ALLOWED_IPS);
    __type(key, __u32);    // IP地址
    __type(value, __u8);   // 1=allowed
} allowed_ips SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct fw_stats);
} stats_map SEC(".maps");

// 获取统计信息
static struct fw_stats* get_stats() {
    __u32 key = 0;
    return bpf_map_lookup_elem(&stats_map, &key);
}

// 更新统计信息
static void update_stats(struct fw_stats *stats, __u8 protocol, __u8 action) {
    if (!stats) return;
    
    __sync_fetch_and_add(&stats->total_packets, 1);
    
    if (action == TC_ACT_SHOT) {
        __sync_fetch_and_add(&stats->dropped_packets, 1);
    } else {
        __sync_fetch_and_add(&stats->accepted_packets, 1);
    }
    
    switch (protocol) {
        case IPPROTO_TCP:
            __sync_fetch_and_add(&stats->tcp_packets, 1);
            break;
        case IPPROTO_UDP:
            __sync_fetch_and_add(&stats->udp_packets, 1);
            break;
        case IPPROTO_ICMP:
            __sync_fetch_and_add(&stats->icmp_packets, 1);
            break;
        default:
            __sync_fetch_and_add(&stats->other_packets, 1);
            break;
    }
}

// 检查IP是否在白名单中
static int is_ip_allowed(__u32 ip) {
    __u8 *allowed = bpf_map_lookup_elem(&allowed_ips, &ip);
    return allowed && *allowed;
}

// 检查IP是否被阻止
static int is_ip_blocked(__u32 ip) {
    __u8 *blocked = bpf_map_lookup_elem(&blocked_ips, &ip);
    return blocked && *blocked;
}

// 检查端口是否被阻止
static int is_port_blocked(__u16 port) {
    __u8 *blocked = bpf_map_lookup_elem(&blocked_ports, &port);
    return blocked && *blocked;
}

// 解析TCP头部
static int parse_tcp(struct __sk_buff *skb, struct tcphdr *tcp, __u32 offset) {
    if (bpf_skb_load_bytes(skb, offset, tcp, sizeof(*tcp)) < 0) {
        return -1;
    }
    return 0;
}

// 解析UDP头部
static int parse_udp(struct __sk_buff *skb, struct udphdr *udp, __u32 offset) {
    if (bpf_skb_load_bytes(skb, offset, udp, sizeof(*udp)) < 0) {
        return -1;
    }
    return 0;
}

// 主要的防火墙逻辑
static int firewall_filter(struct __sk_buff *skb) {
    struct ethhdr eth;
    struct iphdr ip;
    struct tcphdr tcp;
    struct udphdr udp;
    struct icmphdr icmp;
    
    __u32 ip_offset = sizeof(eth);
    __u32 l4_offset = ip_offset + sizeof(ip);
    
    struct fw_stats *stats = get_stats();
    
    // 解析以太网头部
    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0) {
        return TC_ACT_OK;
    }
    
    // 只处理IPv4包
    if (eth.h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }
    
    // 解析IP头部
    if (bpf_skb_load_bytes(skb, ip_offset, &ip, sizeof(ip)) < 0) {
        return TC_ACT_OK;
    }
    
    // 检查IP版本和头部长度
    if (ip.version != 4 || ip.ihl < 5) {
        return TC_ACT_OK;
    }
    
    // 更新L4偏移量
    l4_offset = ip_offset + (ip.ihl * 4);
    
    __u32 src_ip = bpf_ntohl(ip.saddr);
    __u32 dst_ip = bpf_ntohl(ip.daddr);
    __u16 src_port = 0;
    __u16 dst_port = 0;
    
    // 检查白名单 - 如果源IP或目标IP在白名单中，则允许
    if (is_ip_allowed(src_ip) || is_ip_allowed(dst_ip)) {
        if (stats) {
            update_stats(stats, ip.protocol, TC_ACT_OK);
        }
        return TC_ACT_OK;
    }
    
    // 检查IP黑名单
    if (is_ip_blocked(src_ip) || is_ip_blocked(dst_ip)) {
        if (stats) {
            update_stats(stats, ip.protocol, TC_ACT_SHOT);
        }
        bpf_printk("Blocked IP: src=%u.%u.%u.%u dst=%u.%u.%u.%u\n",
                   (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF,
                   (src_ip >> 8) & 0xFF, src_ip & 0xFF,
                   (dst_ip >> 24) & 0xFF, (dst_ip >> 16) & 0xFF,
                   (dst_ip >> 8) & 0xFF, dst_ip & 0xFF);
        return TC_ACT_SHOT;
    }
    
    // 根据协议解析端口
    switch (ip.protocol) {
        case IPPROTO_TCP:
            if (parse_tcp(skb, &tcp, l4_offset) == 0) {
                src_port = bpf_ntohs(tcp.source);
                dst_port = bpf_ntohs(tcp.dest);
            }
            break;
        case IPPROTO_UDP:
            if (parse_udp(skb, &udp, l4_offset) == 0) {
                src_port = bpf_ntohs(udp.source);
                dst_port = bpf_ntohs(udp.dest);
            }
            break;
        case IPPROTO_ICMP:
            // ICMP不检查端口
            if (stats) {
                update_stats(stats, ip.protocol, TC_ACT_OK);
            }
            return TC_ACT_OK;
        default:
            // 其他协议默认允许
            if (stats) {
                update_stats(stats, ip.protocol, TC_ACT_OK);
            }
            return TC_ACT_OK;
    }
    
    // 检查端口黑名单
    if (is_port_blocked(src_port) || is_port_blocked(dst_port)) {
        if (stats) {
            update_stats(stats, ip.protocol, TC_ACT_SHOT);
        }
        bpf_printk("Blocked port: src=%u:%u dst=%u:%u proto=%u\n",
                   src_ip, src_port, dst_ip, dst_port, ip.protocol);
        return TC_ACT_SHOT;
    }
    
    // 默认允许
    if (stats) {
        update_stats(stats, ip.protocol, TC_ACT_OK);
    }
    return TC_ACT_OK;
}

// TC ingress 防火墙
SEC("tc")
int tc_ingress_firewall(struct __sk_buff *skb) {
    return firewall_filter(skb);
}

// TC egress 防火墙
SEC("tc")
int tc_egress_firewall(struct __sk_buff *skb) {
    return firewall_filter(skb);
}

char _license[] SEC("license") = "GPL";