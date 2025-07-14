//go:build ignore

#include "common/common.h"
#include "firewall_common.h"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

// Pin maps by name for external access
#ifndef LIBBPF_PIN_BY_NAME
#define LIBBPF_PIN_BY_NAME 1
#endif

// 网络字节序转换宏
#ifndef bpf_htons
#define bpf_htons(x) __builtin_bswap16(x)
#endif

#ifndef bpf_ntohs
#define bpf_ntohs(x) __builtin_bswap16(x)
#endif

// XDP动作定义
#ifndef XDP_ABORTED
#define XDP_ABORTED 0
#define XDP_DROP    1
#define XDP_PASS    2
#define XDP_TX      3
#define XDP_REDIRECT 4
#endif

// 防火墙规则结构
struct fw_rule {
    __u32 ip_start;     // IP地址起始范围
    __u32 ip_end;       // IP地址结束范围  
    __u16 port;         // 端口号，0表示所有端口
    __u8 protocol;      // 协议类型 (IPPROTO_TCP, IPPROTO_UDP, 0表示所有)
    __u8 action;        // 动作: 0=BLOCK, 1=ALLOW
};

// 统计信息结构
struct fw_stats {
    __u64 total_packets;
    __u64 allowed_packets;
    __u64 blocked_packets;
};

// 白名单Map (优先级高)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct fw_rule);
    __uint(max_entries, MAX_RULES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} whitelist_map SEC(".maps");

// 黑名单Map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct fw_rule);
    __uint(max_entries, MAX_RULES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} blacklist_map SEC(".maps");

// 统计信息Map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct fw_stats);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} stats_map SEC(".maps");

// 配置Map - 用于存储防火墙配置
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 10);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} config_map SEC(".maps");

// 配置键定义
#define CONFIG_WHITELIST_ENABLED 0
#define CONFIG_BLACKLIST_ENABLED 1
#define CONFIG_DEFAULT_ACTION    2  // 0=DROP, 1=PASS

static __always_inline int parse_ipv4(void *data, void *data_end, 
                                      __u32 *src_ip, __u32 *dst_ip, 
                                      __u16 *src_port, __u16 *dst_port,
                                      __u8 *protocol)
{
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;

    // 检查以太网头部
    if ((void *)(eth + 1) > data_end)
        return -1;

    // 只处理IPv4包
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;

    ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return -1;

    *src_ip = ip->saddr;
    *dst_ip = ip->daddr;
    *protocol = ip->protocol;

    // 解析端口号
    if (ip->protocol == IPPROTO_TCP) {
        tcp = (struct tcphdr *)((void *)ip + (ip->ihl * 4));
        if ((void *)(tcp + 1) > data_end)
            return -1;
        *src_port = bpf_ntohs(tcp->source);
        *dst_port = bpf_ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        udp = (struct udphdr *)((void *)ip + (ip->ihl * 4));
        if ((void *)(udp + 1) > data_end)
            return -1;
        *src_port = bpf_ntohs(udp->source);
        *dst_port = bpf_ntohs(udp->dest);
    } else {
        *src_port = 0;
        *dst_port = 0;
    }

    return 0;
}

static __always_inline int check_rule_match(struct fw_rule *rule, 
                                           __u32 ip, __u16 port, __u8 protocol)
{
    // 检查IP范围
    if (ip < rule->ip_start || ip > rule->ip_end)
        return 0;

    // 检查端口 (0表示匹配所有端口)
    if (rule->port != 0 && rule->port != port)
        return 0;

    // 检查协议 (0表示匹配所有协议)
    if (rule->protocol != 0 && rule->protocol != protocol)
        return 0;

    return 1;
}

static __always_inline int check_whitelist(__u32 ip, __u16 port, __u8 protocol)
{
    struct fw_rule *rule;
    __u32 key;

    // 使用#pragma unroll优化循环 - 检查前50个规则
    #pragma unroll
    for (int i = 0; i < MAX_RULES; i++) {
        key = i;
        rule = bpf_map_lookup_elem(&whitelist_map, &key);
        if (rule && rule->ip_start != 0 && check_rule_match(rule, ip, port, protocol))
            return 1;
    }

    return 0; // 未匹配白名单
}

static __always_inline int check_blacklist(__u32 ip, __u16 port, __u8 protocol)
{
    struct fw_rule *rule;
    __u32 key;

    // 使用#pragma unroll优化循环 - 检查前50个规则
    #pragma unroll
    for (int i = 0; i < MAX_RULES; i++) {
        key = i;
        rule = bpf_map_lookup_elem(&blacklist_map, &key);
        if (rule && rule->ip_start != 0 && check_rule_match(rule, ip, port, protocol))
            return 1;
    }

    return 0; // 未匹配黑名单
}

static __always_inline void update_stats(__u32 allowed)
{
    __u32 key = 0;
    struct fw_stats *stats;

    stats = bpf_map_lookup_elem(&stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->total_packets, 1);
        if (allowed)
            __sync_fetch_and_add(&stats->allowed_packets, 1);
        else
            __sync_fetch_and_add(&stats->blocked_packets, 1);
    }
}

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    __u32 src_ip, dst_ip;
    __u16 src_port, dst_port;
    __u8 protocol;
    
    // 解析数据包
    if (parse_ipv4(data, data_end, &src_ip, &dst_ip, 
                   &src_port, &dst_port, &protocol) < 0) {
        return XDP_PASS; // 非IPv4包直接通过
    }

    // 获取配置
    __u32 config_key = CONFIG_WHITELIST_ENABLED;
    __u32 *whitelist_enabled = bpf_map_lookup_elem(&config_map, &config_key);
    
    config_key = CONFIG_BLACKLIST_ENABLED;
    __u32 *blacklist_enabled = bpf_map_lookup_elem(&config_map, &config_key);
    
    config_key = CONFIG_DEFAULT_ACTION;
    __u32 *default_action = bpf_map_lookup_elem(&config_map, &config_key);

    // 1. 首先检查白名单 (优先级最高)
    if (whitelist_enabled && *whitelist_enabled) {
        if (check_whitelist(src_ip, src_port, protocol)) {
            update_stats(1);
            return XDP_PASS; // 白名单匹配，允许通过
        }
    }

    // 2. 然后检查黑名单
    if (blacklist_enabled && *blacklist_enabled) {
        if (check_blacklist(src_ip, src_port, protocol)) {
            update_stats(0);
            return XDP_DROP; // 黑名单匹配，丢弃数据包
        }
    }

    // 3. 默认动作
    if (default_action && *default_action == 0) {
        update_stats(0);
        return XDP_DROP; // 默认丢弃
    } else {
        update_stats(1);
        return XDP_PASS; // 默认通过
    }
}

char _license[] SEC("license") = "GPL";