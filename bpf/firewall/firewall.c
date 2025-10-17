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
} __attribute__((packed));

// 统计信息结构
struct fw_stats {
    __u64 total_packets;
    __u64 allowed_packets;
    __u64 blocked_packets;
};

// 流量限制配置结构
struct rate_limit_config {
    __u64 pps_limit;        // 包速率限制 (packets per second)
    __u64 bps_limit;        // 字节速率限制 (bytes per second)
    __u8 enabled;           // 是否启用流量限制
    __u8 padding[7];        // 对齐
} __attribute__((packed));

// 流量限制状态结构
struct rate_limit_state {
    __u64 last_update_ns;   // 上次更新时间（纳秒）
    __u64 tokens_packets;   // 令牌桶：数据包数量
    __u64 tokens_bytes;     // 令牌桶：字节数量
} __attribute__((packed));

// 流量限制统计
struct rate_limit_stats {
    __u64 dropped_packets;  // 因流量限制丢弃的包数
    __u64 dropped_bytes;    // 因流量限制丢弃的字节数
    __u64 passed_packets;   // 通过的包数
    __u64 passed_bytes;     // 通过的字节数
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

// 流量限制配置Map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct rate_limit_config);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rate_limit_config_map SEC(".maps");

// 流量限制状态Map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct rate_limit_state);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rate_limit_state_map SEC(".maps");

// 流量限制统计Map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct rate_limit_stats);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rate_limit_stats_map SEC(".maps");

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

    // 检查IP头长度
    if (ip->ihl < 5)
        return -1;

    *src_ip = ip->saddr;
    *dst_ip = ip->daddr;
    *protocol = ip->protocol;

    // 计算IP头部长度，确保不超出数据包边界
    void *ip_end = (void *)ip + (ip->ihl * 4);
    if (ip_end > data_end)
        return -1;

    // 解析端口号
    if (ip->protocol == IPPROTO_TCP) {
        tcp = (struct tcphdr *)ip_end;
        if ((void *)(tcp + 1) > data_end)
            return -1;
        *src_port = bpf_ntohs(tcp->source);
        *dst_port = bpf_ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        udp = (struct udphdr *)ip_end;
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

    // 使用#pragma unroll优化循环 - 减少到30个规则
    #pragma unroll
    for (int i = 0; i < 30; i++) {
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

    // 使用#pragma unroll优化循环 - 减少到30个规则
    #pragma unroll
    for (int i = 0; i < 30; i++) {
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

// 流量限制检查函数 - 使用令牌桶算法
// 返回: 1=允许通过, 0=需要丢弃
static __always_inline int check_rate_limit(__u32 packet_size)
{
    __u32 key = 0;
    struct rate_limit_config *config;
    struct rate_limit_state *state;
    struct rate_limit_stats *stats;
    __u64 now_ns, elapsed_ns;
    __u64 new_tokens_packets, new_tokens_bytes;
    int allow = 1;

    // 获取配置
    config = bpf_map_lookup_elem(&rate_limit_config_map, &key);
    if (!config || !config->enabled) {
        return 1; // 未启用流量限制，允许通过
    }

    // 获取状态
    state = bpf_map_lookup_elem(&rate_limit_state_map, &key);
    if (!state) {
        return 1; // 状态不存在，允许通过
    }

    // 获取统计
    stats = bpf_map_lookup_elem(&rate_limit_stats_map, &key);
    if (!stats) {
        return 1; // 统计不存在，允许通过
    }

    // 获取当前时间（纳秒）
    now_ns = bpf_ktime_get_ns();
    
    // 计算时间差（纳秒）
    if (now_ns < state->last_update_ns) {
        // 时间回退，重置
        state->last_update_ns = now_ns;
        state->tokens_packets = config->pps_limit;
        state->tokens_bytes = config->bps_limit;
        return 1;
    }
    
    elapsed_ns = now_ns - state->last_update_ns;
    
    // 令牌桶算法：根据经过的时间添加令牌
    // tokens_per_ns = limit / 1000000000 (1秒 = 10^9纳秒)
    // new_tokens = (elapsed_ns * limit) / 1000000000
    
    // 包速率限制检查
    if (config->pps_limit > 0) {
        // 计算新增的包令牌
        new_tokens_packets = (elapsed_ns * config->pps_limit) / 1000000000;
        state->tokens_packets += new_tokens_packets;
        
        // 令牌桶上限为配置的限制值
        if (state->tokens_packets > config->pps_limit) {
            state->tokens_packets = config->pps_limit;
        }
        
        // 检查是否有足够的令牌
        if (state->tokens_packets >= 1) {
            state->tokens_packets -= 1;
        } else {
            allow = 0; // 包速率超限
        }
    }
    
    // 字节速率限制检查
    if (allow && config->bps_limit > 0) {
        // 计算新增的字节令牌
        new_tokens_bytes = (elapsed_ns * config->bps_limit) / 1000000000;
        state->tokens_bytes += new_tokens_bytes;
        
        // 令牌桶上限为配置的限制值
        if (state->tokens_bytes > config->bps_limit) {
            state->tokens_bytes = config->bps_limit;
        }
        
        // 检查是否有足够的令牌
        if (state->tokens_bytes >= packet_size) {
            state->tokens_bytes -= packet_size;
        } else {
            allow = 0; // 字节速率超限
        }
    }
    
    // 更新时间戳
    state->last_update_ns = now_ns;
    
    // 更新统计
    if (allow) {
        __sync_fetch_and_add(&stats->passed_packets, 1);
        __sync_fetch_and_add(&stats->passed_bytes, packet_size);
    } else {
        __sync_fetch_and_add(&stats->dropped_packets, 1);
        __sync_fetch_and_add(&stats->dropped_bytes, packet_size);
    }
    
    return allow;
}

SEC("xdp")
int xdp_firewall_with_lvs(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    __u32 src_ip, dst_ip;
    __u16 src_port, dst_port;
    __u8 protocol;
    __u32 packet_size = data_end - data;
    
    // 解析数据包
    if (parse_ipv4(data, data_end, &src_ip, &dst_ip, 
                   &src_port, &dst_port, &protocol) < 0) {
        return XDP_PASS; // 非IPv4包直接通过
    }

    // 防火墙过滤逻辑
    __u32 config_key = CONFIG_WHITELIST_ENABLED;
    __u32 *whitelist_enabled = bpf_map_lookup_elem(&config_map, &config_key);
    
    // 1. 首先检查白名单 (优先级最高)
    if (whitelist_enabled && *whitelist_enabled) {
        if (check_whitelist(src_ip, dst_port, protocol)) {
            update_stats(1);
            // 白名单通过后，继续检查流量限制
            goto check_rate;
        }
        // 如果启用了白名单但不匹配，继续检查其他规则而不是直接丢弃
    }

    // 2. 然后检查黑名单
    config_key = CONFIG_BLACKLIST_ENABLED;
    __u32 *blacklist_enabled = bpf_map_lookup_elem(&config_map, &config_key);
    if (blacklist_enabled && *blacklist_enabled) {
        if (check_blacklist(src_ip, dst_port, protocol)) {
            update_stats(0);
            return XDP_DROP; // 黑名单匹配，丢弃数据包
        }
    }

    // 3. 默认动作
    config_key = CONFIG_DEFAULT_ACTION;
    __u32 *default_action = bpf_map_lookup_elem(&config_map, &config_key);
    if (default_action && *default_action == 0) {
        update_stats(0);
        return XDP_DROP; // 默认丢弃
    } else {
        update_stats(1);
        // 默认允许后，继续检查流量限制
    }

check_rate:
    // 4. 流量限制检查（在防火墙规则之后执行）
    if (!check_rate_limit(packet_size)) {
        return XDP_DROP; // 超过流量限制，丢弃数据包
    }
    
    return XDP_PASS; // 所有检查通过
}

char _license[] SEC("license") = "GPL";