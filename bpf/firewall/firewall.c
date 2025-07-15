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

// LVS DNAT规则Map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct dnat_rule);
    __uint(max_entries, MAX_RULES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} lvs_dnat_map SEC(".maps");

// 连接跟踪Map
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u64);  // client_ip:client_port 组合作为key
    __type(value, struct conn_track);
    __uint(max_entries, 10000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} conn_track_map SEC(".maps");

// 后端服务器Map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct backend_server);
    __uint(max_entries, MAX_RULES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} backend_map SEC(".maps");

// 服务配置Map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct service_config);
    __uint(max_entries, 100);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} service_map SEC(".maps");

// DNAT的规则结构
struct dnat_rule {
    __u32 original_ip;      // 原始目的IP (VIP)
    __u16 original_port;    // 原始目的端口
    __u32 target_ip;        // 转发目标IP
    __u16 target_port;      // 转发目标端口
    __u8 protocol;          // 协议类型
    __u8 enabled;           // 是否启用
};

// 连接跟踪结构
struct conn_track {
    __u32 client_ip;
    __u16 client_port;
    __u32 original_dest_ip;
    __u16 original_dest_port;
    __u32 target_ip;
    __u16 target_port;
    __u64 timestamp;
};

// 负载均衡后端服务器结构
struct backend_server {
    __u32 ip;
    __u16 port;
    __u8 weight;
    __u8 enabled;
};

// 服务配置结构
struct service_config {
    __u32 vip;
    __u16 vport;
    __u8 protocol;
    __u8 scheduler;     // 0=RR, 1=WRR, 2=LC
    __u32 backend_count;
    __u8 enabled;
    __u8 padding[3];
};

// 配置键定义
#define CONFIG_WHITELIST_ENABLED 0
#define CONFIG_BLACKLIST_ENABLED 1
#define CONFIG_DEFAULT_ACTION    2  // 0=DROP, 1=PASS
#define CONFIG_LVS_ENABLED       3  // 是否启用LVS功能

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

// 计算16位校验和
static __always_inline __u16 csum_fold(__u32 sum)
{
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (__u16)~sum;
}

// 更新IP校验和
static __always_inline void update_ip_checksum(struct iphdr *ip, 
                                              __u32 old_addr, __u32 new_addr)
{
    __u32 csum = (~ip->check) & 0xFFFF;
    csum += (~old_addr >> 16) & 0xFFFF;
    csum += (~old_addr) & 0xFFFF;
    csum += (new_addr >> 16) & 0xFFFF;
    csum += new_addr & 0xFFFF;
    ip->check = csum_fold(csum);
}

// 更新TCP校验和
static __always_inline void update_tcp_checksum(struct tcphdr *tcp,
                                               __u32 old_addr, __u32 new_addr,
                                               __u16 old_port, __u16 new_port)
{
    __u32 csum = (~tcp->check) & 0xFFFF;
    
    // 更新地址
    csum += (~old_addr >> 16) & 0xFFFF;
    csum += (~old_addr) & 0xFFFF;
    csum += (new_addr >> 16) & 0xFFFF;
    csum += new_addr & 0xFFFF;
    
    // 更新端口
    csum += (~old_port) & 0xFFFF;
    csum += new_port & 0xFFFF;
    
    tcp->check = csum_fold(csum);
}

// 更新UDP校验和
static __always_inline void update_udp_checksum(struct udphdr *udp,
                                               __u32 old_addr, __u32 new_addr,
                                               __u16 old_port, __u16 new_port)
{
    if (udp->check == 0) // UDP校验和为0表示不使用校验和
        return;
        
    __u32 csum = (~udp->check) & 0xFFFF;
    
    // 更新地址
    csum += (~old_addr >> 16) & 0xFFFF;
    csum += (~old_addr) & 0xFFFF;
    csum += (new_addr >> 16) & 0xFFFF;
    csum += new_addr & 0xFFFF;
    
    // 更新端口
    csum += (~old_port) & 0xFFFF;
    csum += new_port & 0xFFFF;
    
    udp->check = csum_fold(csum);
}

// LVS NAT模式处理入站流量
static __always_inline int handle_lvs_dnat(struct xdp_md *ctx, 
                                          __u32 src_ip, __u16 src_port,
                                          __u32 dst_ip, __u16 dst_port,
                                          __u8 protocol)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    
    // 验证以太网头部
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
        
    ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    
    // 查找DNAT规则 - 减少循环次数以降低复杂度
    struct dnat_rule *rule;
    __u32 key;
    
    #pragma unroll
    for (int i = 0; i < 30; i++) {  // 进一步减少到30个规则
        key = i;
        rule = bpf_map_lookup_elem(&lvs_dnat_map, &key);
        if (!rule || !rule->enabled)
            continue;
            
        if (rule->original_ip == dst_ip && 
            rule->original_port == dst_port &&
            rule->protocol == protocol) {
            
            // 记录连接跟踪
            __u64 conn_key = ((__u64)src_ip << 32) | src_port;
            struct conn_track *existing_conn = bpf_map_lookup_elem(&conn_track_map, &conn_key);
            if (!existing_conn) {
                // 直接在map中创建连接跟踪记录
                struct conn_track zero_conn = {};
                if (bpf_map_update_elem(&conn_track_map, &conn_key, &zero_conn, BPF_NOEXIST) == 0) {
                    struct conn_track *new_conn = bpf_map_lookup_elem(&conn_track_map, &conn_key);
                    if (new_conn) {
                        new_conn->client_ip = src_ip;
                        new_conn->client_port = src_port;
                        new_conn->original_dest_ip = dst_ip;
                        new_conn->original_dest_port = dst_port;
                        new_conn->target_ip = rule->target_ip;
                        new_conn->target_port = rule->target_port;
                        new_conn->timestamp = bpf_ktime_get_ns();
                    }
                }
            }
            
            // 修改目的地址
            __u32 old_ip = ip->daddr;
            ip->daddr = rule->target_ip;
            
            // 计算IP头部长度并检查边界
            void *ip_end = (void *)ip + (ip->ihl * 4);
            if (ip_end > data_end)
                return XDP_PASS;
            
            if (protocol == IPPROTO_TCP) {
                struct tcphdr *tcp = (struct tcphdr *)ip_end;
                if ((void *)(tcp + 1) > data_end)
                    return XDP_PASS;
                    
                __u16 old_port = tcp->dest;
                tcp->dest = bpf_htons(rule->target_port);
                update_tcp_checksum(tcp, old_ip, rule->target_ip, old_port, tcp->dest);
                
            } else if (protocol == IPPROTO_UDP) {
                struct udphdr *udp = (struct udphdr *)ip_end;
                if ((void *)(udp + 1) > data_end)
                    return XDP_PASS;
                    
                __u16 old_port = udp->dest;
                udp->dest = bpf_htons(rule->target_port);
                update_udp_checksum(udp, old_ip, rule->target_ip, old_port, udp->dest);
            }
            
            // 更新IP校验和
            update_ip_checksum(ip, old_ip, rule->target_ip);
            
            return XDP_PASS; // 转发修改后的数据包
        }
    }
    
    return XDP_PASS; // 没有匹配的规则，正常通过
}

// LVS NAT模式处理返回流量
static __always_inline int handle_lvs_snat(struct xdp_md *ctx,
                                          __u32 src_ip, __u16 src_port,
                                          __u32 dst_ip, __u16 dst_port,
                                          __u8 protocol)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    
    // 验证以太网头部
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
        
    ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    
    // 查找连接跟踪记录
    __u64 conn_key = ((__u64)dst_ip << 32) | dst_port;
    struct conn_track *conn = bpf_map_lookup_elem(&conn_track_map, &conn_key);
    
    if (!conn)
        return XDP_PASS; // 没有找到对应的连接记录
    
    // 检查是否是对应的返回流量
    if (conn->target_ip != src_ip || conn->target_port != src_port)
        return XDP_PASS;
    
    // 恢复原始的源地址
    __u32 old_ip = ip->saddr;
    ip->saddr = conn->original_dest_ip;
    
    // 计算IP头部长度并检查边界
    void *ip_end = (void *)ip + (ip->ihl * 4);
    if (ip_end > data_end)
        return XDP_PASS;
    
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)ip_end;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
            
        __u16 old_port = tcp->source;
        tcp->source = bpf_htons(conn->original_dest_port);
        update_tcp_checksum(tcp, old_ip, conn->original_dest_ip, old_port, tcp->source);
        
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)ip_end;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
            
        __u16 old_port = udp->source;
        udp->source = bpf_htons(conn->original_dest_port);
        update_udp_checksum(udp, old_ip, conn->original_dest_ip, old_port, udp->source);
    }
    
    // 更新IP校验和
    update_ip_checksum(ip, old_ip, conn->original_dest_ip);
    
    return XDP_PASS;
}

SEC("xdp")
int xdp_firewall_with_lvs(struct xdp_md *ctx)
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

    // 防火墙过滤逻辑
    __u32 config_key = CONFIG_WHITELIST_ENABLED;
    __u32 *whitelist_enabled = bpf_map_lookup_elem(&config_map, &config_key);
    
    // 1. 首先检查白名单 (优先级最高)
    if (whitelist_enabled && *whitelist_enabled) {
        if (check_whitelist(src_ip, src_port, protocol)) {
            update_stats(1);
            goto lvs_process; // 白名单通过，继续LVS处理
        }
    }

    // 2. 然后检查黑名单
    config_key = CONFIG_BLACKLIST_ENABLED;
    __u32 *blacklist_enabled = bpf_map_lookup_elem(&config_map, &config_key);
    if (blacklist_enabled && *blacklist_enabled) {
        if (check_blacklist(src_ip, src_port, protocol)) {
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
        // 继续LVS处理
    }

lvs_process:
    // LVS NAT处理（在防火墙逻辑后面）
    config_key = CONFIG_LVS_ENABLED;
    __u32 *lvs_enabled = bpf_map_lookup_elem(&config_map, &config_key);
    
    if (lvs_enabled && *lvs_enabled) {
        // 1. 检查是否是需要DNAT的入站流量
        handle_lvs_dnat(ctx, src_ip, src_port, dst_ip, dst_port, protocol);
        
        // 2. 检查是否是返回流量需要SNAT
        handle_lvs_snat(ctx, src_ip, src_port, dst_ip, dst_port, protocol);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";