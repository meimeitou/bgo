//go:build ignore

#include "common/common.h"
#include "firewall_common.h"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/pkt_cls.h>
#include "libbpf/src/bpf_endian.h"

// Protocol numbers
#define IPPROTO_ICMP 1
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

// 网络字节序转换宏
#ifndef bpf_htons
#define bpf_htons(x) __builtin_bswap16(x)
#endif

#ifndef bpf_ntohs
#define bpf_ntohs(x) __builtin_bswap16(x)
#endif

#ifndef bpf_htonl
#define bpf_htonl(x) __builtin_bswap32(x)
#endif

#ifndef bpf_ntohl
#define bpf_ntohl(x) __builtin_bswap32(x)
#endif

// Rule types
#define RULE_TYPE_WHITELIST 0
#define RULE_TYPE_BLACKLIST 1

// Actions
#define ACTION_ALLOW 0
#define ACTION_DENY 1

// Directions
#define DIRECTION_INGRESS 0
#define DIRECTION_EGRESS 1

// LVS 相关结构定义
// DNAT 规则结构
struct dnat_rule {
    __u32 original_ip;      // 原始目的IP (VIP)
    __u16 original_port;    // 原始目的端口
    __u16 _pad1;            // 填充字节，确保对齐
    __u32 target_ip;        // 转发目标IP
    __u16 target_port;      // 转发目标端口
    __u8 protocol;          // 协议类型
    __u8 enabled;           // 是否启用
} __attribute__((packed));

// 连接跟踪结构
struct conn_track {
    __u32 client_ip;
    __u16 client_port;
    __u16 _pad1;
    __u32 original_dest_ip;
    __u16 original_dest_port;
    __u16 _pad2;
    __u32 target_ip;
    __u16 target_port;
    __u16 _pad3;
    __u64 timestamp;
} __attribute__((packed));

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

// ============ LVS 相关 Maps ============

// LVS DNAT 规则映射
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_RULES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);
    __type(value, struct dnat_rule);
} lvs_dnat_map SEC(".maps");

// LVS 连接跟踪映射 (使用 LRU 自动清理旧连接)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u64);  // (client_ip << 32) | client_port
    __type(value, struct conn_track);
} conn_track_map SEC(".maps");

// LVS 反向连接映射 (用于SNAT查找: (target_ip << 32) | client_port -> client_ip)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u64);  // (target_ip << 32) | client_port
    __type(value, __u32);  // client_ip
} conn_reverse_map SEC(".maps");

// LVS 调试计数器
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);
    __type(value, __u64);
} debug_counters SEC(".maps");

// LVS 调试事件 Ring Buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} debug_map SEC(".maps");

// 调试信息结构
struct debug_info {
    __u64 timestamp;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 stage;
    __u8 rule_index;
    __u8 result;
};

// 调试计数器索引
#define DEBUG_COUNTER_TOTAL_PACKETS 0
#define DEBUG_COUNTER_LVS_ENABLED 1
#define DEBUG_COUNTER_DNAT_LOOKUP 2
#define DEBUG_COUNTER_DNAT_RULE_CHECK 3
#define DEBUG_COUNTER_DNAT_MATCH 4
#define DEBUG_COUNTER_SNAT_LOOKUP 5
#define DEBUG_COUNTER_SNAT_MATCH 6
#define DEBUG_COUNTER_CONN_CREATED 7
#define DEBUG_COUNTER_CONN_REUSED 8

// ============ 辅助函数 ============

// 增加调试计数器
static __always_inline void increment_debug_counter(__u32 index) {
    __u64 *counter = bpf_map_lookup_elem(&debug_counters, &index);
    if (counter) {
        __sync_fetch_and_add(counter, 1);
    }
}

// 记录调试信息到 Ring Buffer
static __always_inline void log_debug_info(__u32 src_ip, __u32 dst_ip,
                                          __u16 src_port, __u16 dst_port,
                                          __u8 protocol, __u8 stage,
                                          __u8 rule_index, __u8 result) {
    struct debug_info *info = bpf_ringbuf_reserve(&debug_map, sizeof(struct debug_info), 0);
    if (!info) return;
    
    info->timestamp = bpf_ktime_get_ns();
    info->src_ip = src_ip;
    info->dst_ip = dst_ip;
    info->src_port = src_port;
    info->dst_port = dst_port;
    info->protocol = protocol;
    info->stage = stage;
    info->rule_index = rule_index;
    info->result = result;
    
    bpf_ringbuf_submit(info, 0);
}

// ============ 校验和计算函数 ============

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

// ============ LVS 处理函数 ============

// LVS NAT模式处理入站流量 (DNAT)
static __always_inline int handle_lvs_dnat(struct __sk_buff *skb,
                                          __u32 src_ip, __u16 src_port,
                                          __u32 dst_ip, __u16 dst_port,
                                          __u8 protocol)
{
    // 查找DNAT规则
    struct dnat_rule *rule;
    __u32 rule_key;
    
    // 记录DNAT查找
    increment_debug_counter(DEBUG_COUNTER_DNAT_LOOKUP);
    
    #pragma unroll
    for (int i = 0; i < 30; i++) {
        rule_key = i;
        rule = bpf_map_lookup_elem(&lvs_dnat_map, &rule_key);
        if (!rule || !rule->enabled)
            continue;
            
        // 记录规则检查
        increment_debug_counter(DEBUG_COUNTER_DNAT_RULE_CHECK);
        
        // 临时调试：记录第一次检查时的实际值
        if (i == 0) {
            bpf_printk("DNAT: dst_ip=0x%x, rule->original_ip=0x%x", dst_ip, rule->original_ip);
            bpf_printk("DNAT: dst_port=%u, rule->original_port=%u", dst_port, rule->original_port);
            bpf_printk("DNAT: protocol=%u, rule->protocol=%u", protocol, rule->protocol);
            log_debug_info(dst_ip, rule->original_ip, dst_port, rule->original_port, protocol, 10, i, rule->protocol);
        }
            
        // 检查规则是否匹配
        if (rule->original_ip == dst_ip && 
            rule->original_port == dst_port &&
            rule->protocol == protocol) {
            
            // 记录DNAT匹配
            increment_debug_counter(DEBUG_COUNTER_DNAT_MATCH);
            log_debug_info(src_ip, dst_ip, src_port, dst_port, protocol, 2, i, 1);
            bpf_printk("DNAT Match: will change dst to 0x%x:%u", rule->target_ip, rule->target_port);
            
            // 创建或查找连接跟踪
            __u64 conn_key = ((__u64)src_ip << 32) | src_port;
            struct conn_track *existing_conn = bpf_map_lookup_elem(&conn_track_map, &conn_key);
            if (!existing_conn) {
                // 记录新连接创建
                increment_debug_counter(DEBUG_COUNTER_CONN_CREATED);
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
            
            // 始终创建或更新反向映射用于SNAT查找
            // key = (target_ip << 32) | client_port
            __u64 reverse_key = ((__u64)rule->target_ip << 32) | src_port;
            bpf_map_update_elem(&conn_reverse_map, &reverse_key, &src_ip, BPF_ANY);
            bpf_printk("DNAT: reverse map target_ip=0x%x port=%u", rule->target_ip, src_port);
            
            // 使用 bpf_skb_store_bytes 修改目的IP地址（DNAT）
            __u32 new_dst_ip = rule->target_ip;
            __u32 ip_offset = sizeof(struct ethhdr) + offsetof(struct iphdr, daddr);
            if (bpf_skb_store_bytes(skb, ip_offset, &new_dst_ip, sizeof(new_dst_ip), 0) < 0) {
                return 0;
            }
            
            // Full NAT: 同时修改源IP地址为LVS服务器的IP，这样后端回复时会发送到LVS服务器
            // 这样就不需要修改后端的网关了
            // 硬编码 LVS 服务器 IP: 192.168.63.10 (小端序: 0x0a3fa8c0)
            __u32 new_src_ip = 0x0a3fa8c0;  // 192.168.63.10
            __u32 src_ip_offset = sizeof(struct ethhdr) + offsetof(struct iphdr, saddr);
            if (bpf_skb_store_bytes(skb, src_ip_offset, &new_src_ip, sizeof(new_src_ip), 0) < 0) {
                return 0;
            }
            
            // 修改目的端口并更新校验和
            __u16 new_dst_port = bpf_htons(rule->target_port);
            __u32 l4_offset = sizeof(struct ethhdr) + sizeof(struct iphdr);
            
            if (protocol == IPPROTO_TCP) {
                __u32 port_offset = l4_offset + offsetof(struct tcphdr, dest);
                if (bpf_skb_store_bytes(skb, port_offset, &new_dst_port, sizeof(new_dst_port), 0) < 0) {
                    return 0;
                }
                
                // 使用 bpf_l4_csum_replace 更新TCP校验和
                __u32 csum_offset = l4_offset + offsetof(struct tcphdr, check);
                bpf_l4_csum_replace(skb, csum_offset, src_ip, new_src_ip, BPF_F_PSEUDO_HDR | sizeof(__u32));
                bpf_l4_csum_replace(skb, csum_offset, dst_ip, new_dst_ip, BPF_F_PSEUDO_HDR | sizeof(__u32));
                bpf_l4_csum_replace(skb, csum_offset, dst_port, new_dst_port, sizeof(__u16));
                
            } else if (protocol == IPPROTO_UDP) {
                __u32 port_offset = l4_offset + offsetof(struct udphdr, dest);
                if (bpf_skb_store_bytes(skb, port_offset, &new_dst_port, sizeof(new_dst_port), 0) < 0) {
                    return 0;
                }
                
                // 使用 bpf_l4_csum_replace 更新UDP校验和
                __u32 csum_offset = l4_offset + offsetof(struct udphdr, check);
                bpf_l4_csum_replace(skb, csum_offset, src_ip, new_src_ip, BPF_F_PSEUDO_HDR | sizeof(__u32));
                bpf_l4_csum_replace(skb, csum_offset, dst_ip, new_dst_ip, BPF_F_PSEUDO_HDR | sizeof(__u32));
                bpf_l4_csum_replace(skb, csum_offset, dst_port, new_dst_port, sizeof(__u16));
            }
            
            // 使用 bpf_l3_csum_replace 更新IP校验和（源IP和目标IP都变了）
            __u32 ip_csum_offset = sizeof(struct ethhdr) + offsetof(struct iphdr, check);
            bpf_l3_csum_replace(skb, ip_csum_offset, src_ip, new_src_ip, sizeof(__u32));
            bpf_l3_csum_replace(skb, ip_csum_offset, dst_ip, new_dst_ip, sizeof(__u32));
            
            bpf_printk("DNAT Complete: new src=0x%x, new dst=0x%x", new_src_ip, new_dst_ip);
            
            return 1; // 处理了 DNAT
        }
    }
    
    return 0; // 没有匹配的规则
}

// LVS DNAT with redirect - 在 Ingress 直接转发到后端
// 使用 bpf_redirect 绕过路由决策
static __always_inline int handle_lvs_dnat_redirect(struct __sk_buff *skb,
                                                     __u32 src_ip, __u16 src_port,
                                                     __u32 dst_ip, __u16 dst_port,
                                                     __u8 protocol)
{
    // 查找DNAT规则
    struct dnat_rule *rule;
    __u32 rule_key;
    
    // 记录DNAT查找
    increment_debug_counter(DEBUG_COUNTER_DNAT_LOOKUP);
    
    #pragma unroll
    for (int i = 0; i < 30; i++) {
        rule_key = i;
        rule = bpf_map_lookup_elem(&lvs_dnat_map, &rule_key);
        if (!rule || !rule->enabled)
            continue;
            
        // 记录规则检查
        increment_debug_counter(DEBUG_COUNTER_DNAT_RULE_CHECK);
        
        // 调试：打印第一条规则的详细信息
        if (i == 0) {
            bpf_printk("Rule[0]: original_ip=0x%x, original_port=%u, proto=%u", 
                      rule->original_ip, rule->original_port, rule->protocol);
            bpf_printk("Packet: dst_ip=0x%x, dst_port=%u, proto=%u", 
                      dst_ip, dst_port, protocol);
        }
        
        // 检查规则是否匹配
        if (rule->original_ip != dst_ip || 
            rule->original_port != dst_port ||
            rule->protocol != protocol) {
            continue;
        }
        
        // 匹配成功
        increment_debug_counter(DEBUG_COUNTER_DNAT_MATCH);
        
        // 创建连接跟踪
        __u64 conn_key = ((__u64)src_ip << 32) | src_port;
        struct conn_track *existing_conn = bpf_map_lookup_elem(&conn_track_map, &conn_key);
        if (!existing_conn) {
            increment_debug_counter(DEBUG_COUNTER_CONN_CREATED);
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
        
        // 创建反向映射
        __u64 reverse_key = ((__u64)rule->target_ip << 32) | src_port;
        bpf_map_update_elem(&conn_reverse_map, &reverse_key, &src_ip, BPF_ANY);
        
        // 修改目的IP
        __u32 new_dst_ip = rule->target_ip;
        __u32 ip_offset = sizeof(struct ethhdr) + offsetof(struct iphdr, daddr);
        if (bpf_skb_store_bytes(skb, ip_offset, &new_dst_ip, sizeof(new_dst_ip), 0) < 0) {
            return 0;
        }
        
        // 修改源IP (Full NAT)
        __u32 new_src_ip = 0x0a3fa8c0;  // 192.168.63.10
        __u32 src_ip_offset = sizeof(struct ethhdr) + offsetof(struct iphdr, saddr);
        if (bpf_skb_store_bytes(skb, src_ip_offset, &new_src_ip, sizeof(new_src_ip), 0) < 0) {
            return 0;
        }
        
        // 修改目的端口
        __u16 new_dst_port = bpf_htons(rule->target_port);
        __u32 l4_offset = sizeof(struct ethhdr) + sizeof(struct iphdr);
        
        if (protocol == IPPROTO_TCP) {
            __u32 port_offset = l4_offset + offsetof(struct tcphdr, dest);
            if (bpf_skb_store_bytes(skb, port_offset, &new_dst_port, sizeof(new_dst_port), 0) < 0) {
                return 0;
            }
            
            __u32 csum_offset = l4_offset + offsetof(struct tcphdr, check);
            bpf_l4_csum_replace(skb, csum_offset, src_ip, new_src_ip, BPF_F_PSEUDO_HDR | sizeof(__u32));
            bpf_l4_csum_replace(skb, csum_offset, dst_ip, new_dst_ip, BPF_F_PSEUDO_HDR | sizeof(__u32));
            bpf_l4_csum_replace(skb, csum_offset, dst_port, new_dst_port, sizeof(__u16));
            
        } else if (protocol == IPPROTO_UDP) {
            __u32 port_offset = l4_offset + offsetof(struct udphdr, dest);
            if (bpf_skb_store_bytes(skb, port_offset, &new_dst_port, sizeof(new_dst_port), 0) < 0) {
                return 0;
            }
            
            __u32 csum_offset = l4_offset + offsetof(struct udphdr, check);
            bpf_l4_csum_replace(skb, csum_offset, src_ip, new_src_ip, BPF_F_PSEUDO_HDR | sizeof(__u32));
            bpf_l4_csum_replace(skb, csum_offset, dst_ip, new_dst_ip, BPF_F_PSEUDO_HDR | sizeof(__u32));
            bpf_l4_csum_replace(skb, csum_offset, dst_port, new_dst_port, sizeof(__u16));
        }
        
        // 更新IP校验和
        __u32 ip_csum_offset = sizeof(struct ethhdr) + offsetof(struct iphdr, check);
        bpf_l3_csum_replace(skb, ip_csum_offset, src_ip, new_src_ip, sizeof(__u32));
        bpf_l3_csum_replace(skb, ip_csum_offset, dst_ip, new_dst_ip, sizeof(__u32));
        
        // 返回 TC_ACT_OK 让数据包继续路由流程
        return TC_ACT_OK;
    }
    
    return 0; // 没有匹配的规则
}

// Full NAT 模式：SNAT 处理返回流量
// 返回流量: 后端:8080 → VIP:客户端端口
// 转换为: VIP:80 → 客户端:客户端端口
static __always_inline int handle_lvs_snat(struct __sk_buff *skb,
                                          __u32 src_ip, __u16 src_port,
                                          __u32 dst_ip, __u16 dst_port,
                                          __u8 protocol)
{
    // 记录SNAT查找
    increment_debug_counter(DEBUG_COUNTER_SNAT_LOOKUP);
    log_debug_info(src_ip, dst_ip, src_port, dst_port, protocol, 3, 0, 0);
    
    // 使用反向映射查找客户端IP
    // key = (src_ip << 32) | dst_port
    // src_ip = 后端IP (target_ip), dst_port = 客户端端口
    __u64 reverse_key = ((__u64)src_ip << 32) | dst_port;
    __u32 *client_ip_ptr = bpf_map_lookup_elem(&conn_reverse_map, &reverse_key);
    
    bpf_printk("SNAT: src_ip=0x%x dst_port=%u", src_ip, dst_port);
    
    if (!client_ip_ptr) {
        bpf_printk("SNAT: No reverse mapping found");
        return 0; // 没有找到反向映射
    }
    
    __u32 client_ip = *client_ip_ptr;
    bpf_printk("SNAT: Found client_ip=0x%x", client_ip);
    
    // 现在用客户端IP和端口查找完整的连接跟踪信息
    __u64 conn_key = ((__u64)client_ip << 32) | dst_port;
    struct conn_track *conn = bpf_map_lookup_elem(&conn_track_map, &conn_key);
    
    if (!conn) {
        return 0; // 没有找到连接跟踪记录
    }
    
    // 验证这是对应的返回流量
    if (conn->target_ip != src_ip || conn->target_port != src_port) {
        return 0;
    }
    
    // 记录SNAT匹配
    increment_debug_counter(DEBUG_COUNTER_SNAT_MATCH);
    log_debug_info(src_ip, dst_ip, src_port, dst_port, protocol, 4, 0, 1);
    
    // 恢复原始的源地址和端口 (VIP:80)
    __u32 new_src_ip = conn->original_dest_ip;
    __u16 new_src_port = bpf_htons(conn->original_dest_port);
    
    // 修改源IP
    __u32 src_ip_offset = sizeof(struct ethhdr) + offsetof(struct iphdr, saddr);
    if (bpf_skb_store_bytes(skb, src_ip_offset, &new_src_ip, sizeof(new_src_ip), 0) < 0) {
        return 0;
    }
    
    // 修改目标IP为客户端IP
    __u32 new_dst_ip = conn->client_ip;
    __u32 dst_ip_offset = sizeof(struct ethhdr) + offsetof(struct iphdr, daddr);
    if (bpf_skb_store_bytes(skb, dst_ip_offset, &new_dst_ip, sizeof(new_dst_ip), 0) < 0) {
        return 0;
    }
    
    __u32 l4_offset = sizeof(struct ethhdr) + sizeof(struct iphdr);
    
    if (protocol == IPPROTO_TCP) {
        __u32 src_port_offset = l4_offset + offsetof(struct tcphdr, source);
        if (bpf_skb_store_bytes(skb, src_port_offset, &new_src_port, sizeof(new_src_port), 0) < 0) {
            return 0;
        }
        
        // 使用 bpf_l4_csum_replace 更新TCP校验和（源IP、目标IP、源端口都变了）
        __u32 csum_offset = l4_offset + offsetof(struct tcphdr, check);
        bpf_l4_csum_replace(skb, csum_offset, src_ip, new_src_ip, BPF_F_PSEUDO_HDR | sizeof(__u32));
        bpf_l4_csum_replace(skb, csum_offset, dst_ip, new_dst_ip, BPF_F_PSEUDO_HDR | sizeof(__u32));
        bpf_l4_csum_replace(skb, csum_offset, src_port, new_src_port, sizeof(__u16));
        
    } else if (protocol == IPPROTO_UDP) {
        __u32 src_port_offset = l4_offset + offsetof(struct udphdr, source);
        if (bpf_skb_store_bytes(skb, src_port_offset, &new_src_port, sizeof(new_src_port), 0) < 0) {
            return 0;
        }
        
        // 使用 bpf_l4_csum_replace 更新UDP校验和（源IP、目标IP、源端口都变了）
        __u32 csum_offset = l4_offset + offsetof(struct udphdr, check);
        bpf_l4_csum_replace(skb, csum_offset, src_ip, new_src_ip, BPF_F_PSEUDO_HDR | sizeof(__u32));
        bpf_l4_csum_replace(skb, csum_offset, dst_ip, new_dst_ip, BPF_F_PSEUDO_HDR | sizeof(__u32));
        bpf_l4_csum_replace(skb, csum_offset, src_port, new_src_port, sizeof(__u16));
    }
    
    // 使用 bpf_l3_csum_replace 更新IP校验和（源IP和目标IP都变了）
    __u32 ip_csum_offset = sizeof(struct ethhdr) + offsetof(struct iphdr, check);
    bpf_l3_csum_replace(skb, ip_csum_offset, src_ip, new_src_ip, sizeof(__u32));
    bpf_l3_csum_replace(skb, ip_csum_offset, dst_ip, new_dst_ip, sizeof(__u32));
    
    return 1; // 处理了 SNAT
}

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
// 在check_whitelist_rules函数中：
    __u32 i = 0;
    if (i < MAX_RULES) {
        if (direction == DIRECTION_INGRESS) {
            rule = bpf_map_lookup_elem(&tc_ingress_whitelist, &i);
        } else {
            rule = bpf_map_lookup_elem(&tc_egress_whitelist, &i);
        }
        
        if (rule) {
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
        }else{
            return TC_ACT_OK;
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
   
    // 在check_blacklist_rules函数中：
    // Iterate through blacklist rules - simplified to avoid infinite loop
    __u32 i = 0;
    if (i < MAX_RULES) {
        if (direction == DIRECTION_INGRESS) {
            rule = bpf_map_lookup_elem(&tc_ingress_blacklist, &i);
        } else {
            rule = bpf_map_lookup_elem(&tc_egress_blacklist, &i);
        }

        if (rule) {
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
        } else {
            return TC_ACT_OK; // No rule found, default allow
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
    
    // ============ LVS 处理 ============
    // 处理 LVS (在防火墙规则之前，优先级更高)
    
    // 入站流量: 处理 DNAT (客户端发来的流量) 和 SNAT (后端返回的流量)
    if (direction == DIRECTION_INGRESS) {
        bpf_printk("TC Ingress: src_ip=0x%x, dst_ip=0x%x", src_ip, dst_ip);
        bpf_printk("TC Ingress: src_port=%u, dst_port=%u, proto=%u", src_port, dst_port, packet_protocol);
        
        if (packet_protocol == IPPROTO_TCP || packet_protocol == IPPROTO_UDP) {
            // 先尝试 SNAT (处理后端返回的流量)
            int snat_result = handle_lvs_snat(skb, src_ip, src_port, dst_ip, dst_port, packet_protocol);
            if (snat_result) {
                // SNAT成功，更新统计并允许通过
                if (stats) {
                    __sync_fetch_and_add(&stats->allowed_packets, 1);
                    __sync_fetch_and_add(&stats->ingress_packets, 1);
                    __sync_fetch_and_add(&stats->total_packets, 1);
                }
                return TC_ACT_OK;
            }
            
            // 如果不是返回流量，尝试 DNAT (处理客户端发来的流量)
            // 使用 redirect 版本的 DNAT，直接转发到后端
            bpf_printk("Trying DNAT: dst_ip=0x%x, dst_port=%u", dst_ip, dst_port);
            int dnat_result = handle_lvs_dnat_redirect(skb, src_ip, src_port, dst_ip, dst_port, packet_protocol);
            bpf_printk("DNAT result=%d", dnat_result);
            if (dnat_result) {
                // DNAT成功并已重定向，无需继续处理
                if (stats) {
                    __sync_fetch_and_add(&stats->allowed_packets, 1);
                    __sync_fetch_and_add(&stats->ingress_packets, 1);
                    __sync_fetch_and_add(&stats->total_packets, 1);
                }
                // 返回 TC_ACT_REDIRECT 或其他redirect返回值
                return dnat_result;
            }
        }
    }
    
    // 出站流量: 只处理 SNAT (后端 -> 客户端的返回流量)
    if (direction == DIRECTION_EGRESS) {
        bpf_printk("TC Egress: src_ip=0x%x, dst_ip=0x%x", src_ip, dst_ip);
        bpf_printk("TC Egress: src_port=%u, dst_port=%u, proto=%u", src_port, dst_port, packet_protocol);
        if (packet_protocol == IPPROTO_TCP || packet_protocol == IPPROTO_UDP) {
            // 尝试 SNAT (后端 -> 客户端的返回流量)
            int snat_result = handle_lvs_snat(skb, src_ip, src_port, dst_ip, dst_port, packet_protocol);
            if (snat_result) {
                // SNAT成功，更新统计并允许通过
                if (stats) {
                    __sync_fetch_and_add(&stats->allowed_packets, 1);
                    __sync_fetch_and_add(&stats->egress_packets, 1);
                    __sync_fetch_and_add(&stats->total_packets, 1);
                }
                return TC_ACT_OK;
            }
        }
    }
    
    // ============ 防火墙规则检查 ============
    // 如果 LVS 没有处理，则继续执行防火墙规则检查
    
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