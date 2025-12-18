//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

// 使用内置的 bpf helper 函数
#include "libbpf/src/bpf_helpers.h"

// 网络字节序转换宏
#ifndef bpf_htons
#define bpf_htons(x) __builtin_bswap16(x)
#endif

#ifndef bpf_ntohs
#define bpf_ntohs(x) __builtin_bswap16(x)
#endif

// DNS端口
#define DNS_PORT 53

// IP列表模式
#define LIST_MODE_DISABLED  0  // 不启用黑白名单
#define LIST_MODE_WHITELIST 1  // 白名单模式：只允许列表中的IP
#define LIST_MODE_BLACKLIST 2  // 黑名单模式：拒绝列表中的IP

// IPv6地址结构
struct ipv6_addr {
    __u64 hi;
    __u64 lo;
};

// 统计信息结构
struct dns_stats {
    __u64 total_packets;
    __u64 dns_packets;
    __u64 dropped_packets;
    __u64 whitelist_allowed;
    __u64 whitelist_dropped;
    __u64 blacklist_dropped;
};

// 配置结构
struct filter_config {
    __u32 list_mode;  // LIST_MODE_*
};

// 统计信息Map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct dns_stats);
    __uint(max_entries, 1);
} stats_map SEC(".maps");

// 配置Map - 使用 Per-CPU Array 避免跨 CPU 缓存同步开销
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct filter_config);
    __uint(max_entries, 1);
} config_map SEC(".maps");

// IPv4白名单Map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 10000);
} ipv4_whitelist SEC(".maps");

// IPv4黑名单Map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 10000);
} ipv4_blacklist SEC(".maps");

// IPv6白名单Map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct ipv6_addr);
    __type(value, __u8);
    __uint(max_entries, 10000);
} ipv6_whitelist SEC(".maps");

// IPv6黑名单Map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct ipv6_addr);
    __type(value, __u8);
    __uint(max_entries, 10000);
} ipv6_blacklist SEC(".maps");

// 更新统计信息
static __always_inline void update_stats(__u32 is_dns, __u32 stat_type) {
    __u32 key = 0;
    struct dns_stats *stats = bpf_map_lookup_elem(&stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->total_packets, 1);
        if (is_dns) {
            __sync_fetch_and_add(&stats->dns_packets, 1);
        } else {
            __sync_fetch_and_add(&stats->dropped_packets, 1);
        }
        
        // 更新黑白名单统计
        // stat_type: 0=normal, 1=whitelist_allowed, 2=whitelist_dropped, 3=blacklist_dropped
        if (stat_type == 1) {
            __sync_fetch_and_add(&stats->whitelist_allowed, 1);
        } else if (stat_type == 2) {
            __sync_fetch_and_add(&stats->whitelist_dropped, 1);
        } else if (stat_type == 3) {
            __sync_fetch_and_add(&stats->blacklist_dropped, 1);
        }
    }
}

// 检查IPv4是否在白名单中
static __always_inline int check_ipv4_whitelist(__u32 addr) {
    __u8 *val = bpf_map_lookup_elem(&ipv4_whitelist, &addr);
    return val != NULL;
}

// 检查IPv4是否在黑名单中
static __always_inline int check_ipv4_blacklist(__u32 addr) {
    __u8 *val = bpf_map_lookup_elem(&ipv4_blacklist, &addr);
    return val != NULL;
}

// 检查IPv6是否在白名单中
static __always_inline int check_ipv6_whitelist(struct ipv6_addr *addr) {
    __u8 *val = bpf_map_lookup_elem(&ipv6_whitelist, addr);
    return val != NULL;
}

// 检查IPv6是否在黑名单中
static __always_inline int check_ipv6_blacklist(struct ipv6_addr *addr) {
    __u8 *val = bpf_map_lookup_elem(&ipv6_blacklist, addr);
    return val != NULL;
}

SEC("xdp")
int xdp_filter_dns(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // 解析以太网头
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }
    
    // 获取配置
    __u32 config_key = 0;
    struct filter_config *config = bpf_map_lookup_elem(&config_map, &config_key);
    __u32 list_mode = config ? config->list_mode : LIST_MODE_DISABLED;
    
    int is_ipv4 = 0;
    int is_ipv6 = 0;
    __u32 ipv4_addr = 0;
    struct ipv6_addr ipv6_addr = {0};
    
    // 处理IPv4
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        is_ipv4 = 1;
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end) {
            return XDP_PASS;
        }
        
        // 检查IP头长度
        if (ip->ihl < 5) {
            return XDP_PASS;
        }
        
        // 保存源IP地址
        ipv4_addr = ip->saddr;
        
        __u16 src_port = 0;
        __u16 dst_port = 0;
        
        // 解析传输层协议
        if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (void *)ip + (ip->ihl * 4);
            if ((void *)(udp + 1) > data_end) {
                return XDP_PASS;
            }
            src_port = bpf_ntohs(udp->source);
            dst_port = bpf_ntohs(udp->dest);
        } else if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
            if ((void *)(tcp + 1) > data_end) {
                return XDP_PASS;
            }
            src_port = bpf_ntohs(tcp->source);
            dst_port = bpf_ntohs(tcp->dest);
        } else {
            // 非TCP/UDP协议 不处理
            update_stats(0, 0);
            return XDP_PASS;
        }
        
        // 检查是否是DNS流量（端口53）
        int is_dns = (src_port == DNS_PORT || dst_port == DNS_PORT);
        
        // 黑白名单检查
        if (list_mode == LIST_MODE_WHITELIST) {
            // 白名单模式：只允许白名单中的IP
            if (!check_ipv4_whitelist(ipv4_addr)) {
                update_stats(0, 2); // whitelist_dropped
                return XDP_DROP;
            }
            if (is_dns) {
                update_stats(1, 1); // dns + whitelist_allowed
                return XDP_PASS;
            }
        } else if (list_mode == LIST_MODE_BLACKLIST) {
            // 黑名单模式：拒绝黑名单中的IP
            if (check_ipv4_blacklist(ipv4_addr)) {
                update_stats(0, 3); // blacklist_dropped
                return XDP_DROP;
            }
            if (is_dns) {
                update_stats(1, 0);
                return XDP_PASS;
            }
        } else {
            // 无黑白名单模式
            if (is_dns) {
                update_stats(1, 0);
                return XDP_PASS;
            }
        }
        
        // 非DNS流量丢弃
        update_stats(0, 0);
        return XDP_DROP;
    }
    // 处理IPv6
    else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        is_ipv6 = 1;
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end) {
            return XDP_PASS;
        }
        
        // 保存源IPv6地址
        #pragma unroll
        for (int i = 0; i < 8; i++) {
            if (i < 4) {
                ipv6_addr.hi = (ipv6_addr.hi << 16) | __builtin_bswap16(ip6->saddr.in6_u.u6_addr16[i]);
            } else {
                ipv6_addr.lo = (ipv6_addr.lo << 16) | __builtin_bswap16(ip6->saddr.in6_u.u6_addr16[i]);
            }
        }
        
        __u16 src_port = 0;
        __u16 dst_port = 0;
        __u8 next_hdr = ip6->nexthdr;
        
        // 解析传输层协议
        if (next_hdr == IPPROTO_UDP) {
            struct udphdr *udp = (void *)(ip6 + 1);
            if ((void *)(udp + 1) > data_end) {
                return XDP_PASS;
            }
            src_port = bpf_ntohs(udp->source);
            dst_port = bpf_ntohs(udp->dest);
        } else if (next_hdr == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)(ip6 + 1);
            if ((void *)(tcp + 1) > data_end) {
                return XDP_PASS;
            }
            src_port = bpf_ntohs(tcp->source);
            dst_port = bpf_ntohs(tcp->dest);
        } else {
            // 非TCP/UDP协议 不处理
            update_stats(0, 0);
            return XDP_PASS;
        }
        
        // 检查是否是DNS流量（端口53）
        int is_dns = (src_port == DNS_PORT || dst_port == DNS_PORT);
        
        // 黑白名单检查
        if (list_mode == LIST_MODE_WHITELIST) {
            // 白名单模式：只允许白名单中的IP
            if (!check_ipv6_whitelist(&ipv6_addr)) {
                update_stats(0, 2); // whitelist_dropped
                return XDP_DROP;
            }
            if (is_dns) {
                update_stats(1, 1); // dns + whitelist_allowed
                return XDP_PASS;
            }
        } else if (list_mode == LIST_MODE_BLACKLIST) {
            // 黑名单模式：拒绝黑名单中的IP
            if (check_ipv6_blacklist(&ipv6_addr)) {
                update_stats(0, 3); // blacklist_dropped
                return XDP_DROP;
            }
            if (is_dns) {
                update_stats(1, 0);
                return XDP_PASS;
            }
        } else {
            // 无黑白名单模式
            if (is_dns) {
                update_stats(1, 0);
                return XDP_PASS;
            }
        }
        
        // 非DNS流量丢弃
        update_stats(0, 0);
        return XDP_DROP;
    }
    
    // 其他协议直接放行
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
