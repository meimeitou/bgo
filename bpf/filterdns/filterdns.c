//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
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

// 统计信息结构
struct dns_stats {
    __u64 total_packets;
    __u64 dns_packets;
    __u64 dropped_packets;
};

// 统计信息Map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct dns_stats);
    __uint(max_entries, 1);
} stats_map SEC(".maps");

// 更新统计信息
static __always_inline void update_stats(__u32 is_dns) {
    __u32 key = 0;
    struct dns_stats *stats = bpf_map_lookup_elem(&stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->total_packets, 1);
        if (is_dns) {
            __sync_fetch_and_add(&stats->dns_packets, 1);
        } else {
            __sync_fetch_and_add(&stats->dropped_packets, 1);
        }
    }
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
    
    // 只处理IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }
    
    // 解析IP头
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }
    
    // 检查IP头长度
    if (ip->ihl < 5) {
        return XDP_PASS;
    }
    
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
        update_stats(0);
        return XDP_PASS;
    }
    
    // 检查是否是DNS流量（端口53）
    if (src_port == DNS_PORT) {
        update_stats(1);
        return XDP_PASS;
    }
    
    // 其他流量丢弃
    update_stats(0);
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
