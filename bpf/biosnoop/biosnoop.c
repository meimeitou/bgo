//go:build ignore

#include "common/common.h"
#include <linux/bpf.h>

// Define the tracepoint context structure for block events
// This matches the kernel's tracepoint structure for block_rq_issue/block_rq_complete
struct block_rq_ctx {
    u64 __do_not_use__; // First 8 bytes are not used
    u32 dev;
    u64 sector;
    u32 nr_sector;
    u32 __data_len;
    char rwbs[8];
    char comm[16];
    // ... other fields we don't need
};

// Data structures for tracking I/O requests
struct start_req_t {
    u64 ts;         // timestamp when I/O started
    u64 data_len;   // I/O data length
};

struct val_t {
    u64 ts;         // queued timestamp
    u32 pid;        // process ID
    char name[16];  // process name (TASK_COMM_LEN)
};

// Hash key for tracking requests
struct hash_key {
    u32 dev;        // device ID
    u32 rwflag;     // read/write flag
    u64 sector;     // sector number
};

// Event data sent to userspace
struct data_t {
    u32 pid;        // process ID
    u32 dev;        // device ID
    u64 rwflag;     // read/write flag (0=read, 1=write)
    u64 delta;      // I/O latency in nanoseconds
    u64 qdelta;     // queue time in nanoseconds
    u64 sector;     // sector number
    u64 len;        // I/O length in bytes
    u64 ts;         // timestamp in microseconds
    char name[16];  // process name
};

// BPF maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct hash_key);
    __type(value, struct start_req_t);
} start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct hash_key);
    __type(value, struct val_t);
} infobyreq SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

// Helper function to determine if operation is write
static __always_inline int is_write_op(char *rwbs) {
    // Check if the first character in rwbs is 'W' (write)
    return (rwbs[0] == 'W' || rwbs[0] == 'w');
}

// Trace block I/O issue
SEC("tracepoint/block/block_rq_issue")
int trace_block_rq_issue(struct block_rq_ctx *ctx) {
    struct hash_key key = {};
    struct start_req_t start_req = {};
    struct val_t val = {};
    
    key.dev = ctx->dev;
    key.rwflag = is_write_op(ctx->rwbs);
    key.sector = ctx->sector;
    
    // Record start time and data length
    start_req.ts = bpf_ktime_get_ns();
    start_req.data_len = ctx->nr_sector * 512; // Convert sectors to bytes
    
    // Get process info
    val.pid = bpf_get_current_pid_tgid() >> 32;
    val.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&val.name, sizeof(val.name));
    
    bpf_map_update_elem(&start, &key, &start_req, BPF_ANY);
    bpf_map_update_elem(&infobyreq, &key, &val, BPF_ANY);
    
    return 0;
}

// Trace block I/O completion
SEC("tracepoint/block/block_rq_complete")
int trace_block_rq_complete(struct block_rq_ctx *ctx) {
    struct hash_key key = {};
    struct start_req_t *startp;
    struct val_t *valp;
    struct data_t data = {};
    u64 ts;
    
    key.dev = ctx->dev;
    key.rwflag = is_write_op(ctx->rwbs);
    key.sector = ctx->sector;
    
    // Get start time
    startp = bpf_map_lookup_elem(&start, &key);
    if (!startp)
        return 0;
        
    ts = bpf_ktime_get_ns();
    data.delta = ts - startp->ts;
    data.ts = ts / 1000;  // convert to microseconds
    data.len = startp->data_len;
    
    // Get process info
    valp = bpf_map_lookup_elem(&infobyreq, &key);
    if (valp) {
        data.pid = valp->pid;
        data.qdelta = startp->ts - valp->ts;  // queue time
        __builtin_memcpy(data.name, valp->name, sizeof(data.name));
    } else {
        data.name[0] = '?';
        data.name[1] = 0;
        data.qdelta = 0;
        data.pid = 0;
    }
    
    data.dev = key.dev;
    data.rwflag = key.rwflag;
    data.sector = key.sector;
    
    // Send event to userspace
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    
    // Clean up maps
    bpf_map_delete_elem(&start, &key);
    bpf_map_delete_elem(&infobyreq, &key);
    
    return 0;
}

char _license[] SEC("license") = "GPL";
