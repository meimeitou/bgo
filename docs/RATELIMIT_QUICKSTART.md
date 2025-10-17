# XDP Firewall Rate Limiting Feature

## Quick Start

### Enable Rate Limiting

```bash
# Limit to 1000 packets/second and 1 MB/second
sudo ./bin/bgo firewall-ratelimit --enable --pps 1000 --bps 1048576
```

### Check Status

```bash
# Show configuration
sudo ./bin/bgo firewall-ratelimit --show-config

# Show statistics
sudo ./bin/bgo firewall-ratelimit --show-stats
```

### Disable Rate Limiting

```bash
sudo ./bin/bgo firewall-ratelimit --disable
```

## Features

✅ **Packet Rate Limiting (PPS)**: Control the number of packets per second  
✅ **Bandwidth Limiting (BPS)**: Control the bytes per second  
✅ **Token Bucket Algorithm**: Smooth burst handling  
✅ **Real-time Statistics**: Track passed and dropped packets/bytes  
✅ **Dynamic Configuration**: Enable/disable without restart  
✅ **Applied After Firewall Rules**: Only affects packets that pass firewall checks  

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Incoming Packet                         │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
                  ┌───────────────┐
                  │  Parse IPv4   │
                  └───────┬───────┘
                          │
                          ▼
                  ┌───────────────┐
                  │   Whitelist   │ ◄─── Firewall Rules
                  └───────┬───────┘
                          │
                          ▼
                  ┌───────────────┐
                  │   Blacklist   │ ◄─── Firewall Rules
                  └───────┬───────┘
                          │
                          ▼
                  ┌───────────────┐
                  │ Default Action│ ◄─── Firewall Rules
                  └───────┬───────┘
                          │
                          ▼
            ┌─────────────────────────┐
            │  Rate Limit Check       │ ◄─── NEW: Rate Limiting
            │  - PPS Token Bucket     │
            │  - BPS Token Bucket     │
            └─────────┬───────────────┘
                      │
              ┌───────┴────────┐
              │                │
              ▼                ▼
          XDP_PASS         XDP_DROP
       (Pass packet)    (Drop packet)
```

## Implementation Details

### BPF Maps

**rate_limit_config_map**: Stores rate limit configuration
- `pps_limit`: Packets per second limit (uint64)
- `bps_limit`: Bytes per second limit (uint64)
- `enabled`: Enable flag (uint8)

**rate_limit_state_map**: Stores token bucket state
- `last_update_ns`: Last update timestamp in nanoseconds
- `tokens_packets`: Current packet tokens available
- `tokens_bytes`: Current byte tokens available

**rate_limit_stats_map**: Stores statistics
- `dropped_packets`: Packets dropped by rate limiter
- `dropped_bytes`: Bytes dropped by rate limiter
- `passed_packets`: Packets passed by rate limiter
- `passed_bytes`: Bytes passed by rate limiter

### Token Bucket Algorithm

1. **Token Generation**: Tokens are generated continuously based on time elapsed
   ```c
   new_tokens = (elapsed_time_ns * limit) / 1_000_000_000
   ```

2. **Token Consumption**: Each packet consumes tokens
   - 1 packet = 1 PPS token
   - 1 packet = packet_size BPS tokens

3. **Bucket Capacity**: Maximum tokens = configured limit
   - Allows traffic bursts up to the limit
   - Unused tokens accumulate up to the limit

4. **Decision**: Packet passes if enough tokens are available

## Usage Examples

### Web Server Protection

```bash
# Allow 5000 packets/sec and 50 MB/sec
sudo ./bin/bgo firewall-ratelimit --enable --pps 5000 --bps 52428800
```

### DDoS Mitigation

```bash
# Strict limits for DDoS protection
sudo ./bin/bgo firewall-ratelimit --enable --pps 1000 --bps 10485760
```

### Monitor in Real-time

```bash
# Watch statistics update every second
watch -n 1 'sudo ./bin/bgo firewall-ratelimit --show-stats'
```

### Reset Statistics

```bash
# Clear all statistics counters
sudo ./bin/bgo firewall-ratelimit --reset-stats
```

## Testing

### Run Demo Script

```bash
cd /home/vagrant/bgo
./scripts/demo_ratelimit.sh
```

### Generate Test Traffic

```bash
# Ping flood (requires root)
sudo ping -f <target_ip>

# Using hping3
hping3 --flood <target_ip>

# Using iperf
iperf3 -c <target_ip> -b 100M
```

### Monitor Results

```bash
# Terminal 1: Monitor statistics
watch -n 1 'sudo ./bin/bgo firewall-ratelimit --show-stats'

# Terminal 2: Generate traffic
ping -f <target_ip>
```

## Files Modified/Created

### Core Implementation
- `bpf/firewall/firewall.c`: Added rate limiting BPF logic
  - New structures: `rate_limit_config`, `rate_limit_state`, `rate_limit_stats`
  - New BPF maps for rate limiting
  - Token bucket algorithm implementation
  - Integration with firewall processing

- `bpf/firewall/firewall.go`: Added Go bindings
  - `RateLimitConfig` struct
  - `RateLimitStats` struct
  - `SetRateLimit()` method
  - `GetRateLimit()` method
  - `GetRateLimitStats()` method
  - `ResetRateLimitStats()` method

### Command Line Interface
- `cmd/firewall.go`: Added CLI command
  - `MakeFirewallRateLimit()` function
  - `runFirewallRateLimit()` function
  - Command line flags for configuration

- `cmd/root.go`: Registered new command
  - Added `MakeFirewallRateLimit()` to command list

### Documentation
- `docs/RATELIMIT.md`: Comprehensive documentation
- `scripts/demo_ratelimit.sh`: Demo script

## Performance Considerations

- **Minimal Overhead**: Token calculations use simple arithmetic
- **Nanosecond Precision**: Uses `bpf_ktime_get_ns()` for accurate timing
- **Atomic Operations**: Thread-safe statistics updates
- **Efficient**: Executes in XDP context (before SKB allocation)

## Troubleshooting

### Maps Not Found

If you see "failed to load pinned map" errors:

1. Ensure firewall server is running:
   ```bash
   ps aux | grep "bgo firewall-server"
   ```

2. Restart firewall server:
   ```bash
   sudo pkill -f "bgo firewall-server"
   sudo ./bin/bgo firewall-server start --interface enp0s8
   ```

3. Check BPF filesystem:
   ```bash
   ls -la /sys/fs/bpf/firewall/
   ```

### Rate Limiting Not Working

1. Verify rate limiting is enabled:
   ```bash
   sudo ./bin/bgo firewall-ratelimit --show-config
   ```

2. Check if limits are set:
   ```bash
   # Should show non-zero values for pps_limit or bps_limit
   ```

3. Generate traffic and check statistics:
   ```bash
   # Generate some traffic
   ping -c 10 <target_ip>
   
   # Check if counters are updating
   sudo ./bin/bgo firewall-ratelimit --show-stats
   ```

## Future Enhancements

Possible improvements:
- [ ] Per-IP rate limiting
- [ ] Per-port rate limiting
- [ ] Time-based rate limit schedules
- [ ] Integration with TC rate limiting
- [ ] Grafana/Prometheus metrics export
- [ ] Alert when rate limits are exceeded

## References

- [XDP Documentation](https://www.kernel.org/doc/html/latest/networking/filter.html)
- [Token Bucket Algorithm](https://en.wikipedia.org/wiki/Token_bucket)
- [eBPF Documentation](https://ebpf.io/)
