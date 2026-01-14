package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"

	"github.com/cilium/ebpf"
)

// 关键理解：
// 1. 网络包中的字节序列：[192][168][63][20] = [0xC0][0xA8][0x3F][0x14]
// 2. 在x86(小端)机器上，struct iphdr { __u32 saddr; } 读取这4个字节时：
//    - 内存位置: [0xC0][0xA8][0x3F][0x14] (网络包的原始顺序)
//    - 读取为uint32: 0x143FA8C0 (小端解释：低字节在前)
// 3. 所以内核态 iph->saddr 在小端机器上的值是 0x143FA8C0

func main() {
	ipStr := "192.168.63.20"
	ip := net.ParseIP(ipStr)
	ipv4 := ip.To4()

	fmt.Printf("=== 字节序列分析 ===\n")
	fmt.Printf("IP: %s\n", ipStr)
	fmt.Printf("字节序列: %v\n", ipv4)
	fmt.Printf("十六进制: [0x%02X][0x%02X][0x%02X][0x%02X]\n",
		ipv4[0], ipv4[1], ipv4[2], ipv4[3])

	// 方法1: BigEndian - "概念上"的网络字节序
	bigEndian := binary.BigEndian.Uint32(ipv4)
	fmt.Printf("\nBigEndian.Uint32:    0x%08X (%d)\n", bigEndian, bigEndian)
	fmt.Printf("  解释: 把字节当作大端读取 -> 0xC0A83F14\n")

	// 方法2: LittleEndian - 小端机器上的实际值
	littleEndian := binary.LittleEndian.Uint32(ipv4)
	fmt.Printf("\nLittleEndian.Uint32: 0x%08X (%d)\n", littleEndian, littleEndian)
	fmt.Printf("  解释: 把字节当作小端读取 -> 0x143FA8C0\n")
	fmt.Printf("  这才是 iph->saddr 在x86机器上的实际值！\n")

	fmt.Printf("\n=== eBPF Map 存储策略 ===\n")

	// 错误方式：使用 BigEndian
	wrongValue := binary.BigEndian.Uint32(ipv4)
	fmt.Printf("❌ 错误: 使用 BigEndian = 0x%08X\n", wrongValue)
	fmt.Printf("   内核态 iph->saddr  = 0x143FA8C0\n")
	fmt.Printf("   不匹配！\n")

	// 正确方式：使用 LittleEndian (在x86机器上)
	correctValue := binary.LittleEndian.Uint32(ipv4)
	fmt.Printf("\n✅ 正确: 使用 LittleEndian = 0x%08X\n", correctValue)
	fmt.Printf("   内核态 iph->saddr    = 0x143FA8C0\n")
	fmt.Printf("   匹配！\n")

	// 或者更通用的方式：直接转换字节
	fmt.Printf("\n=== 通用方式（推荐）===\n")
	var ipUint32 uint32
	// 直接将4个字节按主机字节序解释
	ipUint32 = *(*uint32)(unsafe.Pointer(&ipv4[0]))
	fmt.Printf("直接转换: 0x%08X\n", ipUint32)
	fmt.Printf("这个值在小端机器上 = LittleEndian = 0x%08X\n", correctValue)
}

// 正确的存储函数
func storeIPv4ToMap(ipMap *ebpf.Map, ip string) error {
	netIP := net.ParseIP(ip)
	if netIP == nil {
		return fmt.Errorf("invalid IP address")
	}

	ipv4 := netIP.To4()
	if ipv4 == nil {
		return fmt.Errorf("not an IPv4 address")
	}

	// 关键：在x86(小端)机器上，使用 LittleEndian
	// 这样才能匹配内核态 iph->saddr 的值
	var ipUint32 uint32

	// 方法1: 使用 unsafe (性能更好)
	ipUint32 = *(*uint32)(unsafe.Pointer(&ipv4[0]))

	// 方法2: 使用 binary.LittleEndian (更明确)
	// ipUint32 = binary.LittleEndian.Uint32(ipv4)

	// 方法3: 使用 binary.NativeEndian (最通用，自动适配机器字节序)
	// ipUint32 = binary.NativeEndian.Uint32(ipv4)

	value := uint32(1)
	return ipMap.Put(unsafe.Pointer(&ipUint32), unsafe.Pointer(&value))
}

// 完整示例：IPv4和IPv6
type IPFilter struct {
	ipv4Map *ebpf.Map
	ipv6Map *ebpf.Map
}

func (f *IPFilter) AddIP(ip string) error {
	netIP := net.ParseIP(ip)
	if netIP == nil {
		return fmt.Errorf("invalid IP: %s", ip)
	}

	if ipv4 := netIP.To4(); ipv4 != nil {
		// IPv4: 使用主机字节序(小端机器上就是LittleEndian)
		var ipUint32 uint32
		ipUint32 = *(*uint32)(unsafe.Pointer(&ipv4[0]))

		value := uint32(1)
		return f.ipv4Map.Put(unsafe.Pointer(&ipUint32), unsafe.Pointer(&value))
	} else {
		// IPv6: 直接复制字节数组
		var ipv6Bytes [16]byte
		copy(ipv6Bytes[:], netIP.To16())

		value := uint32(1)
		return f.ipv6Map.Put(unsafe.Pointer(&ipv6Bytes), unsafe.Pointer(&value))
	}
}
