package utils

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"

	"github.com/cilium/ebpf"
)

// 将IPv4地址转换为网络字节序的uint32
func ipv4ToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	// 网络字节序（大端）
	return binary.BigEndian.Uint32(ip)
}

// 存储到eBPF map
func StoreIPv4ToMap(ipMap *ebpf.Map, ip string) error {
	netIP := net.ParseIP(ip)
	if netIP == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	ipUint32 := ipv4ToUint32(netIP)
	value := uint32(1) // 示例value

	return ipMap.Put(unsafe.Pointer(&ipUint32), unsafe.Pointer(&value))
}

// IPv6地址表示（128位）
type IPv6Addr struct {
	Addr [16]byte // 网络字节序
}

// 将IPv6地址转换为字节数组
func ipv6ToBytes(ip net.IP) [16]byte {
	var addr [16]byte
	ip16 := ip.To16()
	if ip16 == nil {
		return addr
	}
	copy(addr[:], ip16)
	return addr
}

// 存储IPv6到eBPF map
func StoreIPv6ToMap(ipMap *ebpf.Map, ip string) error {
	netIP := net.ParseIP(ip)
	if netIP == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	ipv6Bytes := ipv6ToBytes(netIP)
	value := uint32(1)

	return ipMap.Put(unsafe.Pointer(&ipv6Bytes), unsafe.Pointer(&value))
}
