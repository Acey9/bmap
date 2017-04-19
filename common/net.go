package common

import (
	"net"
)

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func IP2CIDR(s string) string {
	ip := net.ParseIP(s)
	if ip == nil {
		return ""
	}
	return s + "/32"
}

func CIDR2IP(s string) (ips []string, err error) {
	ip, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return
	}

	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	return
}
