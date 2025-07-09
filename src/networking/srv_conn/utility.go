package srv_conn

import (
	"net"
	"strings"
)

func convertStringToAddr(string_addresses []string) ([]net.Addr, []error) {
	var addrs []net.Addr
	var errors []error
	for _, addrStr := range string_addresses {
		addr, err := net.ResolveUDPAddr("udp", addrStr)
		if err != nil {
			errors = append(errors, err)
			continue
		}
		addrs = append(addrs, addr)
	}
	return addrs, errors
}

func getUDPaddr(addr string) (*net.UDPAddr, error) {
	if strings.Count(addr, ":") < 2 {
		return net.ResolveUDPAddr("udp4", addr)
	}
	return net.ResolveUDPAddr("udp6", addr)
}
