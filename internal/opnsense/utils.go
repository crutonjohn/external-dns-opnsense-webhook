package opnsense

import (
	"net"
	"strings"
)

// splitFQDN splits "www.example.com" into ("www", "example.com").
func splitFQDN(fqdn string) (hostname, domain string) {
	parts := strings.SplitN(fqdn, ".", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return fqdn, ""
}

// joinFQDN joins a hostname and domain into a fully-qualified domain name.
func joinFQDN(hostname, domain string) string {
	return hostname + "." + domain
}

// recordTypeFromIP infers "A" or "AAAA" from whether the IP is IPv4 or IPv6.
func recordTypeFromIP(ip string) string {
	if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() == nil {
		return "AAAA"
	}
	return "A"
}
