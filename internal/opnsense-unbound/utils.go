package opnsense

import (
	"strconv"
	"strings"

	"sigs.k8s.io/external-dns/endpoint"
)

// ParseUnboundTTL converts an override's TTL field to an endpoint TTL.
// An empty or invalid value means the override uses Unbound's default TTL,
// which external-dns treats as unconfigured.
func ParseUnboundTTL(ttl string) endpoint.TTL {
	seconds, err := strconv.ParseInt(ttl, 10, 64)
	if err != nil || seconds < 0 {
		return 0
	}
	return endpoint.TTL(seconds)
}

// FormatUnboundTTL converts an endpoint TTL to an override's TTL field.
// An unconfigured TTL leaves the field empty so Unbound applies its default.
func FormatUnboundTTL(ttl endpoint.TTL) string {
	if !ttl.IsConfigured() {
		return ""
	}
	return strconv.FormatInt(int64(ttl), 10)
}

// UnboundFQDNSplitter splits a DNSName into two parts,
// [0] Being the top level hostname
// [1] Being the subdomain/domain
//
// TODO: really this should return (hostname, domain string)
func SplitUnboundFQDN(hostname string) []string {
	return strings.SplitN(hostname, ".", 2)
}

func JoinUnboundFQDN(hostname string, domain string) string {
	return strings.Join([]string{hostname, domain}, ".")
}

func PruneUnboundType(unboundType string) string {
	if i := strings.IndexByte(unboundType, ' '); i != -1 {
		return unboundType[:i]
	}
	return unboundType
}

func EmbellishUnboundType(unboundType string) string {
	switch unboundType {
	case "A":
		return unboundType + " (IPv4 address)"
	case "AAAA":
		return unboundType + " (IPv6 address)"
	case "TXT":
		return unboundType + " (Text record)"
	case "CNAME":
		return unboundType + " (CNAME record)"
	}
	return unboundType
}
