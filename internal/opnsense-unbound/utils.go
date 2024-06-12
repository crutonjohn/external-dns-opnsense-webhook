package opnsense

import "strings"

// UnboundFQDNSplitter splits a DNSName into two parts,
// [0] Being the top level hostname
// [1] Being the subdomain/domain
func UnboundFQDNSplitter(hostname string) []string {
	unboundSplittedHost := strings.SplitN(hostname, ".", 2)

	return unboundSplittedHost
}

func UnboundFQDNCombiner(hostname string, domain string) string {
	unboundCombinededHost := hostname + "." + domain

	return unboundCombinededHost
}

func UnboundTypePrune(unboundType string) string {
	unboundUncrufted := strings.SplitN(unboundType, " ", 2)[0]

	return unboundUncrufted
}

func UnboundTypeEmbellisher(unboundType string) string {
	if unboundType == "A" {
		return unboundType + " (IPv4 address)"
	}
	if unboundType == "AAAA" {
		return unboundType + " (IPv6 address)"
	}

	return unboundType
}
