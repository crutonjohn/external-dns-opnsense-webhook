package opnsense

import "strings"

// FormatUrl formats a URL with the given parameters.
func FormatUrl(path string, params ...string) string {
	segments := strings.Split(path, "%s")
	for i, param := range params {
		if param != "" {
			segments[i] += param
		}
	}
	return strings.Join(segments, "")
}

// UnboundFQDNSplitter splits a DNSName into two parts,
// [0] Being the top level hostname
// [1] Being the subdomain/domain
func UnboundFQDNSplitter(hostname string) []string {
	unboundSplittedHost := strings.SplitN(hostname, ".", 2)

	return unboundSplittedHost
}
