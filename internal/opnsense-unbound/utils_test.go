package opnsense

import (
	"testing"

	"sigs.k8s.io/external-dns/endpoint"
)

func TestParseUnboundTTL(t *testing.T) {
	cases := map[string]endpoint.TTL{
		"":     0,
		"60":   60,
		"3600": 3600,
		"-1":   0,
		"abc":  0,
	}
	for in, want := range cases {
		if got := ParseUnboundTTL(in); got != want {
			t.Errorf("ParseUnboundTTL(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestFormatUnboundTTL(t *testing.T) {
	cases := map[endpoint.TTL]string{
		0:    "",
		60:   "60",
		3600: "3600",
	}
	for in, want := range cases {
		if got := FormatUnboundTTL(in); got != want {
			t.Errorf("FormatUnboundTTL(%d) = %q, want %q", in, got, want)
		}
	}
}
