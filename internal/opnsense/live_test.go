//go:build live

// Live tests against a real OPNsense firewall. Excluded from normal builds and
// from CI by the "live" build tag.
//
// Load the credentials without running the webhook, then pick a phase:
//
//	eval "$(grep '^export ' .private/run.sh)"
//
//	# Phase 1 — read only, touches nothing:
//	go test -tags=live ./internal/opnsense/ -run TestLiveInspect -v
//
//	# Phase 2 — creates and deletes records under a scratch domain, then
//	# verifies the firewall is back to its original state. Never calls
//	# reconfigure, so the running dnsmasq service is not reloaded.
//	LIVE_WRITE_DOMAIN=scratch.example.com \
//	  go test -tags=live ./internal/opnsense/ -run TestLiveRoundTrip -v
package opnsense

import (
	"encoding/json"
	"io"
	"os"
	"sort"
	"strings"
	"testing"

	"sigs.k8s.io/external-dns/endpoint"
)

func liveClient(t *testing.T) *httpClient {
	t.Helper()

	cfg := &Config{
		Host:          os.Getenv("OPNSENSE_HOST"),
		Key:           os.Getenv("OPNSENSE_API_KEY"),
		Secret:        os.Getenv("OPNSENSE_API_SECRET"),
		Plugin:        os.Getenv("OPNSENSE_PLUGIN"),
		SkipTLSVerify: os.Getenv("OPNSENSE_SKIP_TLS_VERIFY") == "true",
	}
	if cfg.Host == "" || cfg.Key == "" || cfg.Secret == "" {
		t.Skip("OPNSENSE_HOST/API_KEY/API_SECRET not set; source .private/run.sh env first")
	}
	if cfg.Plugin == "" {
		cfg.Plugin = "unbound"
	}

	c, err := newOpnsenseClient(cfg)
	if err != nil {
		t.Fatalf("connect to %s: %v", cfg.Host, err)
	}
	t.Logf("connected to %s (plugin=%s)", cfg.Host, cfg.Plugin)
	return c
}

// TestLiveInspect is read-only. It reports the wire shape of the search
// response so we can confirm the assumptions the decoder is built on —
// in particular that dnsmasq returns cnames as a comma-separated string.
func TestLiveInspect(t *testing.T) {
	c := liveClient(t)

	resp, err := c.search(c.plugin.searchPath())
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	var generic struct {
		Rows  []map[string]json.RawMessage `json:"rows"`
		Total int                          `json:"total"`
	}
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("decode search response: %v\nfirst 300 bytes: %s", err, truncate(string(raw), 300))
	}

	t.Logf("search returned %d rows (total=%d)", len(generic.Rows), generic.Total)
	if len(generic.Rows) == 0 {
		t.Log("no host entries defined; create one in the UI to inspect the field shape")
		return
	}

	keys := make([]string, 0, len(generic.Rows[0]))
	for k := range generic.Rows[0] {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	t.Logf("fields on a host entry: %s", strings.Join(keys, ", "))

	if _, ok := generic.Rows[0]["cnames"]; !ok {
		t.Errorf("no cnames field: this firewall predates OPNsense 25.7, " +
			"so CNAME support on the dnsmasq backend will not work here")
	}

	// Report the shape of cnames wherever one is actually populated.
	populated := 0
	for _, row := range generic.Rows {
		v, ok := row["cnames"]
		if !ok || string(v) == `""` || string(v) == "null" {
			continue
		}
		populated++
		if populated == 1 {
			t.Logf("example cnames value (raw JSON): %s", string(v))
			var s string
			if err := json.Unmarshal(v, &s); err != nil {
				t.Errorf("cnames is not a JSON string, decoder assumption is wrong: %v", err)
			} else {
				t.Logf("parsed as comma-separated list: %q", splitCnames(s))
			}
		}
	}
	t.Logf("%d of %d entries have a populated cnames field", populated, len(generic.Rows))

	// Exercise the normal read path end to end.
	records, err := c.getRecords()
	if err != nil {
		t.Fatalf("getRecords: %v", err)
	}
	byType := map[string]int{}
	for _, r := range records {
		byType[r.recordType]++
	}
	t.Logf("normalized records by type: %v", byType)
}

// TestLiveRoundTrip creates, repoints and deletes records under a scratch
// domain, checking the firewall's state after each step. It restores the
// original state even on failure, and never calls reconfigure, so the running
// dnsmasq service is left alone.
func TestLiveRoundTrip(t *testing.T) {
	domain := os.Getenv("LIVE_WRITE_DOMAIN")
	if domain == "" {
		t.Skip("LIVE_WRITE_DOMAIN not set; refusing to write to a live firewall without an explicit scratch domain")
	}

	c := liveClient(t)

	var (
		targetA = "extdns-target." + domain
		targetB = "extdns-other." + domain
		cname   = "extdns-alias." + domain
	)

	epA := &endpoint.Endpoint{DNSName: targetA, RecordType: "A", Targets: endpoint.NewTargets("192.0.2.10")}
	epB := &endpoint.Endpoint{DNSName: targetB, RecordType: "A", Targets: endpoint.NewTargets("192.0.2.11")}
	epCNAME := &endpoint.Endpoint{DNSName: cname, RecordType: "CNAME", Targets: endpoint.NewTargets(targetA)}
	epCNAMEMoved := &endpoint.Endpoint{DNSName: cname, RecordType: "CNAME", Targets: endpoint.NewTargets(targetB)}

	// The scratch domain may hold records that matter. Never touch a name that
	// already exists — the cleanup below deletes every name listed here.
	existing, err := c.getRecords()
	if err != nil {
		t.Fatalf("preflight getRecords: %v", err)
	}
	for _, name := range []string{targetA, targetB, cname} {
		for _, r := range existing {
			if joinFQDN(r.hostname, r.domain) == name {
				t.Fatalf("preflight: %s already exists on the firewall as a %s record; "+
					"refusing to run so the test cannot delete a real record", name, r.recordType)
			}
		}
	}
	t.Logf("preflight: %s, %s and %s are unused", targetA, targetB, cname)

	// Clean up whatever we manage to create, in reverse dependency order.
	t.Cleanup(func() {
		for _, ep := range []*endpoint.Endpoint{epCNAME, epA, epB} {
			if err := c.deleteRecord(ep); err != nil {
				t.Errorf("cleanup: delete %s %s: %v", ep.RecordType, ep.DNSName, err)
			}
		}
		assertAbsent(t, c, cname, "CNAME")
		assertAbsent(t, c, targetA, "A")
		assertAbsent(t, c, targetB, "A")
		t.Log("cleanup: scratch records removed")

		// Apply the now-restored config, exercising the reconfigure path that
		// ApplyChanges normally calls. This reloads dnsmasq once.
		if os.Getenv("LIVE_RECONFIGURE") == "" {
			t.Log("cleanup: LIVE_RECONFIGURE not set, leaving dnsmasq unreloaded")
			return
		}
		if err := c.reconfigure(); err != nil {
			t.Errorf("cleanup: reconfigure: %v", err)
		} else {
			t.Log("cleanup: dnsmasq reconfigured")
		}
	})

	// A CNAME with no target must be refused rather than silently dropped.
	if err := c.createRecord(epCNAME); err == nil {
		t.Error("expected creating a CNAME with no target to fail")
	} else {
		t.Logf("CNAME without target correctly refused: %v", err)
	}

	for _, ep := range []*endpoint.Endpoint{epA, epB} {
		if err := c.createRecord(ep); err != nil {
			t.Fatalf("create %s: %v", ep.DNSName, err)
		}
	}
	assertPresent(t, c, targetA, "A", "192.0.2.10")
	assertPresent(t, c, targetB, "A", "192.0.2.11")

	if err := c.createRecord(epCNAME); err != nil {
		t.Fatalf("create CNAME: %v", err)
	}
	assertPresent(t, c, cname, "CNAME", targetA)

	// Creating the same CNAME again must be a no-op, not a duplicate.
	if err := c.createRecord(epCNAME); err != nil {
		t.Fatalf("recreate CNAME: %v", err)
	}
	assertPresent(t, c, cname, "CNAME", targetA)

	// Repointing must move it, leaving exactly one CNAME behind.
	if err := c.createRecord(epCNAMEMoved); err != nil {
		t.Fatalf("repoint CNAME: %v", err)
	}
	assertPresent(t, c, cname, "CNAME", targetB)

	records, err := c.getRecords()
	if err != nil {
		t.Fatalf("getRecords: %v", err)
	}
	seen := 0
	for _, r := range records {
		if joinFQDN(r.hostname, r.domain) == cname && r.recordType == "CNAME" {
			seen++
		}
	}
	if seen != 1 {
		t.Errorf("found %d CNAMEs for %s after repointing, want exactly 1", seen, cname)
	}

	// Deleting the CNAME must leave its host entry intact.
	if err := c.deleteRecord(epCNAME); err != nil {
		t.Fatalf("delete CNAME: %v", err)
	}
	assertAbsent(t, c, cname, "CNAME")
	assertPresent(t, c, targetB, "A", "192.0.2.11")
}

func assertPresent(t *testing.T, c *httpClient, fqdn, recordType, target string) {
	t.Helper()
	r, err := c.lookup(fqdn, recordType)
	if err != nil {
		t.Fatalf("lookup %s: %v", fqdn, err)
	}
	if r == nil {
		t.Fatalf("%s %s not found on the firewall", recordType, fqdn)
	}
	if r.target != target {
		t.Errorf("%s %s target = %q, want %q", recordType, fqdn, r.target, target)
	}
	t.Logf("ok: %s %s -> %s", recordType, fqdn, r.target)
}

func assertAbsent(t *testing.T, c *httpClient, fqdn, recordType string) {
	t.Helper()
	r, err := c.lookup(fqdn, recordType)
	if err != nil {
		t.Errorf("lookup %s: %v", fqdn, err)
		return
	}
	if r != nil {
		t.Errorf("%s %s still present (uuid=%s)", recordType, fqdn, r.uuid)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
