package opnsense

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
)

// dnsmasqStub stands in for the OPNsense dnsmasq API. It is stateful, and
// applies setHost as a partial update the way OPNsense does — only the fields
// present in the body change — so tests can tell a targeted cnames rewrite
// apart from one that clobbers the rest of the entry.
type dnsmasqStub struct {
	hosts []dnsmasqSearchRow

	addedHosts   []string
	deletedPaths []string
	setBodies    map[string]string // uuid -> last body posted to setHost
	unexpected   []string
	nextUUID     int
}

func (s *dnsmasqStub) provider(t *testing.T) *Provider {
	t.Helper()

	s.setBodies = map[string]string{}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/dnsmasq/service/status", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"status":"running"}`)
	})
	mux.HandleFunc("/api/dnsmasq/service/reconfigure", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"status":"ok"}`)
	})
	mux.HandleFunc("/api/dnsmasq/settings/searchHost", func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(dnsmasqSearchResponse{Rows: s.hosts}); err != nil {
			t.Errorf("stub: encode response: %v", err)
		}
	})
	mux.HandleFunc("/api/dnsmasq/settings/addHost", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.addedHosts = append(s.addedHosts, string(body))

		var req dnsmasqAddBody
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("stub: decode addHost: %v", err)
		}
		s.nextUUID++
		s.hosts = append(s.hosts, dnsmasqSearchRow{
			UUID:   fmt.Sprintf("new-host-%d", s.nextUUID),
			Host:   req.Host.Host,
			Domain: req.Host.Domain,
			IP:     req.Host.IP,
		})
		io.WriteString(w, `{"result":"saved"}`)
	})
	mux.HandleFunc("/api/dnsmasq/settings/setHost/", func(w http.ResponseWriter, r *http.Request) {
		uuid := strings.TrimPrefix(r.URL.Path, "/api/dnsmasq/settings/setHost/")
		body, _ := io.ReadAll(r.Body)
		s.setBodies[uuid] = string(body)

		var req dnsmasqSetCnamesBody
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("stub: decode setHost: %v", err)
		}
		found := false
		for i := range s.hosts {
			if s.hosts[i].UUID == uuid {
				s.hosts[i].Cnames = req.Host.Cnames
				found = true
			}
		}
		if !found {
			t.Errorf("stub: setHost for unknown uuid %q", uuid)
		}
		io.WriteString(w, `{"result":"saved"}`)
	})
	mux.HandleFunc("/api/dnsmasq/settings/delHost/", func(w http.ResponseWriter, r *http.Request) {
		s.deletedPaths = append(s.deletedPaths, r.URL.Path)
		io.WriteString(w, `{"result":"deleted"}`)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.unexpected = append(s.unexpected, r.URL.Path)
		http.Error(w, "unexpected path", http.StatusNotFound)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	p, err := NewOpnsenseProvider(endpoint.NewDomainFilter(nil), &Config{
		Host:   srv.URL,
		Key:    "key",
		Secret: "secret",
		Plugin: "dnsmasq",
	})
	if err != nil {
		t.Fatalf("NewOpnsenseProvider: %v", err)
	}
	return p.(*Provider)
}

func (s *dnsmasqStub) assertNoUnexpectedCalls(t *testing.T) {
	t.Helper()
	if len(s.unexpected) > 0 {
		t.Errorf("dnsmasq backend called unknown paths: %v", s.unexpected)
	}
}

// cnamesOf returns the stored cnames list for a host, by FQDN.
func (s *dnsmasqStub) cnamesOf(t *testing.T, fqdn string) string {
	t.Helper()
	for _, row := range s.hosts {
		if joinFQDN(row.Host, row.Domain) == fqdn {
			return row.Cnames
		}
	}
	t.Fatalf("no host entry for %s", fqdn)
	return ""
}

func webHost() []dnsmasqSearchRow {
	return []dnsmasqSearchRow{{
		UUID:   "host-uuid-1",
		Host:   "web",
		Domain: "example.com",
		IP:     "10.0.0.1",
	}}
}

func cnameChange(dnsName, target string) *endpoint.Endpoint {
	return &endpoint.Endpoint{
		DNSName:    dnsName,
		RecordType: "CNAME",
		Targets:    endpoint.NewTargets(target),
	}
}

// dnsmasq can represent CNAMEs (OPNsense 25.7+) but still has no TXT support.
func TestDnsmasqSupportedTypes(t *testing.T) {
	d := &dnsmasqPlugin{}
	for _, rt := range []string{"A", "AAAA", "CNAME"} {
		if !d.supportsType(rt) {
			t.Errorf("dnsmasq should support %s", rt)
		}
	}
	if d.supportsType("TXT") {
		t.Error("dnsmasq plugin should not claim TXT support")
	}
}

// Each name in a host entry's cnames list becomes a CNAME pointing at that host.
func TestDnsmasqRecordsExpandsCnames(t *testing.T) {
	hosts := webHost()
	hosts[0].Cnames = "www.example.com,shop.example.com"
	stub := &dnsmasqStub{hosts: hosts}

	endpoints, err := stub.provider(t).Records(context.Background())
	if err != nil {
		t.Fatalf("Records: %v", err)
	}

	got := map[string]string{}
	for _, ep := range endpoints {
		if ep.RecordType == "CNAME" {
			got[ep.DNSName] = ep.Targets[0]
		}
	}
	want := map[string]string{
		"www.example.com":  "web.example.com",
		"shop.example.com": "web.example.com",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d CNAMEs, want %d: %v", len(got), len(want), got)
	}
	for name, target := range want {
		if got[name] != target {
			t.Errorf("%s -> %q, want %q", name, got[name], target)
		}
	}
	stub.assertNoUnexpectedCalls(t)
}

// An empty cnames column must not produce a phantom CNAME for "".
func TestDnsmasqRecordsIgnoresEmptyCnames(t *testing.T) {
	stub := &dnsmasqStub{hosts: webHost()}

	endpoints, err := stub.provider(t).Records(context.Background())
	if err != nil {
		t.Fatalf("Records: %v", err)
	}
	for _, ep := range endpoints {
		if ep.RecordType == "CNAME" {
			t.Errorf("unexpected CNAME from empty cnames: %+v", ep)
		}
	}
	stub.assertNoUnexpectedCalls(t)
}

// Creating a CNAME appends it to the target entry's cnames list.
func TestDnsmasqCreateCNAME(t *testing.T) {
	stub := &dnsmasqStub{hosts: webHost()}

	err := stub.provider(t).ApplyChanges(context.Background(), &plan.Changes{
		Create: []*endpoint.Endpoint{cnameChange("www.example.com", "web.example.com")},
	})
	if err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}

	if got := stub.cnamesOf(t, "web.example.com"); got != "www.example.com" {
		t.Errorf("cnames = %q, want www.example.com", got)
	}
	stub.assertNoUnexpectedCalls(t)
}

// Adding a second CNAME must preserve the first.
func TestDnsmasqCreateCNAMEPreservesExisting(t *testing.T) {
	hosts := webHost()
	hosts[0].Cnames = "www.example.com"
	stub := &dnsmasqStub{hosts: hosts}

	err := stub.provider(t).ApplyChanges(context.Background(), &plan.Changes{
		Create: []*endpoint.Endpoint{cnameChange("shop.example.com", "web.example.com")},
	})
	if err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}

	got := splitCnames(stub.cnamesOf(t, "web.example.com"))
	if len(got) != 2 || got[0] != "www.example.com" || got[1] != "shop.example.com" {
		t.Errorf("cnames = %v, want [www.example.com shop.example.com]", got)
	}
	stub.assertNoUnexpectedCalls(t)
}

// The update must send only the cnames field, so the rest of the host entry
// (ip, hwaddr, tags...) is left alone by OPNsense's partial merge.
func TestDnsmasqCreateCNAMESendsOnlyCnames(t *testing.T) {
	stub := &dnsmasqStub{hosts: webHost()}

	err := stub.provider(t).ApplyChanges(context.Background(), &plan.Changes{
		Create: []*endpoint.Endpoint{cnameChange("www.example.com", "web.example.com")},
	})
	if err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}

	body, ok := stub.setBodies["host-uuid-1"]
	if !ok {
		t.Fatalf("no setHost call for host-uuid-1, got %v", stub.setBodies)
	}

	var decoded map[string]map[string]any
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatalf("unmarshal setHost body: %v", err)
	}
	host, ok := decoded["host"]
	if !ok {
		t.Fatalf("setHost body has no host object: %s", body)
	}
	if len(host) != 1 {
		t.Errorf("setHost sent %d fields, want only cnames: %s", len(host), body)
	}
	if _, ok := host["cnames"]; !ok {
		t.Errorf("setHost body missing cnames: %s", body)
	}
	// The IP must survive untouched.
	if stub.hosts[0].IP != "10.0.0.1" {
		t.Errorf("host ip = %q, want 10.0.0.1", stub.hosts[0].IP)
	}
}

// Re-creating a CNAME that already points at the same target is a no-op.
func TestDnsmasqCreateCNAMEIdempotent(t *testing.T) {
	hosts := webHost()
	hosts[0].Cnames = "www.example.com"
	stub := &dnsmasqStub{hosts: hosts}

	err := stub.provider(t).ApplyChanges(context.Background(), &plan.Changes{
		Create: []*endpoint.Endpoint{cnameChange("www.example.com", "web.example.com")},
	})
	if err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}
	if len(stub.setBodies) != 0 {
		t.Errorf("expected no setHost call, got %v", stub.setBodies)
	}
}

// Repointing a CNAME must remove it from the old entry, not leave a duplicate
// that would render two conflicting cname= lines.
func TestDnsmasqCreateCNAMEMovesBetweenTargets(t *testing.T) {
	stub := &dnsmasqStub{hosts: []dnsmasqSearchRow{
		{UUID: "host-uuid-1", Host: "web", Domain: "example.com", IP: "10.0.0.1", Cnames: "www.example.com"},
		{UUID: "host-uuid-2", Host: "api", Domain: "example.com", IP: "10.0.0.2"},
	}}

	err := stub.provider(t).ApplyChanges(context.Background(), &plan.Changes{
		Create: []*endpoint.Endpoint{cnameChange("www.example.com", "api.example.com")},
	})
	if err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}

	if got := stub.cnamesOf(t, "web.example.com"); got != "" {
		t.Errorf("old target still holds the alias: %q", got)
	}
	if got := stub.cnamesOf(t, "api.example.com"); got != "www.example.com" {
		t.Errorf("new target cnames = %q, want www.example.com", got)
	}
}

// A CNAME whose target has no host entry cannot be stored.
func TestDnsmasqCreateCNAMEFailsWithoutTarget(t *testing.T) {
	stub := &dnsmasqStub{}

	err := stub.provider(t).ApplyChanges(context.Background(), &plan.Changes{
		Create: []*endpoint.Endpoint{cnameChange("www.example.com", "web.example.com")},
	})
	if err == nil {
		t.Fatal("expected an error when the CNAME target has no host entry")
	}
	if len(stub.setBodies) != 0 {
		t.Errorf("expected no setHost call, got %v", stub.setBodies)
	}
}

// Deleting a CNAME removes only that name and leaves its siblings in place.
func TestDnsmasqDeleteCNAME(t *testing.T) {
	hosts := webHost()
	hosts[0].Cnames = "www.example.com,shop.example.com"
	stub := &dnsmasqStub{hosts: hosts}

	err := stub.provider(t).ApplyChanges(context.Background(), &plan.Changes{
		Delete: []*endpoint.Endpoint{cnameChange("www.example.com", "web.example.com")},
	})
	if err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}

	if got := stub.cnamesOf(t, "web.example.com"); got != "shop.example.com" {
		t.Errorf("cnames = %q, want shop.example.com", got)
	}
	// The host entry itself must not be deleted along with its alias.
	if len(stub.deletedPaths) != 0 {
		t.Errorf("expected no delHost call, got %v", stub.deletedPaths)
	}
}

// Deleting a CNAME that is not stored anywhere is a no-op, not an error.
func TestDnsmasqDeleteMissingCNAME(t *testing.T) {
	stub := &dnsmasqStub{hosts: webHost()}

	err := stub.provider(t).ApplyChanges(context.Background(), &plan.Changes{
		Delete: []*endpoint.Endpoint{cnameChange("gone.example.com", "web.example.com")},
	})
	if err != nil {
		t.Fatalf("ApplyChanges should skip a missing CNAME, not fail: %v", err)
	}
	if len(stub.setBodies) != 0 {
		t.Errorf("expected no setHost call, got %v", stub.setBodies)
	}
}

// A CNAME can only hang off an existing entry, so within one batch the host
// must be created before the alias that points at it.
func TestDnsmasqCreatesTargetBeforeCNAME(t *testing.T) {
	stub := &dnsmasqStub{}

	err := stub.provider(t).ApplyChanges(context.Background(), &plan.Changes{
		Create: []*endpoint.Endpoint{
			cnameChange("www.example.com", "web.example.com"),
			{DNSName: "web.example.com", RecordType: "A", Targets: endpoint.NewTargets("10.0.0.1")},
		},
	})
	if err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}

	if got := stub.cnamesOf(t, "web.example.com"); got != "www.example.com" {
		t.Errorf("cnames = %q, want www.example.com", got)
	}
}

// TXT remains unrepresentable and must be skipped without failing the sync.
func TestDnsmasqSkipsTXT(t *testing.T) {
	stub := &dnsmasqStub{}

	err := stub.provider(t).ApplyChanges(context.Background(), &plan.Changes{
		Create: []*endpoint.Endpoint{
			{DNSName: "txt.example.com", RecordType: "TXT", Targets: endpoint.NewTargets("hello")},
			{DNSName: "web.example.com", RecordType: "A", Targets: endpoint.NewTargets("10.0.0.1")},
		},
	})
	if err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}
	if len(stub.addedHosts) != 1 {
		t.Errorf("expected only the A record to be written, got %d: %v", len(stub.addedHosts), stub.addedHosts)
	}
	stub.assertNoUnexpectedCalls(t)
}

// A records must still be written normally.
func TestDnsmasqStillCreatesARecords(t *testing.T) {
	stub := &dnsmasqStub{}

	err := stub.provider(t).ApplyChanges(context.Background(), &plan.Changes{
		Create: []*endpoint.Endpoint{
			{DNSName: "web.example.com", RecordType: "A", Targets: endpoint.NewTargets("10.0.0.1")},
		},
	})
	if err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}

	var body dnsmasqAddBody
	if err := json.Unmarshal([]byte(stub.addedHosts[0]), &body); err != nil {
		t.Fatalf("unmarshal host body: %v", err)
	}
	if body.Host.Host != "web" || body.Host.Domain != "example.com" || body.Host.IP != "10.0.0.1" {
		t.Errorf("unexpected host body: %+v", body.Host)
	}
	stub.assertNoUnexpectedCalls(t)
}
