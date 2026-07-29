package opnsense

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
)

// unboundStub is a minimal stand-in for the OPNsense Unbound API, covering the
// Host Override and Host Alias endpoints the provider talks to. It is stateful:
// records added during a test are visible to later requests in the same test,
// so ordering within a batch of changes is exercised for real.
type unboundStub struct {
	overrides []unboundSearchRow
	aliases   []unboundAliasRow

	addedAliases []string // request bodies POSTed to addHostAlias
	addedHosts   []string // request bodies POSTed to addHostOverride
	deletedPaths []string // paths POSTed to delHostAlias/delHostOverride
	nextUUID     int
}

func (s *unboundStub) server(t *testing.T) *httptest.Server {
	t.Helper()

	writeJSON := func(w http.ResponseWriter, v any) {
		if err := json.NewEncoder(w).Encode(v); err != nil {
			t.Errorf("stub: encode response: %v", err)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/unbound/service/status", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"status":"running"}`)
	})
	mux.HandleFunc("/api/unbound/service/reconfigure", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"status":"ok"}`)
	})
	mux.HandleFunc("/api/unbound/settings/searchHostOverride", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, unboundSearchResponse{Rows: s.overrides})
	})
	mux.HandleFunc("/api/unbound/settings/searchHostAlias", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, unboundAliasSearchResponse{Rows: s.aliases})
	})
	mux.HandleFunc("/api/unbound/settings/addHostOverride", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.addedHosts = append(s.addedHosts, string(body))

		var req unboundAddBody
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("stub: decode addHostOverride: %v", err)
		}
		s.nextUUID++
		s.overrides = append(s.overrides, unboundSearchRow{
			UUID:     fmt.Sprintf("new-host-%d", s.nextUUID),
			Hostname: req.Host.Hostname,
			Domain:   req.Host.Domain,
			Rr:       req.Host.Rr,
			Server:   req.Host.Server,
			TxtData:  req.Host.TxtData,
		})
		io.WriteString(w, `{"result":"saved"}`)
	})
	mux.HandleFunc("/api/unbound/settings/addHostAlias", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.addedAliases = append(s.addedAliases, string(body))
		io.WriteString(w, `{"result":"saved"}`)
	})
	mux.HandleFunc("/api/unbound/settings/", func(w http.ResponseWriter, r *http.Request) {
		s.deletedPaths = append(s.deletedPaths, r.URL.Path)
		io.WriteString(w, `{"result":"deleted"}`)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func (s *unboundStub) provider(t *testing.T) *Provider {
	t.Helper()

	srv := s.server(t)
	p, err := NewOpnsenseProvider(endpoint.NewDomainFilter(nil), &Config{
		Host:   srv.URL,
		Key:    "key",
		Secret: "secret",
		Plugin: "unbound",
	})
	if err != nil {
		t.Fatalf("NewOpnsenseProvider: %v", err)
	}
	return p.(*Provider)
}

// webOverride is a single A record for web.example.com, the usual CNAME target
// in these tests.
func webOverride() []unboundSearchRow {
	return []unboundSearchRow{{
		UUID:     "host-uuid-1",
		Hostname: "web",
		Domain:   "example.com",
		Rr:       "A (IPv4 address)",
		Server:   "10.0.0.1",
	}}
}

// wwwAlias is a single CNAME www.example.com pointing at webOverride.
func wwwAlias() []unboundAliasRow {
	return []unboundAliasRow{{
		UUID:     "alias-uuid-1",
		Hostname: "www",
		Domain:   "example.com",
		Host:     "host-uuid-1",
	}}
}

// Records must resolve an alias's target UUID back into the target's FQDN.
func TestRecordsResolvesAliasTarget(t *testing.T) {
	stub := &unboundStub{overrides: webOverride(), aliases: wwwAlias()}

	endpoints, err := stub.provider(t).Records(context.Background())
	if err != nil {
		t.Fatalf("Records: %v", err)
	}

	var cname *endpoint.Endpoint
	for _, ep := range endpoints {
		if ep.RecordType == "CNAME" {
			cname = ep
		}
	}
	if cname == nil {
		t.Fatalf("no CNAME endpoint returned, got %+v", endpoints)
	}
	if cname.DNSName != "www.example.com" {
		t.Errorf("DNSName = %q, want www.example.com", cname.DNSName)
	}
	if got := cname.Targets[0]; got != "web.example.com" {
		t.Errorf("target = %q, want web.example.com (resolved from host-uuid-1)", got)
	}
}

// An alias whose target UUID no longer exists is skipped rather than surfaced
// as a CNAME pointing at nothing.
func TestRecordsSkipsAliasWithMissingTarget(t *testing.T) {
	dangling := wwwAlias()
	dangling[0].Host = "gone"
	stub := &unboundStub{overrides: webOverride(), aliases: dangling}

	endpoints, err := stub.provider(t).Records(context.Background())
	if err != nil {
		t.Fatalf("Records: %v", err)
	}

	for _, ep := range endpoints {
		if ep.RecordType == "CNAME" {
			t.Fatalf("expected dangling alias to be skipped, got %+v", ep)
		}
	}
}

// Creating a CNAME must post the target record's UUID, not its name.
func TestCreateAliasSendsTargetUUID(t *testing.T) {
	stub := &unboundStub{overrides: webOverride()}

	err := stub.provider(t).ApplyChanges(context.Background(), &plan.Changes{
		Create: []*endpoint.Endpoint{{
			DNSName:    "www.example.com",
			RecordType: "CNAME",
			Targets:    endpoint.NewTargets("web.example.com"),
		}},
	})
	if err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}

	if len(stub.addedAliases) != 1 {
		t.Fatalf("expected 1 addHostAlias call, got %d", len(stub.addedAliases))
	}

	var body unboundAddAliasBody
	if err := json.Unmarshal([]byte(stub.addedAliases[0]), &body); err != nil {
		t.Fatalf("unmarshal alias body: %v", err)
	}
	if body.Alias.Host != "host-uuid-1" {
		t.Errorf("alias host = %q, want host-uuid-1", body.Alias.Host)
	}
	if body.Alias.Hostname != "www" || body.Alias.Domain != "example.com" {
		t.Errorf("alias name = %q.%q, want www.example.com", body.Alias.Hostname, body.Alias.Domain)
	}
}

// A CNAME with no corresponding A/AAAA record cannot be expressed as an alias,
// so it must fail loudly rather than silently doing nothing.
func TestCreateAliasFailsWithoutTarget(t *testing.T) {
	stub := &unboundStub{}

	err := stub.provider(t).ApplyChanges(context.Background(), &plan.Changes{
		Create: []*endpoint.Endpoint{{
			DNSName:    "www.example.com",
			RecordType: "CNAME",
			Targets:    endpoint.NewTargets("web.example.com"),
		}},
	})
	if err == nil {
		t.Fatal("expected an error when the CNAME target has no A/AAAA record")
	}
	if len(stub.addedAliases) != 0 {
		t.Errorf("expected no addHostAlias call, got %d", len(stub.addedAliases))
	}
}

// Deleting a CNAME must use the alias delete path, not the host override one.
func TestDeleteAliasUsesAliasPath(t *testing.T) {
	stub := &unboundStub{overrides: webOverride(), aliases: wwwAlias()}

	err := stub.provider(t).ApplyChanges(context.Background(), &plan.Changes{
		Delete: []*endpoint.Endpoint{{
			DNSName:    "www.example.com",
			RecordType: "CNAME",
			Targets:    endpoint.NewTargets("web.example.com"),
		}},
	})
	if err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}

	want := "/api/unbound/settings/delHostAlias/alias-uuid-1"
	if len(stub.deletedPaths) != 1 || stub.deletedPaths[0] != want {
		t.Errorf("delete paths = %v, want [%s]", stub.deletedPaths, want)
	}
}

// An alias can only be created once its target exists. Here the CNAME's target
// is created in the same batch, and is listed after the CNAME, so this only
// succeeds if host overrides are applied before aliases.
func TestApplyChangesCreatesTargetBeforeAlias(t *testing.T) {
	stub := &unboundStub{}

	err := stub.provider(t).ApplyChanges(context.Background(), &plan.Changes{
		Create: []*endpoint.Endpoint{
			{
				DNSName:    "www.example.com",
				RecordType: "CNAME",
				Targets:    endpoint.NewTargets("web.example.com"),
			},
			{
				DNSName:    "web.example.com",
				RecordType: "A",
				Targets:    endpoint.NewTargets("10.0.0.1"),
			},
		},
	})
	if err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}

	if len(stub.addedHosts) != 1 {
		t.Fatalf("expected 1 addHostOverride call, got %d", len(stub.addedHosts))
	}
	if len(stub.addedAliases) != 1 {
		t.Fatalf("expected 1 addHostAlias call, got %d", len(stub.addedAliases))
	}

	var body unboundAddAliasBody
	if err := json.Unmarshal([]byte(stub.addedAliases[0]), &body); err != nil {
		t.Fatalf("unmarshal alias body: %v", err)
	}
	if body.Alias.Host != "new-host-1" {
		t.Errorf("alias host = %q, want new-host-1 (the override created in this batch)", body.Alias.Host)
	}
}
