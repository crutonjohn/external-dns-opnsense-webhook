package opnsense

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sigs.k8s.io/external-dns/endpoint"
)

// mockOpnsenseServer builds a minimal OPNsense Unbound API server for testing.
// records is the initial set of host overrides; it is mutated as create/update/delete
// requests arrive so tests can observe side effects.
func mockOpnsenseServer(t *testing.T, records *[]DNSRecord) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	// login probe
	mux.HandleFunc("/api/unbound/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"running"}`)
	})

	// list records (accepts POST with rowCount=-1 body)
	mux.HandleFunc("/api/unbound/settings/searchHostOverride", func(w http.ResponseWriter, r *http.Request) {
		resp := unboundRecordsList{
			RowCount: len(*records),
			Total:    len(*records),
			Current:  1,
			Rows:     *records,
		}
		if resp.Rows == nil {
			resp.Rows = []DNSRecord{}
		}
		json.NewEncoder(w).Encode(resp)
	})

	// create record
	mux.HandleFunc("/api/unbound/settings/addHostOverride", func(w http.ResponseWriter, r *http.Request) {
		var body unboundAddHostOverride
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		newUUID := fmt.Sprintf("uuid-%d", len(*records)+1)
		body.Host.Uuid = newUUID
		*records = append(*records, body.Host)
		json.NewEncoder(w).Encode(unboundHostOverrideResponse{Result: "saved", UUID: newUUID})
	})

	// update record
	mux.HandleFunc("/api/unbound/settings/setHostOverride/", func(w http.ResponseWriter, r *http.Request) {
		uuid := strings.TrimPrefix(r.URL.Path, "/api/unbound/settings/setHostOverride/")
		var body unboundAddHostOverride
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		for i, rec := range *records {
			if rec.Uuid == uuid {
				body.Host.Uuid = uuid
				(*records)[i] = body.Host
				json.NewEncoder(w).Encode(unboundHostOverrideResponse{Result: "saved", UUID: uuid})
				return
			}
		}
		http.Error(w, "not found", http.StatusNotFound)
	})

	// delete record
	mux.HandleFunc("/api/unbound/settings/delHostOverride/", func(w http.ResponseWriter, r *http.Request) {
		uuid := strings.TrimPrefix(r.URL.Path, "/api/unbound/settings/delHostOverride/")
		for i, rec := range *records {
			if rec.Uuid == uuid {
				*records = append((*records)[:i], (*records)[i+1:]...)
				json.NewEncoder(w).Encode(unboundHostOverrideResponse{Result: "deleted"})
				return
			}
		}
		http.Error(w, "not found", http.StatusNotFound)
	})

	// reconfigure
	mux.HandleFunc("/api/unbound/service/reconfigure", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	return httptest.NewServer(mux)
}

func newTestClient(t *testing.T, records *[]DNSRecord) *httpClient {
	t.Helper()
	srv := mockOpnsenseServer(t, records)
	t.Cleanup(srv.Close)

	client, err := newOpnsenseClient(&Config{
		Host:          srv.URL,
		Key:           "key",
		Secret:        "secret",
		SkipTLSVerify: true,
	})
	if err != nil {
		t.Fatalf("newOpnsenseClient: %v", err)
	}
	return client
}

func TestCreateHostOverride_NewRecord(t *testing.T) {
	records := &[]DNSRecord{}
	c := newTestClient(t, records)

	ep := &endpoint.Endpoint{
		DNSName:    "jellyfin.avril",
		RecordType: "A",
		Targets:    endpoint.NewTargets("192.168.1.50"),
	}

	result, err := c.CreateHostOverride(ep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result for new record creation")
	}
	if result.Uuid == "" {
		t.Error("expected UUID to be populated on created record")
	}
	if len(*records) != 1 {
		t.Errorf("expected 1 record in store, got %d", len(*records))
	}
	if (*records)[0].Server != "192.168.1.50" {
		t.Errorf("expected server 192.168.1.50, got %s", (*records)[0].Server)
	}
}

func TestCreateHostOverride_ExistingRecordSameTarget(t *testing.T) {
	existing := DNSRecord{
		Uuid:     "existing-uuid",
		Enabled:  "1",
		Hostname: "jellyfin",
		Domain:   "avril",
		Rr:       "A (IPv4 address)",
		Server:   "192.168.1.50",
	}
	records := &[]DNSRecord{existing}
	c := newTestClient(t, records)

	ep := &endpoint.Endpoint{
		DNSName:    "jellyfin.avril",
		RecordType: "A",
		Targets:    endpoint.NewTargets("192.168.1.50"),
	}

	result, err := c.CreateHostOverride(ep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil || result.Uuid != "existing-uuid" {
		t.Error("expected existing record to be returned unchanged")
	}
	// Store should not have grown — no new record added
	if len(*records) != 1 {
		t.Errorf("expected 1 record in store, got %d", len(*records))
	}
}

func TestCreateHostOverride_ExistingRecordDifferentTarget(t *testing.T) {
	// With AdjustEndpoints enforcing single-target, a different-target endpoint is simply
	// a new record alongside the existing one — not an update of it.
	existing := DNSRecord{
		Uuid:     "existing-uuid",
		Enabled:  "1",
		Hostname: "jellyfin",
		Domain:   "avril",
		Rr:       "A (IPv4 address)",
		Server:   "192.168.1.50",
	}
	records := &[]DNSRecord{existing}
	c := newTestClient(t, records)

	ep := &endpoint.Endpoint{
		DNSName:    "jellyfin.avril",
		RecordType: "A",
		Targets:    endpoint.NewTargets("192.168.1.99"),
	}

	result, err := c.CreateHostOverride(ep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result for new record creation")
	}
	// A new record should have been created alongside the existing one
	if len(*records) != 2 {
		t.Errorf("expected 2 records in store, got %d", len(*records))
	}
	targets := map[string]bool{}
	for _, r := range *records {
		targets[r.Server] = true
	}
	if !targets["192.168.1.50"] || !targets["192.168.1.99"] {
		t.Errorf("expected both 192.168.1.50 and 192.168.1.99 in store, got %v", targets)
	}
}

func TestAdjustEndpoints_SplitsMultiTarget(t *testing.T) {
	provider := &Provider{
		domainFilter: endpoint.NewDomainFilter([]string{"avril"}),
	}

	eps := []*endpoint.Endpoint{
		{
			DNSName:    "wedding-media.avril",
			RecordType: "A",
			Targets:    endpoint.NewTargets("192.168.1.13", "192.168.1.156", "192.168.1.69"),
		},
		{
			DNSName:    "jellyfin.avril",
			RecordType: "A",
			Targets:    endpoint.NewTargets("192.168.1.50"),
		},
	}

	adjusted, err := provider.AdjustEndpoints(eps)
	if err != nil {
		t.Fatalf("AdjustEndpoints: %v", err)
	}
	if len(adjusted) != 4 {
		t.Fatalf("expected 4 endpoints after split, got %d", len(adjusted))
	}

	count := map[string]int{}
	for _, ep := range adjusted {
		if len(ep.Targets) != 1 {
			t.Errorf("expected each adjusted endpoint to have exactly 1 target, got %d", len(ep.Targets))
		}
		count[ep.DNSName]++
	}
	if count["wedding-media.avril"] != 3 {
		t.Errorf("expected 3 endpoints for wedding-media.avril, got %d", count["wedding-media.avril"])
	}
	if count["jellyfin.avril"] != 1 {
		t.Errorf("expected 1 endpoint for jellyfin.avril, got %d", count["jellyfin.avril"])
	}
}

func TestDeleteHostOverride_ExistingRecord(t *testing.T) {
	existing := DNSRecord{
		Uuid:     "del-uuid",
		Enabled:  "1",
		Hostname: "jellyfin",
		Domain:   "avril",
		Rr:       "A (IPv4 address)",
		Server:   "192.168.1.50",
	}
	records := &[]DNSRecord{existing}
	c := newTestClient(t, records)

	ep := &endpoint.Endpoint{
		DNSName:    "jellyfin.avril",
		RecordType: "A",
		Targets:    endpoint.NewTargets("192.168.1.50"),
	}

	if err := c.DeleteHostOverride(ep); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(*records) != 0 {
		t.Errorf("expected 0 records after delete, got %d", len(*records))
	}
}

func TestDeleteHostOverride_NonExistentRecord(t *testing.T) {
	records := &[]DNSRecord{}
	c := newTestClient(t, records)

	ep := &endpoint.Endpoint{
		DNSName:    "nonexistent.avril",
		RecordType: "A",
		Targets:    endpoint.NewTargets("192.168.1.99"),
	}

	// Should not panic or return an error
	if err := c.DeleteHostOverride(ep); err != nil {
		t.Fatalf("expected nil error for non-existent record, got: %v", err)
	}
}

func TestRecords_ReturnsCorrectEndpoints(t *testing.T) {
	records := &[]DNSRecord{
		{
			Uuid:     "uuid-1",
			Enabled:  "1",
			Hostname: "jellyfin",
			Domain:   "avril",
			Rr:       "A (IPv4 address)",
			Server:   "192.168.1.50",
		},
		{
			Uuid:     "uuid-2",
			Enabled:  "1",
			Hostname: "auth",
			Domain:   "avril",
			Rr:       "A (IPv4 address)",
			Server:   "192.168.1.51",
		},
	}
	c := newTestClient(t, records)

	provider := &Provider{
		client:       c,
		domainFilter: endpoint.NewDomainFilter([]string{"avril"}),
	}

	eps, err := provider.Records(nil)
	if err != nil {
		t.Fatalf("Records: %v", err)
	}
	if len(eps) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(eps))
	}

	byName := map[string]*endpoint.Endpoint{}
	for _, ep := range eps {
		byName[ep.DNSName] = ep
	}

	jellyfinEp := byName["jellyfin.avril"]
	if jellyfinEp == nil {
		t.Fatal("expected jellyfin.avril endpoint")
	}
	if jellyfinEp.RecordType != "A" {
		t.Errorf("expected RecordType A, got %s", jellyfinEp.RecordType)
	}
	if len(jellyfinEp.Targets) != 1 || jellyfinEp.Targets[0] != "192.168.1.50" {
		t.Errorf("expected target 192.168.1.50, got %v", jellyfinEp.Targets)
	}
}
