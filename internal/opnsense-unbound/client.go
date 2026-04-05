package opnsense

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"

	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/external-dns/endpoint"
)

const emptyJSONObject = "{}"

// httpClient is the DNS provider client.
type httpClient struct {
	*Config
	*http.Client
	baseURL *url.URL
}

// newOpnsenseClient creates a new DNS provider client.
func newOpnsenseClient(config *Config) (*httpClient, error) {
	u, err := url.Parse(config.Host)
	if err != nil {
		return nil, fmt.Errorf("parse url: %w", err)
	}

	// Ensure the base path is correctly set
	basePath, err := url.Parse("api/unbound/")
	if err != nil {
		return nil, fmt.Errorf("parse base path: %w", err)
	}
	u = u.ResolveReference(basePath)

	// Create the HTTP client
	client := &httpClient{
		Config: config,
		Client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: config.SkipTLSVerify},
			},
		},
		baseURL: u,
	}

	if err := client.login(); err != nil {
		return nil, err
	}

	return client, nil
}

// login performs a basic call to validate credentials
func (c *httpClient) login() error {
	// Perform the test call by getting service status
	resp, err := c.doRequest(
		http.MethodGet,
		"service/status",
		nil,
	)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	// Check if the login was successful
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		log.Errorf("login: failed: %s, response: %s", resp.Status, string(respBody))
		return fmt.Errorf("login: failed: %s", resp.Status)
	}

	return nil
}

// doRequest makes an HTTP request to the Opnsense firewall.
func (c *httpClient) doRequest(method, path string, body io.Reader) (*http.Response, error) {
	u := c.baseURL.ResolveReference(&url.URL{
		Path: path,
	})

	log.Debugf("doRequest: making %s request to %s", method, u)

	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		return nil, err
	}

	c.setHeaders(req)

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}

	log.Debugf("doRequest: response code from %s request to %s: %d", method, u, resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		return nil, fmt.Errorf("doRequest: %s request to %s was not successful: %d", method, u, resp.StatusCode)
	}

	return resp, nil
}

// GetHostOverrides retrieves all HostOverrides from the Opnsense Firewall's Unbound API.
// These are equivalent to A, AAAA, or TXT records.
// We POST with rowCount=-1 to request all records in a single response rather than relying
// on the default pagination which may return only a subset.
func (c *httpClient) GetHostOverrides() ([]DNSRecord, error) {
	resp, err := c.doRequest(
		http.MethodPost,
		"settings/searchHostOverride",
		strings.NewReader(`{"current":1,"rowCount":-1,"sort":{},"searchPhrase":""}`),
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var records unboundRecordsList
	if err = json.NewDecoder(resp.Body).Decode(&records); err != nil {
		return nil, err
	}

	log.Debugf("gethost: retrieved %d/%d records", len(records.Rows), records.Total)

	if records.Rows == nil {
		return []DNSRecord{}, nil
	}
	return records.Rows, nil
}

// CreateHostOverride creates a DNS A, AAAA, or TXT record in the Opnsense Firewall's Unbound API.
// Each endpoint is expected to carry exactly one target (see AdjustEndpoints). If a record already
// exists with the same name, type, and target it is a no-op.
func (c *httpClient) CreateHostOverride(ep *endpoint.Endpoint) (*DNSRecord, error) {
	log.Debugf("create: Try pulling pre-existing Unbound %s record: %s", ep.RecordType, ep.DNSName)
	lookup, err := c.lookupHostOverrideIdentifier(ep.DNSName, ep.RecordType, ep.Targets[0])
	if err != nil {
		return nil, err
	}

	if lookup != nil {
		log.Debugf("create: exact %s record for %s → %s already exists, skipping", ep.RecordType, ep.DNSName, ep.Targets[0])
		return lookup, nil
	}

	splitHost := SplitUnboundFQDN(ep.DNSName)

	record := DNSRecord{
		Enabled:  "1",
		Rr:       ep.RecordType,
		Hostname: splitHost[0],
		Domain:   splitHost[1],
	}

	if ep.RecordType == "TXT" {
		record.TxtData = ep.Targets[0]
	} else {
		record.Server = ep.Targets[0]
	}

	jsonBody, err := json.Marshal(unboundAddHostOverride{
		Host: record,
	})
	if err != nil {
		return nil, err
	}

	log.Debugf("create: POST: %s", string(jsonBody))
	resp, err := c.doRequest(
		http.MethodPost,
		"settings/addHostOverride",
		bytes.NewReader(jsonBody),
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var apiResp unboundHostOverrideResponse
	if err = json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, err
	}
	if apiResp.Result != "saved" {
		return nil, fmt.Errorf("create: addHostOverride returned result %q for %s", apiResp.Result, ep.DNSName)
	}
	record.Uuid = apiResp.UUID
	log.Debugf("create: created record %s with uuid %s", ep.DNSName, record.Uuid)

	return &record, nil
}

// DeleteHostOverride deletes a DNS record from the Opnsense Firewall's Unbound API.
func (c *httpClient) DeleteHostOverride(endpoint *endpoint.Endpoint) error {
	log.Debugf("delete: Deleting record %+v", endpoint)
	lookup, err := c.lookupHostOverrideIdentifier(endpoint.DNSName, endpoint.RecordType, endpoint.Targets[0])
	if err != nil {
		return err
	}

	if lookup == nil {
		log.Debugf("delete: no %s record found for %s, skipping", endpoint.RecordType, endpoint.DNSName)
		return nil
	}

	log.Debugf("delete: Found match %s", lookup.Uuid)

	log.Debugf("delete: Sending POST %s", lookup.Uuid)
	resp, err := c.doRequest(
		http.MethodPost,
		path.Join("settings/delHostOverride", lookup.Uuid),
		strings.NewReader(emptyJSONObject),
	)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// lookupHostOverrideIdentifier finds a HostOverride in the Opnsense Firewall's Unbound API
// that matches the given name, record type, and target value.
func (c *httpClient) lookupHostOverrideIdentifier(key, recordType, target string) (*DNSRecord, error) {
	records, err := c.GetHostOverrides()
	if err != nil {
		return nil, err
	}
	log.Debug("lookup: Splitting FQDN")
	splitHost := SplitUnboundFQDN(key)

	for _, r := range records {
		log.Debugf("lookup: Checking record: Host=%s, Domain=%s, Type=%s, UUID=%s", r.Hostname, r.Domain, EmbellishUnboundType(r.Rr), r.Uuid)
		if r.Hostname != splitHost[0] || r.Domain != splitHost[1] || EmbellishUnboundType(r.Rr) != EmbellishUnboundType(recordType) {
			continue
		}
		var recordTarget string
		if PruneUnboundType(r.Rr) == "TXT" {
			recordTarget = r.TxtData
		} else {
			recordTarget = r.Server
		}
		if recordTarget != target {
			continue
		}
		log.Debugf("lookup: UUID Match Found: %s", r.Uuid)
		return &r, nil
	}
	log.Debugf("lookup: No matching record found for Host=%s, Domain=%s, Type=%s, Target=%s", splitHost[0], splitHost[1], EmbellishUnboundType(recordType), target)
	return nil, nil
}

// ReconfigureUnbound performs a reconfigure action in Unbound after editing records
func (c *httpClient) ReconfigureUnbound() error {
	// Perform the reconfigure
	resp, err := c.doRequest(
		http.MethodPost,
		"service/reconfigure",
		strings.NewReader(emptyJSONObject),
	)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	// Check if the login was successful
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		log.Errorf("reconfigure: login failed: %s, response: %s", resp.Status, string(respBody))
		return fmt.Errorf("reconfigure: unbound failed: %s", resp.Status)
	}

	return nil
}

// setHeaders sets the headers for the HTTP request.
func (c *httpClient) setHeaders(req *http.Request) {
	// Add basic auth header
	opnsenseAuth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", c.Config.Key, c.Config.Secret)))
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", opnsenseAuth))
	req.Header.Add("Accept", "application/json")
	if req.Method != http.MethodGet {
		req.Header.Add("Content-Type", "application/json; charset=utf-8")
	}
	// Log the request URL
	log.Debugf("headers: Requesting %s", req.URL)
}
