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

// GetHostOverrides retrieves the list of HostOverrides from the Opnsense Firewall's Unbound API.
// These are equivalent to A, AAAA, or TXT records
func (c *httpClient) GetHostOverrides() ([]DNSRecord, error) {
	resp, err := c.doRequest(
		http.MethodGet,
		"settings/searchHostOverride",
		nil,
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var records unboundRecordsList
	if err = json.NewDecoder(resp.Body).Decode(&records); err != nil {
		return nil, err
	}

	log.Debugf("gethost: retrieved records: %+v", records.Rows)

	if records.Rows == nil {
		return []DNSRecord{}, nil
	}
	return records.Rows, nil
}

// GetHostAliases retrieves the list of HostAliases from the Opnsense Firewall's Unbound API.
// These are equivalent to CNAME records
func (c *httpClient) GetHostAliases() ([]DNSAlias, error) {
	resp, err := c.doRequest(
		http.MethodGet,
		"settings/searchHostAlias",
		nil,
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var aliases unboundAliasesList
	if err = json.NewDecoder(resp.Body).Decode(&aliases); err != nil {
		return nil, err
	}

	log.Debugf("getaliases: retrieved aliases: %+v", aliases.Rows)

	return aliases.Rows, nil
}

// CreateHostOverride creates a new DNS A, AAAA, or TXT record in the Opnsense Firewall's Unbound API.
func (c *httpClient) CreateHostOverride(endpoint *endpoint.Endpoint) (*DNSRecord, error) {
	log.Debugf("create: Try pulling pre-existing Unbound %s record: %s", endpoint.RecordType, endpoint.DNSName)
	lookup, err := c.lookupHostOverrideIdentifier(endpoint.DNSName, endpoint.RecordType)
	if err != nil {
		return nil, err
	}

	if lookup != nil {
		log.Debugf("create: Found uuid: %s", lookup.Uuid)
		log.Debugf("create: Found existing %s record for %s : %s", endpoint.RecordType, endpoint.DNSName, lookup.Uuid)
		return lookup, nil
	}

	splitHost := SplitUnboundFQDN(endpoint.DNSName)

	record := DNSRecord{
		Enabled:  "1",
		Rr:       endpoint.RecordType,
		Hostname: splitHost[0],
		Domain:   splitHost[1],
	}

	if endpoint.RecordType == "TXT" {
		record.TxtData = endpoint.Targets[0]
	} else {
		record.Server = endpoint.Targets[0]
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

	// TODO: Better error handling if API returns:
	// {"result":"failed"}
	//if resp.Body != nil && resp.Body

	var respRecord unboundAddHostOverride
	if err = json.NewDecoder(resp.Body).Decode(&respRecord); err != nil {
		return nil, err
	}
	log.Debugf("create: created record: %+v", respRecord)

	return nil, nil
}

// CreateHostAlias creates a new DNS CNAME record in the Opnsense Firewall's Unbound API.
func (c *httpClient) CreateHostAlias(endpoint *endpoint.Endpoint) (*DNSAlias, error) {
	log.Debugf("create: Try pulling pre-existing Unbound CNAME record: %s", endpoint.DNSName)
	lookup, err := c.lookupHostAliasIdentifier(endpoint.DNSName)
	if err != nil {
		return nil, err
	}

	if lookup != nil {
		log.Debugf("create: Found uuid: %s", lookup.Uuid)
		log.Debugf("create: Found existing CNAME record for %s : %s", endpoint.DNSName, lookup.Uuid)
		return lookup, nil
	}

	// For CNAME, we need to find the target host override first
	targetHost := endpoint.Targets[0]
	targetOverride, err := c.lookupHostOverrideIdentifier(targetHost, "A")
	if err != nil {
		return nil, fmt.Errorf("failed to find target host override for %s: %w", targetHost, err)
	}
	if targetOverride == nil {
		return nil, fmt.Errorf("target host override not found for %s", targetHost)
	}

	splitHost := SplitUnboundFQDN(endpoint.DNSName)

	jsonBody, err := json.Marshal(unboundAddHostAlias{
		Alias: DNSAlias{
			Enabled:  "1",
			Host:     targetOverride.Uuid,
			Hostname:    splitHost[0],
			Domain:   splitHost[1],
		}})
	if err != nil {
		return nil, err
	}

	log.Debugf("create: POST CNAME: %s", string(jsonBody))
	resp, err := c.doRequest(
		http.MethodPost,
		"settings/addHostAlias",
		bytes.NewReader(jsonBody),
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var alias unboundAddHostAlias
	if err = json.NewDecoder(resp.Body).Decode(&alias); err != nil {
		return nil, err
	}
	log.Debugf("create: created alias: %+v", alias)

	return nil, nil
}

// DeleteHostOverride deletes a DNS record from the Opnsense Firewall's Unbound API.
func (c *httpClient) DeleteHostOverride(endpoint *endpoint.Endpoint) error {
	log.Debugf("delete: Deleting record %+v", endpoint)
	lookup, err := c.lookupHostOverrideIdentifier(endpoint.DNSName, endpoint.RecordType)
	if err != nil {
		return err
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

// DeleteHostAlias deletes a DNS CNAME record from the Opnsense Firewall's Unbound API.
func (c *httpClient) DeleteHostAlias(endpoint *endpoint.Endpoint) error {
	log.Debugf("delete: Deleting CNAME record %+v", endpoint)
	lookup, err := c.lookupHostAliasIdentifier(endpoint.DNSName)
	if err != nil {
		return err
	}

	if lookup == nil {
		log.Debugf("delete: CNAME record not found for %s", endpoint.DNSName)
		return nil
	}

	log.Debugf("delete: Found CNAME match %s", lookup.Uuid)

	log.Debugf("delete: Sending POST CNAME %s", lookup.Uuid)
	if _, err = c.doRequest(
		http.MethodPost,
		path.Join("settings/delHostAlias", lookup.Uuid),
		strings.NewReader(emptyJSONObject),
	); err != nil {
		return err
	}

	return nil
}

// lookupHostOverrideIdentifier finds a HostOverride in the Opnsense Firewall's Unbound API.
func (c *httpClient) lookupHostOverrideIdentifier(key, recordType string) (*DNSRecord, error) {
	records, err := c.GetHostOverrides()
	if err != nil {
		return nil, err
	}
	log.Debug("lookup: Splitting FQDN")
	splitHost := SplitUnboundFQDN(key)

	for _, r := range records {
		log.Debugf("lookup: Checking record: Host=%s, Domain=%s, Type=%s, UUID=%s", r.Hostname, r.Domain, EmbellishUnboundType(r.Rr), r.Uuid)
		if r.Hostname == splitHost[0] && r.Domain == splitHost[1] && EmbellishUnboundType(r.Rr) == EmbellishUnboundType(recordType) {
			log.Debugf("lookup: UUID Match Found: %s", r.Uuid)
			return &r, nil
		}
	}
	log.Debugf("lookup: No matching record found for Host=%s, Domain=%s, Type=%s", splitHost[0], splitHost[1], EmbellishUnboundType(recordType))
	return nil, nil
}

// lookupHostAliasIdentifier finds a HostAlias in the Opnsense Firewall's Unbound API.
func (c *httpClient) lookupHostAliasIdentifier(key string) (*DNSAlias, error) {
	aliases, err := c.GetHostAliases()
	if err != nil {
		return nil, err
	}
	log.Debug("lookup: Splitting FQDN for alias")
	splitHost := SplitUnboundFQDN(key)

	for _, a := range aliases {
		log.Debugf("lookup: Checking alias: Alias=%s, Domain=%s, UUID=%s", a.Hostname, a.Domain, a.Uuid)
		if a.Hostname == splitHost[0] && a.Domain == splitHost[1] {
			log.Debugf("lookup: Alias UUID Match Found: %s", a.Uuid)
			return &a, nil
		}
	}
	log.Debugf("lookup: No matching alias found for Alias=%s, Domain=%s", splitHost[0], splitHost[1])
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
