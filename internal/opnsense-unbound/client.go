package opnsense

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/external-dns/endpoint"
)

// httpClient is the DNS provider client.
type httpClient struct {
	*Config
	*http.Client
}

const (
	opnsenseUnboundServicePath  = "%s/api/unbound/service/%s"
	opnsenseUnboundSettingsPath = "%s/api/unbound/settings/%s"
	// Hacky, but nice to have the delete as an explicit constant since it's destructive
	opnsenseUnboundSettingsPathDelete = "%s/api/unbound/settings/delHostOverride/%s"
)

// newOpnsenseClient creates a new DNS provider client.
func newOpnsenseClient(config *Config) (*httpClient, error) {

	// Create the HTTP client
	client := &httpClient{
		Config: config,
		Client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: config.SkipTLSVerify},
			},
		},
	}

	if err := client.login(); err != nil {
		return nil, err
	}

	return client, nil
}

// login performs a basic call to validate credentials
func (c *httpClient) login() error {

	// Perform the test call
	resp, err := c.doRequest(
		http.MethodGet,
		FormatUrl(opnsenseUnboundServicePath, c.Config.Host, "status"),
		nil,
	)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	// Check if the login was successful
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		log.Errorf("login failed: %s, response: %s", resp.Status, string(respBody))
		return fmt.Errorf("login failed: %s", resp.Status)
	}

	return nil
}

// doRequest makes an HTTP request to the Opnsense firewall.
func (c *httpClient) doRequest(method, path string, body io.Reader) (*http.Response, error) {
	log.Debugf("making %s request to %s", method, path)

	req, err := http.NewRequest(method, path, body)
	if err != nil {
		return nil, err
	}

	c.setHeaders(req)

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}

	log.Debugf("response code from %s request to %s: %d", method, path, resp.StatusCode)

	// If the status code is 401, re-login and retry the request
	if resp.StatusCode == http.StatusUnauthorized {
		log.Debugf("Received 401 Unauthorized, are your credentials correct?")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s request to %s was not successful: %d", method, path, resp.StatusCode)
	}

	return resp, nil
}

// GetHostOverrides retrieves the list of HostOverrides from the Opnsense Firewall's Unbound API.
// These are equivalent to A or AAAA records
func (c *httpClient) GetHostOverrides() ([]DNSRecord, error) {
	resp, err := c.doRequest(
		http.MethodGet,
		FormatUrl(opnsenseUnboundSettingsPath, c.Config.Host, "searchHostOverride"),
		nil,
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var records unboundRecordsList
	if err = json.NewDecoder(resp.Body).Decode(&records.Rows); err != nil {
		return nil, err
	}

	log.Debugf("retrieved records: %+v", records.Rows)

	return records.Rows, nil
}

// CreateHostOverride creates a new DNS A or AAAA record in the Opnsense Firewall's Unbound API.
func (c *httpClient) CreateHostOverride(endpoint *endpoint.Endpoint) (*DNSRecord, error) {

	SplittedHost := UnboundFQDNSplitter(endpoint.DNSName)

	jsonBody, err := json.Marshal(DNSRecord{
		Enabled:     "1",
		Rr:          endpoint.RecordType,
		Server:      endpoint.Targets[0],
		Hostname:    SplittedHost[0],
		Domain:      SplittedHost[1],
		Description: endpoint.SetIdentifier,
	})
	if err != nil {
		return nil, err
	}
	log.Debugf("POST: %+v", jsonBody)
	resp, err := c.doRequest(
		http.MethodPost,
		FormatUrl(opnsenseUnboundSettingsPath, c.Config.Host, "addHostOverride"),
		bytes.NewReader(jsonBody),
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var record DNSRecord
	if err = json.NewDecoder(resp.Body).Decode(&record); err != nil {
		return nil, err
	}
	log.Debugf("created record: %+v", record)

	return &record, nil
}

// DeleteHostOverride deletes a DNS record from the Opnsense Firewall's Unbound API.
func (c *httpClient) DeleteHostOverride(endpoint *endpoint.Endpoint) error {
	lookup, err := c.lookupHostOverrideIdentifier(endpoint.DNSName, endpoint.RecordType)
	if err != nil {
		return err
	}

	if _, err = c.doRequest(
		http.MethodPost,
		FormatUrl(opnsenseUnboundSettingsPathDelete, c.Config.Host, lookup.Uuid),
		nil,
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

	SplittedHost := UnboundFQDNSplitter(key)

	for _, r := range records {
		if r.Hostname == SplittedHost[0] && r.Domain == SplittedHost[1] && r.Rr == recordType {
			return &r, nil
		}
	}

	return nil, err
}

// ReconfigureUnbound performs a reconfigure action in Unbound after editing records
func (c *httpClient) ReconfigureUnbound() error {

	// Perform the test call
	resp, err := c.doRequest(
		http.MethodGet,
		FormatUrl(opnsenseUnboundServicePath, c.Config.Host, "reconfigure"),
		nil,
	)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	// Check if the login was successful
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		log.Errorf("login failed: %s, response: %s", resp.Status, string(respBody))
		return fmt.Errorf("reconfigure unbound failed: %s", resp.Status)
	}

	return nil
}

// setHeaders sets the headers for the HTTP request.
func (c *httpClient) setHeaders(req *http.Request) {
	// Add basic auth header
	opnsenseAuth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", c.Config.Key, c.Config.Secret)))
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", opnsenseAuth))
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json; charset=utf-8")
	// Log the request URL
	log.Debugf("Requesting %s", req.URL)
}
