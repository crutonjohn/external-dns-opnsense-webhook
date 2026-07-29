package opnsense

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/external-dns/endpoint"
)

const emptyJSONObject = "{}"

// httpClient is the shared DNS provider client.
type httpClient struct {
	*Config
	*http.Client
	baseURL *url.URL
	plugin  pluginBackend
}

// newOpnsenseClient creates a new DNS provider client, selecting the plugin
// backend from config.Plugin ("unbound" or "dnsmasq").
func newOpnsenseClient(config *Config) (*httpClient, error) {
	p, err := newPlugin(config.Plugin)
	if err != nil {
		return nil, err
	}

	u, err := url.Parse(config.Host)
	if err != nil {
		return nil, fmt.Errorf("parse url: %w", err)
	}

	basePath, err := url.Parse(p.basePath())
	if err != nil {
		return nil, fmt.Errorf("parse base path: %w", err)
	}
	u = u.ResolveReference(basePath)

	client := &httpClient{
		Config: config,
		Client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: config.SkipTLSVerify},
			},
		},
		baseURL: u,
		plugin:  p,
	}

	if err := client.login(); err != nil {
		return nil, err
	}

	return client, nil
}

// login validates credentials with a status check.
func (c *httpClient) login() error {
	resp, err := c.doRequest(http.MethodGet, "service/status", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// doRequest makes an authenticated HTTP request to the OPNsense firewall.
func (c *httpClient) doRequest(method, reqPath string, body io.Reader) (*http.Response, error) {
	u := c.baseURL.ResolveReference(&url.URL{Path: reqPath})

	log.Debugf("doRequest: %s %s", method, u)

	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		return nil, err
	}

	c.setHeaders(req)

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}

	log.Debugf("doRequest: response %d from %s %s", resp.StatusCode, method, u)

	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		return nil, fmt.Errorf("doRequest: %s %s returned %d", method, u, resp.StatusCode)
	}

	return resp, nil
}

// search issues the plugin's search request against the given path.
func (c *httpClient) search(reqPath string) (*http.Response, error) {
	var bodyReader io.Reader
	if s := c.plugin.searchBodyStr(); s != "" {
		bodyReader = strings.NewReader(s)
	}
	return c.doRequest(c.plugin.searchMethod(), reqPath, bodyReader)
}

// getPrimaryRecords fetches the records held in the plugin's main record space,
// excluding any separately-stored CNAME aliases.
func (c *httpClient) getPrimaryRecords() ([]record, error) {
	resp, err := c.search(c.plugin.searchPath())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	records, err := c.plugin.decodeRecords(resp.Body)
	if err != nil {
		return nil, err
	}

	if records == nil {
		return []record{}, nil
	}
	return records, nil
}

// getRecords fetches all DNS records via the active plugin, including CNAMEs
// for plugins that can represent them.
func (c *httpClient) getRecords() ([]record, error) {
	records, err := c.getPrimaryRecords()
	if err != nil {
		return nil, err
	}

	if cb, ok := c.plugin.(cnameBackend); ok {
		cnames, err := cb.listCNAMEs(c, records)
		if err != nil {
			return nil, err
		}
		records = append(records, cnames...)
	}

	log.Debugf("getRecords: retrieved %d records", len(records))
	return records, nil
}

// createRecord adds a new DNS record. Unsupported record types are skipped.
func (c *httpClient) createRecord(ep *endpoint.Endpoint) error {
	if !c.plugin.supportsType(ep.RecordType) {
		log.Warnf("createRecord: %s records are not supported by the %s plugin, skipping %s",
			ep.RecordType, c.Config.Plugin, ep.DNSName)
		return nil
	}

	if cb, ok := c.plugin.(cnameBackend); ok && ep.RecordType == "CNAME" {
		return cb.createCNAME(c, ep)
	}

	existing, err := c.lookup(ep.DNSName, ep.RecordType)
	if err != nil {
		return err
	}
	if existing != nil {
		log.Debugf("createRecord: %s record for %s already exists (uuid=%s), skipping",
			ep.RecordType, ep.DNSName, existing.uuid)
		return nil
	}

	body, err := c.plugin.encodeRecord(ep)
	if err != nil {
		return err
	}

	log.Debugf("createRecord: POST %s body: %s", c.plugin.addPath(), string(body))

	resp, err := c.doRequest(http.MethodPost, c.plugin.addPath(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// deleteRecord removes a DNS record. Unsupported or missing records are skipped.
func (c *httpClient) deleteRecord(ep *endpoint.Endpoint) error {
	if !c.plugin.supportsType(ep.RecordType) {
		log.Warnf("deleteRecord: %s records are not supported by the %s plugin, skipping %s",
			ep.RecordType, c.Config.Plugin, ep.DNSName)
		return nil
	}

	if cb, ok := c.plugin.(cnameBackend); ok && ep.RecordType == "CNAME" {
		return cb.deleteCNAME(c, ep)
	}

	r, err := c.lookup(ep.DNSName, ep.RecordType)
	if err != nil {
		return err
	}
	if r == nil {
		log.Debugf("deleteRecord: no matching %s record found for %s, skipping", ep.RecordType, ep.DNSName)
		return nil
	}

	log.Debugf("deleteRecord: deleting %s record %s (uuid=%s)", ep.RecordType, ep.DNSName, r.uuid)

	resp, err := c.doRequest(http.MethodPost, c.plugin.delPath(r.uuid), strings.NewReader(emptyJSONObject))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// resolveCNAMETarget finds the A or AAAA record a CNAME should point at.
// Both backends require the target to exist before the CNAME can be stored.
func resolveCNAMETarget(records []record, ep *endpoint.Endpoint) (*record, error) {
	targetFQDN := strings.TrimSuffix(ep.Targets[0], ".")

	target := findByName(records, targetFQDN, "A")
	if target == nil {
		target = findByName(records, targetFQDN, "AAAA")
	}
	if target == nil {
		return nil, fmt.Errorf("cannot create CNAME %s: no A or AAAA record exists for target %s",
			ep.DNSName, targetFQDN)
	}
	return target, nil
}

// lookup searches the current records for one matching the given FQDN and record type.
func (c *httpClient) lookup(fqdn, recordType string) (*record, error) {
	records, err := c.getRecords()
	if err != nil {
		return nil, err
	}

	if r := findByName(records, fqdn, recordType); r != nil {
		log.Debugf("lookup: matched uuid=%s for %s (%s)", r.uuid, fqdn, recordType)
		return r, nil
	}

	log.Debugf("lookup: no match found for %s (%s)", fqdn, recordType)
	return nil, nil
}

// findByName returns the record matching the given FQDN and record type, or nil.
func findByName(records []record, fqdn, recordType string) *record {
	hostname, domain := splitFQDN(fqdn)
	for i, r := range records {
		if r.hostname == hostname && r.domain == domain && r.recordType == recordType {
			return &records[i]
		}
	}
	return nil
}

// findByUUID returns the record with the given UUID, or nil.
func findByUUID(records []record, uuid string) *record {
	for i, r := range records {
		if r.uuid == uuid {
			return &records[i]
		}
	}
	return nil
}

// reconfigure triggers a service reload to apply pending changes.
func (c *httpClient) reconfigure() error {
	resp, err := c.doRequest(http.MethodPost, "service/reconfigure", strings.NewReader(emptyJSONObject))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// setHeaders adds auth and content-type headers to a request.
func (c *httpClient) setHeaders(req *http.Request) {
	auth := base64.StdEncoding.EncodeToString([]byte(c.Config.Key + ":" + c.Config.Secret))
	req.Header.Add("Authorization", "Basic "+auth)
	req.Header.Add("Accept", "application/json")
	if req.Method != http.MethodGet {
		req.Header.Add("Content-Type", "application/json; charset=utf-8")
	}
}
