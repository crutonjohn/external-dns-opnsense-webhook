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

// getRecords fetches all DNS records via the active plugin.
func (c *httpClient) getRecords() ([]record, error) {
	var bodyReader io.Reader
	if s := c.plugin.searchBodyStr(); s != "" {
		bodyReader = strings.NewReader(s)
	}

	resp, err := c.doRequest(c.plugin.searchMethod(), c.plugin.searchPath(), bodyReader)
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

	r, err := c.lookup(ep.DNSName, ep.RecordType)
	if err != nil {
		return err
	}
	if r == nil {
		log.Debugf("deleteRecord: no matching %s record found for %s, skipping", ep.RecordType, ep.DNSName)
		return nil
	}

	log.Debugf("deleteRecord: deleting %s record %s (uuid=%s)", ep.RecordType, ep.DNSName, r.uuid)

	resp, err := c.doRequest(
		http.MethodPost,
		c.plugin.delPath(r.uuid),
		strings.NewReader(emptyJSONObject),
	)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// lookup searches the current records for one matching the given FQDN and record type.
func (c *httpClient) lookup(fqdn, recordType string) (*record, error) {
	records, err := c.getRecords()
	if err != nil {
		return nil, err
	}

	hostname, domain := splitFQDN(fqdn)
	for _, r := range records {
		if r.hostname == hostname && r.domain == domain && r.recordType == recordType {
			log.Debugf("lookup: matched uuid=%s for %s (%s)", r.uuid, fqdn, recordType)
			return &r, nil
		}
	}

	log.Debugf("lookup: no match found for %s (%s)", fqdn, recordType)
	return nil, nil
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
