package opnsense

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/external-dns/endpoint"
)

// unboundPlugin implements pluginBackend for OPNsense Unbound.
type unboundPlugin struct{}

// Unbound can represent CNAMEs, as Host Aliases.
var _ cnameBackend = (*unboundPlugin)(nil)

// Wire types — only used for JSON marshaling/unmarshaling within this file.

type unboundSearchRow struct {
	UUID     string `json:"uuid"`
	Hostname string `json:"hostname"`
	Domain   string `json:"domain"`
	Rr       string `json:"rr"`
	Server   string `json:"server"`
	TxtData  string `json:"txtdata"`
}

type unboundSearchResponse struct {
	Rows []unboundSearchRow `json:"Rows"`
}

type unboundAddBody struct {
	Host struct {
		Enabled  string `json:"enabled"`
		Hostname string `json:"hostname"`
		Domain   string `json:"domain"`
		Rr       string `json:"rr"`
		Server   string `json:"server,omitempty"`
		TxtData  string `json:"txtdata,omitempty"`
	} `json:"host"`
}

type unboundAliasRow struct {
	UUID     string `json:"uuid"`
	Hostname string `json:"hostname"`
	Domain   string `json:"domain"`
	Host     string `json:"host"` // UUID of the host override this alias points at
}

type unboundAliasSearchResponse struct {
	Rows []unboundAliasRow `json:"Rows"`
}

type unboundAddAliasBody struct {
	Alias struct {
		Enabled  string `json:"enabled"`
		Hostname string `json:"hostname"`
		Domain   string `json:"domain"`
		Host     string `json:"host"`
	} `json:"alias"`
}

func (u *unboundPlugin) basePath() string      { return "api/unbound/" }
func (u *unboundPlugin) searchMethod() string  { return "GET" }
func (u *unboundPlugin) searchPath() string    { return "settings/searchHostOverride" }
func (u *unboundPlugin) searchBodyStr() string { return "" }
func (u *unboundPlugin) addPath() string       { return "settings/addHostOverride" }
func (u *unboundPlugin) delPath(uuid string) string {
	return "settings/delHostOverride/" + uuid
}

// Unbound stores CNAMEs as Host Aliases: standalone records in their own space,
// each referencing its target Host Override by UUID.
const (
	unboundAliasSearchPath = "settings/searchHostAlias"
	unboundAliasAddPath    = "settings/addHostAlias"
	unboundAliasDelPath    = "settings/delHostAlias/"
)

func (u *unboundPlugin) supportsType(recordType string) bool {
	switch recordType {
	case "A", "AAAA", "TXT", "CNAME":
		return true
	}
	return false
}

// pruneRR strips the parenthetical description Unbound appends to record types,
// e.g. "A (IPv4 address)" → "A".
func pruneRR(rr string) string {
	if i := strings.IndexByte(rr, ' '); i != -1 {
		return rr[:i]
	}
	return rr
}

func (u *unboundPlugin) decodeRecords(body io.Reader) ([]record, error) {
	var resp unboundSearchResponse
	if err := json.NewDecoder(body).Decode(&resp); err != nil {
		return nil, err
	}

	records := make([]record, 0, len(resp.Rows))
	for _, row := range resp.Rows {
		rt := pruneRR(row.Rr)
		target := row.Server
		if rt == "TXT" {
			target = row.TxtData
		}
		records = append(records, record{
			uuid:       row.UUID,
			hostname:   row.Hostname,
			domain:     row.Domain,
			recordType: rt,
			target:     target,
		})
	}
	return records, nil
}

func (u *unboundPlugin) encodeRecord(ep *endpoint.Endpoint) ([]byte, error) {
	hostname, domain := splitFQDN(ep.DNSName)

	var body unboundAddBody
	body.Host.Enabled = "1"
	body.Host.Hostname = hostname
	body.Host.Domain = domain
	body.Host.Rr = ep.RecordType

	if ep.RecordType == "TXT" {
		body.Host.TxtData = ep.Targets[0]
	} else {
		body.Host.Server = ep.Targets[0]
	}

	return json.Marshal(body)
}

// fetchAliases retrieves the raw Host Alias rows.
func (u *unboundPlugin) fetchAliases(c *httpClient) ([]unboundAliasRow, error) {
	resp, err := c.search(unboundAliasSearchPath)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var decoded unboundAliasSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return nil, err
	}
	return decoded.Rows, nil
}

func (u *unboundPlugin) listCNAMEs(c *httpClient, records []record) ([]record, error) {
	aliases, err := u.fetchAliases(c)
	if err != nil {
		return nil, err
	}

	cnames := make([]record, 0, len(aliases))
	for _, a := range aliases {
		// An alias references its target by UUID; resolve it back to an FQDN.
		target := findByUUID(records, a.Host)
		if target == nil {
			log.Debugf("listCNAMEs: skipping alias %s: target uuid %s not found",
				joinFQDN(a.Hostname, a.Domain), a.Host)
			continue
		}
		cnames = append(cnames, record{
			uuid:       a.UUID,
			hostname:   a.Hostname,
			domain:     a.Domain,
			recordType: "CNAME",
			target:     joinFQDN(target.hostname, target.domain),
		})
	}
	return cnames, nil
}

func (u *unboundPlugin) createCNAME(c *httpClient, ep *endpoint.Endpoint) error {
	existing, err := c.lookup(ep.DNSName, "CNAME")
	if err != nil {
		return err
	}
	if existing != nil {
		log.Debugf("createCNAME: alias for %s already exists (uuid=%s), skipping", ep.DNSName, existing.uuid)
		return nil
	}

	records, err := c.getPrimaryRecords()
	if err != nil {
		return err
	}
	target, err := resolveCNAMETarget(records, ep)
	if err != nil {
		return err
	}

	hostname, domain := splitFQDN(ep.DNSName)

	var body unboundAddAliasBody
	body.Alias.Enabled = "1"
	body.Alias.Hostname = hostname
	body.Alias.Domain = domain
	body.Alias.Host = target.uuid

	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}

	log.Debugf("createCNAME: POST %s body: %s", unboundAliasAddPath, string(encoded))

	resp, err := c.doRequest(http.MethodPost, unboundAliasAddPath, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func (u *unboundPlugin) deleteCNAME(c *httpClient, ep *endpoint.Endpoint) error {
	existing, err := c.lookup(ep.DNSName, "CNAME")
	if err != nil {
		return err
	}
	if existing == nil {
		log.Debugf("deleteCNAME: no alias found for %s, skipping", ep.DNSName)
		return nil
	}

	log.Debugf("deleteCNAME: deleting alias %s (uuid=%s)", ep.DNSName, existing.uuid)

	resp, err := c.doRequest(
		http.MethodPost,
		unboundAliasDelPath+existing.uuid,
		strings.NewReader(emptyJSONObject),
	)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}
