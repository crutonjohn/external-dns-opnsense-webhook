package opnsense

import (
	"encoding/json"
	"io"
	"strings"

	"sigs.k8s.io/external-dns/endpoint"
)

// unboundPlugin implements pluginBackend for OPNsense Unbound.
type unboundPlugin struct{}

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

func (u *unboundPlugin) basePath() string     { return "api/unbound/" }
func (u *unboundPlugin) searchMethod() string { return "GET" }
func (u *unboundPlugin) searchPath() string   { return "settings/searchHostOverride" }
func (u *unboundPlugin) searchBodyStr() string { return "" }
func (u *unboundPlugin) addPath() string      { return "settings/addHostOverride" }
func (u *unboundPlugin) delPath(uuid string) string {
	return "settings/delHostOverride/" + uuid
}

func (u *unboundPlugin) supportsType(recordType string) bool {
	switch recordType {
	case "A", "AAAA", "TXT":
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
