package opnsense

import (
	"encoding/json"
	"io"

	"sigs.k8s.io/external-dns/endpoint"
)

// dnsmasqPlugin implements pluginBackend for OPNsense dnsmasq.
type dnsmasqPlugin struct{}

// Wire types — only used for JSON marshaling/unmarshaling within this file.

type dnsmasqSearchRow struct {
	UUID   string `json:"uuid"`
	Host   string `json:"host"`
	Domain string `json:"domain"`
	IP     string `json:"ip"`
}

type dnsmasqSearchResponse struct {
	Rows []dnsmasqSearchRow `json:"rows"`
}

type dnsmasqAddBody struct {
	Host struct {
		Host   string `json:"host"`
		Domain string `json:"domain"`
		IP     string `json:"ip"`
	} `json:"host"`
}

func (d *dnsmasqPlugin) basePath() string      { return "api/dnsmasq/" }
func (d *dnsmasqPlugin) searchMethod() string  { return "POST" }
func (d *dnsmasqPlugin) searchPath() string    { return "settings/searchHost" }
func (d *dnsmasqPlugin) searchBodyStr() string { return "{}" }
func (d *dnsmasqPlugin) addPath() string       { return "settings/addHost" }
func (d *dnsmasqPlugin) delPath(uuid string) string {
	return "settings/delHost/" + uuid
}

func (d *dnsmasqPlugin) supportsType(recordType string) bool {
	switch recordType {
	case "A", "AAAA":
		return true
	}
	return false
}

func (d *dnsmasqPlugin) decodeRecords(body io.Reader) ([]record, error) {
	var resp dnsmasqSearchResponse
	if err := json.NewDecoder(body).Decode(&resp); err != nil {
		return nil, err
	}

	records := make([]record, 0, len(resp.Rows))
	for _, row := range resp.Rows {
		records = append(records, record{
			uuid:       row.UUID,
			hostname:   row.Host,
			domain:     row.Domain,
			recordType: recordTypeFromIP(row.IP),
			target:     row.IP,
		})
	}
	return records, nil
}

func (d *dnsmasqPlugin) encodeRecord(ep *endpoint.Endpoint) ([]byte, error) {
	hostname, domain := splitFQDN(ep.DNSName)

	var body dnsmasqAddBody
	body.Host.Host = hostname
	body.Host.Domain = domain
	body.Host.IP = ep.Targets[0]

	return json.Marshal(body)
}
