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

// dnsmasqPlugin implements pluginBackend for OPNsense dnsmasq.
type dnsmasqPlugin struct{}

// Dnsmasq can represent CNAMEs, as a list on the target host entry.
var _ cnameBackend = (*dnsmasqPlugin)(nil)

// setHostPath is the endpoint for updating an existing host entry. Only the
// fields present in the request body are changed, so it can be used to rewrite
// the cnames list without resending the rest of the entry.
const dnsmasqSetHostPath = "settings/setHost/"

// Wire types — only used for JSON marshaling/unmarshaling within this file.

type dnsmasqSearchRow struct {
	UUID   string `json:"uuid"`
	Host   string `json:"host"`
	Domain string `json:"domain"`
	IP     string `json:"ip"`

	// Cnames is a comma-separated list of FQDNs that alias this entry.
	// Added in OPNsense 25.7; empty on earlier releases.
	Cnames string `json:"cnames"`
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

// dnsmasqSetCnamesBody carries only the cnames field, so that updating it
// leaves the rest of the host entry untouched.
type dnsmasqSetCnamesBody struct {
	Host struct {
		Cnames string `json:"cnames"`
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
	case "A", "AAAA", "CNAME":
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

// Dnsmasq stores CNAMEs as a comma-separated cnames list on the host entry they
// point at, rendered into dnsmasq.conf as "cname=<aliases>,<target fqdn>".
// Managing one is therefore a read-modify-write of the target entry, and a
// CNAME cannot exist without a host entry to hang it off.

// splitCnames parses a cnames list, dropping blanks and surrounding whitespace.
func splitCnames(list string) []string {
	names := make([]string, 0, 4)
	for _, name := range strings.Split(list, ",") {
		if name = strings.TrimSpace(name); name != "" {
			names = append(names, name)
		}
	}
	return names
}

// fetchRows retrieves the raw host rows, which carry the cnames column that the
// normalized record type does not.
func (d *dnsmasqPlugin) fetchRows(c *httpClient) ([]dnsmasqSearchRow, error) {
	resp, err := c.search(d.searchPath())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var decoded dnsmasqSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return nil, err
	}
	return decoded.Rows, nil
}

// setCnames rewrites the cnames list of a single host entry. Fields omitted
// from the body are left untouched by the OPNsense API.
func (d *dnsmasqPlugin) setCnames(c *httpClient, uuid string, names []string) error {
	var body dnsmasqSetCnamesBody
	body.Host.Cnames = strings.Join(names, ",")

	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}

	log.Debugf("setCnames: POST %s body: %s", dnsmasqSetHostPath+uuid, string(encoded))

	resp, err := c.doRequest(http.MethodPost, dnsmasqSetHostPath+uuid, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func (d *dnsmasqPlugin) listCNAMEs(c *httpClient, records []record) ([]record, error) {
	rows, err := d.fetchRows(c)
	if err != nil {
		return nil, err
	}

	var cnames []record
	for _, row := range rows {
		target := joinFQDN(row.Host, row.Domain)
		for _, name := range splitCnames(row.Cnames) {
			hostname, domain := splitFQDN(name)
			cnames = append(cnames, record{
				// There is no id of its own; the uuid is the entry this hangs off.
				uuid:       row.UUID,
				hostname:   hostname,
				domain:     domain,
				recordType: "CNAME",
				target:     target,
			})
		}
	}
	return cnames, nil
}

func (d *dnsmasqPlugin) createCNAME(c *httpClient, ep *endpoint.Endpoint) error {
	records, err := c.getPrimaryRecords()
	if err != nil {
		return err
	}
	target, err := resolveCNAMETarget(records, ep)
	if err != nil {
		return err
	}

	rows, err := d.fetchRows(c)
	if err != nil {
		return err
	}

	// The alias may already be recorded, either on this target or on another
	// entry left over from a previous target.
	for _, row := range rows {
		for _, name := range splitCnames(row.Cnames) {
			if name != ep.DNSName {
				continue
			}
			if row.UUID == target.uuid {
				log.Debugf("createCNAME: %s already aliases %s, skipping", ep.DNSName, target.uuid)
				return nil
			}
			// Pointing elsewhere now — drop it from the old entry first.
			log.Debugf("createCNAME: moving %s off entry %s", ep.DNSName, row.UUID)
			if err := d.setCnames(c, row.UUID, without(splitCnames(row.Cnames), ep.DNSName)); err != nil {
				return err
			}
		}
	}

	current := currentCnames(rows, target.uuid)
	return d.setCnames(c, target.uuid, append(current, ep.DNSName))
}

func (d *dnsmasqPlugin) deleteCNAME(c *httpClient, ep *endpoint.Endpoint) error {
	rows, err := d.fetchRows(c)
	if err != nil {
		return err
	}

	for _, row := range rows {
		names := splitCnames(row.Cnames)
		remaining := without(names, ep.DNSName)
		if len(remaining) == len(names) {
			continue
		}

		log.Debugf("deleteCNAME: removing %s from entry %s", ep.DNSName, row.UUID)
		return d.setCnames(c, row.UUID, remaining)
	}

	log.Debugf("deleteCNAME: no entry aliases %s, skipping", ep.DNSName)
	return nil
}

// currentCnames returns the cnames list of the row with the given uuid.
func currentCnames(rows []dnsmasqSearchRow, uuid string) []string {
	for _, row := range rows {
		if row.UUID == uuid {
			return splitCnames(row.Cnames)
		}
	}
	return nil
}

// without returns names with every occurrence of drop removed.
func without(names []string, drop string) []string {
	kept := make([]string, 0, len(names))
	for _, name := range names {
		if name != drop {
			kept = append(kept, name)
		}
	}
	return kept
}
