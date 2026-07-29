package opnsense

import (
	"fmt"
	"io"

	"sigs.k8s.io/external-dns/endpoint"
)

// pluginBackend abstracts the API differences between OPNsense DNS plugins.
// Each plugin implementation handles its own wire format and endpoint paths.
type pluginBackend interface {
	// basePath is the API namespace root, e.g. "api/unbound/" or "api/dnsmasq/".
	basePath() string

	// searchMethod and searchPath describe how to list records.
	// searchBodyStr returns the request body string; "" means no body (GET).
	searchMethod() string
	searchPath() string
	searchBodyStr() string

	// addPath and delPath return the endpoint paths for mutations.
	addPath() string
	delPath(uuid string) string

	// decodeRecords parses a search response body into normalized records.
	decodeRecords(body io.Reader) ([]record, error)

	// encodeRecord serializes an endpoint into the add-host request body.
	// Only called when supportsType returns true for the endpoint's record type.
	encodeRecord(ep *endpoint.Endpoint) ([]byte, error)

	// supportsType reports whether this plugin can handle the given record type.
	supportsType(recordType string) bool
}

// cnameBackend is an optional extension implemented by plugins that can
// represent CNAME records.
//
// The two OPNsense plugins model CNAMEs too differently to share paths and
// codecs the way pluginBackend does. Unbound stores them as standalone Host
// Aliases that reference their target by UUID, so they are created and deleted
// on their own endpoints. Dnsmasq stores them as a comma-separated list on the
// target host entry, so managing one is a read-modify-write of that entry.
// Each plugin therefore implements the operations itself.
//
// In both cases a CNAME can only exist alongside its target: the target must
// already be present as an A or AAAA record.
type cnameBackend interface {
	// listCNAMEs returns the CNAME records the plugin is currently storing.
	// records holds the primary records already fetched by the caller, so
	// implementations can resolve targets without refetching them.
	listCNAMEs(c *httpClient, records []record) ([]record, error)

	// createCNAME stores a CNAME. It returns an error if the target does not
	// resolve to an existing record.
	createCNAME(c *httpClient, ep *endpoint.Endpoint) error

	// deleteCNAME removes a CNAME. One that is already absent is not an error.
	deleteCNAME(c *httpClient, ep *endpoint.Endpoint) error
}

// newPlugin returns the pluginBackend for the given plugin name.
func newPlugin(name string) (pluginBackend, error) {
	switch name {
	case "unbound":
		return &unboundPlugin{}, nil
	case "dnsmasq":
		return &dnsmasqPlugin{}, nil
	default:
		return nil, fmt.Errorf("unknown OPNSENSE_PLUGIN %q: must be \"unbound\" or \"dnsmasq\"", name)
	}
}
