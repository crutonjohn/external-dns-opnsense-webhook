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
