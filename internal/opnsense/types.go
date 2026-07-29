package opnsense

// Config holds the configuration for connecting to the OPNsense API.
type Config struct {
	Host          string `env:"OPNSENSE_HOST,notEmpty"`
	Key           string `env:"OPNSENSE_API_KEY,notEmpty"`
	Secret        string `env:"OPNSENSE_API_SECRET,notEmpty"`
	SkipTLSVerify bool   `env:"OPNSENSE_SKIP_TLS_VERIFY" envDefault:"true"`
	Plugin        string `env:"OPNSENSE_PLUGIN" envDefault:"unbound"`
}

// record is the normalized internal representation of a DNS entry,
// independent of which OPNsense plugin is in use.
type record struct {
	uuid       string
	hostname   string
	domain     string
	recordType string // "A", "AAAA", "TXT", or "CNAME"
	target     string // IP address for A/AAAA, text content for TXT, FQDN for CNAME
}
