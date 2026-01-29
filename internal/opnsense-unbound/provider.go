package opnsense

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
	"sigs.k8s.io/external-dns/provider"
)

// Provider type for interfacing with Opnsense
type Provider struct {
	provider.BaseProvider

	client       *httpClient
	domainFilter endpoint.DomainFilter
}

// NewOpnsenseProvider initializes a new DNSProvider.
func NewOpnsenseProvider(domainFilter endpoint.DomainFilter, config *Config) (provider.Provider, error) {
	c, err := newOpnsenseClient(config)

	if err != nil {
		return nil, fmt.Errorf("provider: failed to create the opnsense client: %w", err)
	}

	p := &Provider{
		client:       c,
		domainFilter: domainFilter,
	}

	return p, nil
}

// Records returns the list of HostOverride and HostAlias records in Opnsense Unbound.
func (p *Provider) Records(ctx context.Context) ([]*endpoint.Endpoint, error) {
	log.Debugf("records: retrieving records from opnsense")

	records, err := p.client.GetHostOverrides()
	if err != nil {
		return nil, err
	}

	aliases, err := p.client.GetHostAliases()
	if err != nil {
		return nil, err
	}

	// Process A/AAAA/TXT records
	var endpoints []*endpoint.Endpoint
	for _, record := range records {
		var targets endpoint.Targets
		recordType := PruneUnboundType(record.Rr)

		if recordType == "TXT" {
			targets = endpoint.NewTargets(record.TxtData)
		} else {
			targets = endpoint.NewTargets(record.Server)
		}

		ep := &endpoint.Endpoint{
			DNSName:    JoinUnboundFQDN(record.Hostname, record.Domain),
			RecordType: recordType,
			Targets:    targets,
		}

		if !p.domainFilter.Match(ep.DNSName) {
			continue
		}

		endpoints = append(endpoints, ep)
	}

	// Process CNAME records (aliases)
	for _, alias := range aliases {
		// Find the target host override to get the target DNS name
		targetRecord, err := p.findHostOverrideByUUID(alias.Host)
		if err != nil {
			log.Debugf("records: failed to find target host for alias %s: %v", alias.Uuid, err)
			continue
		}
		if targetRecord == nil {
			log.Debugf("records: target host not found for alias %s", alias.Uuid)
			continue
		}

		ep := &endpoint.Endpoint{
			DNSName:    JoinUnboundFQDN(alias.Hostname, alias.Domain),
			RecordType: "CNAME",
			Targets:    endpoint.NewTargets(JoinUnboundFQDN(targetRecord.Hostname, targetRecord.Domain)),
		}

		if !p.domainFilter.Match(ep.DNSName) {
			continue
		}

		endpoints = append(endpoints, ep)
	}

	log.Debugf("records: retrieved: %+v", endpoints)

	return endpoints, nil
}

// ApplyChanges applies a given set of changes in the DNS provider.
func (p *Provider) ApplyChanges(ctx context.Context, changes *plan.Changes) error {
	for _, endpoint := range append(changes.UpdateOld, changes.Delete...) {
		if endpoint.RecordType == "CNAME" {
			if err := p.client.DeleteHostAlias(endpoint); err != nil {
				return err
			}
		} else {
			if err := p.client.DeleteHostOverride(endpoint); err != nil {
				return err
			}
		}
	}
	var isCNAME map[bool][]*endpoint.Endpoint = make(map[bool][]*endpoint.Endpoint)

	for _, endpoint := range append(changes.Create, changes.UpdateNew...) {
		isCNAME[endpoint.RecordType == "CNAME"] = append(isCNAME[endpoint.RecordType == "CNAME"], endpoint)
	}

	// It is important to apply the CNAME changes after the overrides have been applied
	// if not, validation will fail when trying to create an alias without a valid hostname
	for _, endpoint := range isCNAME[false] {
		if _, err := p.client.CreateHostOverride(endpoint); err != nil {
			return err
		}
	}
	for _, endpoint := range isCNAME[true] {
		if _, err := p.client.CreateHostAlias(endpoint); err != nil {
			return err
		}
	}

	p.client.ReconfigureUnbound()

	return nil
}

// GetDomainFilter returns the domain filter for the provider.
func (p *Provider) GetDomainFilter() endpoint.DomainFilter {
	return p.domainFilter
}

// findHostOverrideByUUID finds a host override by its UUID.
func (p *Provider) findHostOverrideByUUID(uuid string) (*DNSRecord, error) {
	records, err := p.client.GetHostOverrides()
	if err != nil {
		return nil, err
	}

	for _, record := range records {
		if record.Uuid == uuid {
			return &record, nil
		}
	}

	return nil, nil
}
