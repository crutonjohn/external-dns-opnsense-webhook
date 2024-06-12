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

// Records returns the list of HostOverride records in Opnsense Unbound.
func (p *Provider) Records(ctx context.Context) ([]*endpoint.Endpoint, error) {
	log.Debugf("records: retrieving records from opnsense")

	records, err := p.client.GetHostOverrides()
	if err != nil {
		return nil, err
	}

	var endpoints []*endpoint.Endpoint
	for _, record := range records {
		ep := &endpoint.Endpoint{
			DNSName:    JoinUnboundFQDN(record.Hostname, record.Domain),
			RecordType: PruneUnboundType(record.Rr),
			Targets:    endpoint.NewTargets(record.Server),
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
		if err := p.client.DeleteHostOverride(endpoint); err != nil {
			return err
		}
	}

	for _, endpoint := range append(changes.Create, changes.UpdateNew...) {
		if _, err := p.client.CreateHostOverride(endpoint); err != nil {
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
