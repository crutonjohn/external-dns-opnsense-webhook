package opnsense

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
	"sigs.k8s.io/external-dns/provider"
)

// Provider implements the external-dns provider interface for OPNsense.
type Provider struct {
	provider.BaseProvider

	client       *httpClient
	domainFilter endpoint.DomainFilter
}

// NewOpnsenseProvider initializes a new OPNsense DNS provider.
// The active backend (unbound or dnsmasq) is selected from config.Plugin.
func NewOpnsenseProvider(domainFilter endpoint.DomainFilter, config *Config) (provider.Provider, error) {
	c, err := newOpnsenseClient(config)
	if err != nil {
		return nil, fmt.Errorf("provider: failed to create the opnsense client: %w", err)
	}

	return &Provider{
		client:       c,
		domainFilter: domainFilter,
	}, nil
}

// Records returns the current DNS records from OPNsense.
func (p *Provider) Records(ctx context.Context) ([]*endpoint.Endpoint, error) {
	log.Debugf("Records: retrieving records from opnsense (%s)", p.client.Config.Plugin)

	records, err := p.client.getRecords()
	if err != nil {
		return nil, err
	}

	var endpoints []*endpoint.Endpoint
	for _, r := range records {
		fqdn := joinFQDN(r.hostname, r.domain)
		if !p.domainFilter.Match(fqdn) {
			continue
		}
		endpoints = append(endpoints, &endpoint.Endpoint{
			DNSName:    fqdn,
			RecordType: r.recordType,
			Targets:    endpoint.NewTargets(r.target),
		})
	}

	log.Debugf("Records: returning %d endpoints", len(endpoints))
	return endpoints, nil
}

// ApplyChanges applies a set of DNS changes to OPNsense.
//
// A CNAME alias references its target record, so ordering matters: aliases are
// deleted before the records they may point at, and created only after those
// records exist.
func (p *Provider) ApplyChanges(ctx context.Context, changes *plan.Changes) error {
	deleteCNAMEs, deleteRest := partitionCNAMEs(append(changes.UpdateOld, changes.Delete...))
	for _, ep := range append(deleteCNAMEs, deleteRest...) {
		if err := p.client.deleteRecord(ep); err != nil {
			return err
		}
	}

	createCNAMEs, createRest := partitionCNAMEs(append(changes.Create, changes.UpdateNew...))
	for _, ep := range append(createRest, createCNAMEs...) {
		if err := p.client.createRecord(ep); err != nil {
			return err
		}
	}

	return p.client.reconfigure()
}

// partitionCNAMEs splits endpoints into CNAME records and everything else.
func partitionCNAMEs(endpoints []*endpoint.Endpoint) (cnames, rest []*endpoint.Endpoint) {
	for _, ep := range endpoints {
		if ep.RecordType == "CNAME" {
			cnames = append(cnames, ep)
		} else {
			rest = append(rest, ep)
		}
	}
	return cnames, rest
}

// GetDomainFilter returns the domain filter configured for this provider.
func (p *Provider) GetDomainFilter() endpoint.DomainFilter {
	return p.domainFilter
}
