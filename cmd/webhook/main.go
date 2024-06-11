package main

import (
	"fmt"

	"github.com/crutonjohn/external-dns-provider-opnsense/cmd/webhook/init/configuration"
	"github.com/crutonjohn/external-dns-provider-opnsense/cmd/webhook/init/dnsprovider"
	"github.com/crutonjohn/external-dns-provider-opnsense/cmd/webhook/init/logging"
	"github.com/crutonjohn/external-dns-provider-opnsense/cmd/webhook/init/server"
	"github.com/crutonjohn/external-dns-provider-opnsense/pkg/webhook"
	log "github.com/sirupsen/logrus"
)

const banner = `
external-dns-provider-opnsense
version: %s (%s)

`

var (
	Version = "local"
	Gitsha  = "?"
)

func main() {
	fmt.Printf(banner, Version, Gitsha)

	logging.Init()

	config := configuration.Init()
	provider, err := dnsprovider.Init(config)
	if err != nil {
		log.Fatalf("failed to initialize provider: %v", err)
	}

	main, health := server.Init(config, webhook.New(provider))
	server.WaitForSignal()
	server.ShutdownGracefully(main, health)
}
