package main

import (
	"fmt"
	"net/http"

	"github.com/crutonjohn/external-dns-opnsense-webhook/cmd/webhook/init/configuration"
	"github.com/crutonjohn/external-dns-opnsense-webhook/cmd/webhook/init/dnsprovider"
	"github.com/crutonjohn/external-dns-opnsense-webhook/cmd/webhook/init/logging"
	"github.com/crutonjohn/external-dns-opnsense-webhook/cmd/webhook/init/server"
	"github.com/crutonjohn/external-dns-opnsense-webhook/pkg/webhook"
	log "github.com/sirupsen/logrus"
)

const banner = `
external-dns-opnsense-webhook
version: %s (%s)

`

var (
	Version = "local"
	Gitsha  = "?"
)

func main() {
	fmt.Printf(banner, Version, Gitsha)

	logging.Init()

	// Start pprof server in a separate goroutine
	go func() {
		log.Println("Starting pprof server on :6060")
		if err := http.ListenAndServe(":6060", nil); err != nil {
			log.Fatalf("pprof server failed: %v", err)
		}
	}()

	config := configuration.Init()
	provider, err := dnsprovider.Init(config)
	if err != nil {
		log.Fatalf("failed to initialize provider: %v", err)
	}

	main, health := server.Init(config, webhook.New(provider))
	server.ShutdownGracefully(main, health)
}
