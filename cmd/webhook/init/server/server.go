package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/crutonjohn/external-dns-opnsense-webhook/cmd/webhook/init/configuration"
	"github.com/crutonjohn/external-dns-opnsense-webhook/pkg/webhook"
	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	log "github.com/sirupsen/logrus"
)

// HealthCheckHandler returns the status of the service
func HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// ReadinessHandler returns whether the service is ready to accept requests
func ReadinessHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// Init initializes the http server
func Init(config configuration.Config, p *webhook.Webhook) (*http.Server, *http.Server) {
	mainRouter := chi.NewRouter()
	mainRouter.Get("/", p.Negotiate)
	mainRouter.Get("/records", p.Records)
	mainRouter.Post("/records", p.ApplyChanges)
	mainRouter.Post("/adjustendpoints", p.AdjustEndpoints)

	address := fmt.Sprintf("%s:%d", config.ServerHost, config.ServerPort)
	mainServer := createHTTPServer(address, mainRouter, config.ServerReadTimeout, config.ServerWriteTimeout)
	go func() {
		log.Infof("starting server on addr: '%s' ", mainServer.Addr)
		err := mainServer.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Errorf("can't serve on addr: '%s', error: %v", mainServer.Addr, err)
		}
	}()

	healthRouter := chi.NewRouter()
	healthRouter.Get("/metrics", promhttp.Handler().ServeHTTP)
	healthRouter.Get("/healthz", HealthCheckHandler)
	healthRouter.Get("/readyz", ReadinessHandler)

	healthServer := createHTTPServer("0.0.0.0:8080", healthRouter, config.ServerReadTimeout, config.ServerWriteTimeout)
	go func() {
		log.Infof("starting health server on addr: '%s' ", healthServer.Addr)
		if err := healthServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Errorf("can't serve health on addr: '%s', error: %v", healthServer.Addr, err)
		}
	}()

	return mainServer, healthServer
}

func createHTTPServer(addr string, hand http.Handler, readTimeout, writeTimeout time.Duration) *http.Server {
	return &http.Server{
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		Addr:         addr,
		Handler:      hand,
	}
}

func WaitForSignal() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	sig := <-sigCh
	log.Infof("shutting down servers due to received signal: %v", sig)
}

// ShutdownGracefully gracefully shutdown the http server
func ShutdownGracefully(mainServer *http.Server, healthServer *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := mainServer.Shutdown(ctx); err != nil {
		log.Errorf("error shutting down main server: %v", err)
	}

	if err := healthServer.Shutdown(ctx); err != nil {
		log.Errorf("error shutting down health server: %v", err)
	}
}
