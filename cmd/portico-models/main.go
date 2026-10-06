package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"portico-gateway/internal/config"
	"portico-gateway/internal/identity"
	"portico-gateway/internal/modelaccess"
	"portico-gateway/internal/modelpolicy"
	"portico-gateway/internal/postgres"
	"syscall"
	"time"
)

func main() {
	if e := run(); e != nil {
		slog.Error("Portico models stopped; check configuration and dependencies")
		os.Exit(1)
	}
}
func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	path := os.Getenv("PORTICO_MODELS_CONFIG")
	if path == "" {
		path = "/etc/portico-models/config.yaml"
	}
	c, e := modelaccess.Load(path)
	if e != nil {
		return e
	}
	key := os.Getenv("PORTICO_LITELLM_API_KEY")
	if key == "" {
		return http.ErrNoCookie
	}
	client, e := config.HTTPClient()
	if e != nil {
		return e
	}
	boot, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	idp, e := identity.NewOIDC(boot, identity.Options{Issuer: c.Issuer, ClientID: c.Audience, Audience: c.Audience, RolesClaim: c.GroupsClaim, RolesFormat: "strings", RequiredOrganization: c.Organization}, client)
	if e != nil {
		return e
	}
	gateway := modelaccess.New(idp, c, key, client)
	if c.PolicyStore == "postgres" {
		url, err := config.DatabaseURL()
		if err != nil {
			return err
		}
		db, err := postgres.Open(boot, url)
		if err != nil {
			return err
		}
		defer db.Close()
		policies := &modelpolicy.Store{Pool: db.Pool}
		if err = policies.Migrate(boot); err != nil {
			return err
		}
		if err = policies.Seed(boot, c.Rules); err != nil {
			return err
		}
		gateway.Policy = policies
	}
	handler := gateway.Handler()
	server := &http.Server{Addr: c.Listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 40 << 10}
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe() }()
	select {
	case e := <-done:
		if e == http.ErrServerClosed {
			return nil
		}
		return e
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}
