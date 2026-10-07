package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"portico-gateway/internal/adminauth"
	"portico-gateway/internal/adminserver"
	"portico-gateway/internal/config"
	"portico-gateway/internal/identity"
	"portico-gateway/internal/mcpserver"
	"portico-gateway/internal/modelpolicy"
	"portico-gateway/internal/oauthbridge"
	"portico-gateway/internal/postgres"
	"portico-gateway/internal/proxy"
	"portico-gateway/internal/scanportal"
	"portico-gateway/internal/session"
	"portico-gateway/internal/vault"
	"syscall"
	"time"
)

func main() {
	if e := run(); e != nil {
		slog.Error("Portico stopped; check configuration and dependency availability")
		os.Exit(1)
	}
}
func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	path := os.Getenv("PORTICO_CONFIG")
	if path == "" {
		path = "/etc/portico/config.yaml"
	}
	c, e := config.Load(path)
	if e != nil {
		return e
	}
	key, e := config.EncryptionKey()
	if e != nil {
		return e
	}
	v, e := vault.New(key)
	if e != nil {
		return e
	}
	db, e := config.DatabaseURL()
	if e != nil {
		return e
	}
	boot, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	store, e := postgres.Open(boot, db)
	if e != nil {
		return e
	}
	defer store.Close()
	if e = store.Migrate(boot); e != nil {
		return e
	}
	client, e := config.HTTPClient()
	if e != nil {
		return e
	}
	idp, e := identity.NewOIDC(boot, c.OIDCOptions(), client)
	if e != nil {
		return e
	}
	sessions := &session.Manager{Store: store, Vault: v, Provider: idp, MaxAge: time.Duration(c.Session.MaxAgeSeconds) * time.Second, IdleAge: time.Duration(c.Session.IdleSeconds) * time.Second}
	oauth, e := oauthbridge.New(c.PublicURL, c.OAuth.Clients, store.Pool, v, sessions, idp)
	if e != nil {
		return e
	}
	if e = oauth.Migrate(boot); e != nil {
		return e
	}
	upstream := &proxy.Proxy{Client: client, Services: c.Services}
	mux := http.NewServeMux()
	if c.Admin.Enabled {
		policies := &modelpolicy.Store{Pool: store.Pool}
		if e = policies.Migrate(boot); e != nil {
			return e
		}
		admin := &adminauth.Combined{}
		var err error
		if len(c.Admin.Groups) > 0 {
			admin.OIDC, err = adminauth.New(c.PublicURL, c.Admin.Groups, store.Pool, v, sessions, idp)
			if err != nil {
				return err
			}
			if err = admin.OIDC.Migrate(boot); err != nil {
				return err
			}
		}
		if c.Admin.Local.Enabled {
			admin.Local, err = adminauth.NewLocal(c.PublicURL, c.Admin.Local.Username, os.Getenv("PORTICO_LOCAL_ADMIN_PASSWORD_HASH"), store, sessions.MaxAge, sessions.IdleAge)
			if err != nil {
				return err
			}
			admin.Local.SetPool(store.Pool)
			if err = admin.Local.Migrate(boot); err != nil {
				return err
			}
		}
		catalogKey := os.Getenv("PORTICO_LITELLM_API_KEY")
		if catalogKey == "" {
			return http.ErrNoCookie
		}
		panel := &adminserver.Server{Auth: admin, Policies: policies, CatalogURL: c.Admin.CatalogURL, CatalogKey: catalogKey, Client: client}
		mux.Handle("/admin/", panel.Handler())
	}
	if c.Portal.Enabled {
		portalAuth, err := adminauth.NewPortal(c.PublicURL, c.Services[c.Portal.Service].Roles, store.Pool, v, sessions, idp)
		if err != nil {
			return err
		}
		if err = portalAuth.Migrate(boot); err != nil {
			return err
		}
		portal, err := scanportal.New(portalAuth, upstream, c.Portal.Service)
		if err != nil {
			return err
		}
		mux.Handle("/portal/", portal)
	}
	// Every MCP request requires an OAuth credential and a valid user session.
	mux.Handle("/mcp", mcpserver.Handler(c.PublicURL, c.OAuth.AllowedOrigins, oauth, sessions, upstream, c.Portal.Enabled))
	mux.Handle("/", oauth.Handler())
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		check, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if store.Pool.Ping(check) != nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	server := &http.Server{Addr: c.Listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 50 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe() }()
	slog.Info("Portico listening", "address", c.Listen)
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			return server.Shutdown(shutdown)
		case e := <-done:
			if e == http.ErrServerClosed {
				return nil
			}
			return e
		case <-ticker.C:
			cleanup, cancel := context.WithTimeout(ctx, 10*time.Second)
			if oauth.Cleanup(cleanup) != nil {
				slog.Warn("OAuth cleanup failed")
			}
			if store.Cleanup(cleanup) != nil {
				slog.Warn("session cleanup failed")
			}
			cancel()
		}
	}
}
