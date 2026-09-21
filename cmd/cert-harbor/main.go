package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	alerting "github.com/MamreTek/cert-harbor/internal/alerts"
	"github.com/MamreTek/cert-harbor/internal/catalog"
	"github.com/MamreTek/cert-harbor/internal/config"
	"github.com/MamreTek/cert-harbor/internal/httpapi"
	"github.com/MamreTek/cert-harbor/internal/notifications"
	"github.com/MamreTek/cert-harbor/internal/providers"
	"github.com/MamreTek/cert-harbor/internal/providers/registry"
	"github.com/MamreTek/cert-harbor/internal/scheduler"
	"github.com/MamreTek/cert-harbor/internal/security"
	"github.com/MamreTek/cert-harbor/internal/syncer"
)

func main() {
	cfg := config.FromEnv()
	if err := cfg.Validate(); err != nil {
		log.Fatal(err)
	}
	store, err := catalog.OpenStore(cfg.DataPath)
	if err != nil {
		log.Fatalf("open catalog store: %v", err)
	}
	adapters := registry.New(cfg.FixturePath)
	syncService := syncer.New(store, adapters)
	var secrets *security.SecretBox
	if cfg.EncryptionKey != "" {
		secrets, err = security.NewSecretBox(cfg.EncryptionKey)
		if err != nil {
			log.Fatalf("initialize secret encryption: %v", err)
		}
	}
	alertEngine, err := alerting.OpenEngine(store, cfg.AlertsPath)
	if err != nil {
		log.Fatalf("open alert state: %v", err)
	}
	notificationService, err := notifications.OpenService(secrets, cfg.NotificationsPath)
	if err != nil {
		log.Fatalf("open notification state: %v", err)
	}
	if cfg.Demo {
		if _, exists := store.GetConnection("demo-cloudflare"); !exists {
			if err := store.AddConnection(catalog.Connection{
				ID:           "demo-cloudflare",
				Name:         "Demo Cloudflare",
				Provider:     providers.Cloudflare,
				Enabled:      true,
				Source:       "fixture",
				FixturePath:  cfg.FixturePath,
				Capabilities: adapters[providers.Cloudflare].Capabilities(),
			}); err != nil {
				log.Fatal(err)
			}
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go scheduler.New(store, syncService).Run(ctx, cfg.SyncInterval)

	server := &http.Server{Addr: cfg.Addr, Handler: httpapi.NewServer(cfg, httpapi.Dependencies{Store: store, Syncer: syncService, Alerts: alertEngine, Secrets: secrets, Notifications: notificationService}).Handler()}
	go func() {
		<-ctx.Done()
		_ = server.Shutdown(context.Background())
	}()
	log.Printf("CertHarbor listening on %s", cfg.Addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
