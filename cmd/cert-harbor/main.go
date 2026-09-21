package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	alerting "github.com/MamreTek/cert-harbor/internal/alerts"
	"github.com/MamreTek/cert-harbor/internal/catalog"
	"github.com/MamreTek/cert-harbor/internal/config"
	"github.com/MamreTek/cert-harbor/internal/httpapi"
	observability "github.com/MamreTek/cert-harbor/internal/metrics"
	"github.com/MamreTek/cert-harbor/internal/notifications"
	"github.com/MamreTek/cert-harbor/internal/providers"
	"github.com/MamreTek/cert-harbor/internal/providers/registry"
	"github.com/MamreTek/cert-harbor/internal/scheduler"
	"github.com/MamreTek/cert-harbor/internal/security"
	"github.com/MamreTek/cert-harbor/internal/syncer"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	cfg := config.FromEnv()
	if err := cfg.Validate(); err != nil {
		log.Fatal(err)
	}
	store, err := catalog.OpenStore(cfg.DataPath, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("open catalog store: %v", err)
	}
	defer func() { _ = store.Close() }()
	adapters := registry.New(cfg.FixturePath)
	var secrets *security.SecretBox
	if cfg.EncryptionKey != "" {
		secrets, err = security.NewSecretBox(cfg.EncryptionKey)
		if err != nil {
			log.Fatalf("initialize secret encryption: %v", err)
		}
	}
	var oldSecrets *security.SecretBox
	if cfg.OldEncryptionKey != "" {
		oldSecrets, err = security.NewSecretBox(cfg.OldEncryptionKey)
		if err != nil {
			log.Fatalf("initialize previous secret encryption: %v", err)
		}
	}
	if oldSecrets != nil && secrets == nil {
		log.Fatal("CERT_HARBOR_ENCRYPTION_KEY is required when rotating secrets")
	}
	syncService := syncer.New(store, adapters, secrets)
	metrics := observability.New()
	syncService.SetMetrics(metrics)
	alertEngine, err := alerting.OpenEngine(store, cfg.AlertsPath, store.StateBackend())
	if err != nil {
		log.Fatalf("open alert state: %v", err)
	}
	notificationService, err := notifications.OpenService(secrets, cfg.NotificationsPath, store.StateBackend())
	if err != nil {
		log.Fatalf("open notification state: %v", err)
	}
	if oldSecrets != nil {
		if _, err := store.RotateCredentials(secrets, oldSecrets); err != nil {
			log.Fatalf("rotate provider credentials: %v", err)
		}
		if _, err := notificationService.RotateSecrets(secrets, oldSecrets); err != nil {
			log.Fatalf("rotate notification secrets: %v", err)
		}
		if err := store.AppendAudit(catalog.AuditEvent{Actor: "system", Action: "security.key_rotation", ObjectType: "encryption_key", ObjectID: "application", Outcome: "succeeded", CorrelationID: "startup-key-rotation", CreatedAt: time.Now().UTC()}); err != nil {
			log.Fatalf("record encryption key rotation audit: %v", err)
		}
		log.Printf("encryption key rotation completed; remove CERT_HARBOR_ENCRYPTION_KEY_OLD")
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
	monitorCycle := func(cycleCtx context.Context) {
		for _, alert := range alertEngine.Evaluate() {
			if alert.State == alerting.StateResolved || alert.State == alerting.StateSuppressed {
				continue
			}
			_ = notificationService.Queue(alert)
		}
		recordNotificationDeliveries(store, notificationService.DeliverOutbox(cycleCtx))
	}
	go scheduler.New(store, syncService, monitorCycle).Run(ctx, cfg.SyncInterval)
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		recordNotificationDeliveries(store, notificationService.DeliverOutbox(ctx))
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				recordNotificationDeliveries(store, notificationService.DeliverOutbox(ctx))
			}
		}
	}()

	server := &http.Server{Addr: cfg.Addr, Handler: httpapi.NewServer(cfg, httpapi.Dependencies{Store: store, Syncer: syncService, Alerts: alertEngine, Secrets: secrets, Notifications: notificationService, Metrics: metrics}).Handler()}
	go func() {
		<-ctx.Done()
		_ = server.Shutdown(context.Background())
	}()
	log.Printf("CertHarbor listening on %s", cfg.Addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func recordNotificationDeliveries(store *catalog.Store, deliveries []notifications.Delivery) {
	for _, delivery := range deliveries {
		_ = store.AppendAudit(catalog.AuditEvent{
			Actor:         "system",
			Action:        "notification.delivery",
			ObjectType:    "notification_delivery",
			ObjectID:      delivery.ID,
			Outcome:       delivery.Status,
			CorrelationID: "delivery-" + delivery.ID,
			CreatedAt:     time.Now().UTC(),
		})
	}
}
