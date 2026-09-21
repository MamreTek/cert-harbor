package main

import (
	"log"
	"net/http"

	"github.com/MamreTek/cert-harbor/internal/catalog"
	"github.com/MamreTek/cert-harbor/internal/config"
	"github.com/MamreTek/cert-harbor/internal/httpapi"
	"github.com/MamreTek/cert-harbor/internal/providers"
	"github.com/MamreTek/cert-harbor/internal/providers/registry"
	"github.com/MamreTek/cert-harbor/internal/syncer"
)

func main() {
	cfg := config.FromEnv()
	if err := cfg.Validate(); err != nil {
		log.Fatal(err)
	}
	store := catalog.NewStore()
	adapters := registry.New(cfg.FixturePath)
	syncService := syncer.New(store, adapters)
	if cfg.Demo {
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

	log.Printf("CertHarbor listening on %s", cfg.Addr)
	if err := http.ListenAndServe(cfg.Addr, httpapi.NewServer(cfg, httpapi.Dependencies{Store: store, Syncer: syncService}).Handler()); err != nil {
		log.Fatal(err)
	}
}
