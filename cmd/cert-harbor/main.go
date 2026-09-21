package main

import (
	"log"
	"net/http"

	"github.com/MamreTek/cert-harbor/internal/config"
	"github.com/MamreTek/cert-harbor/internal/httpapi"
)

func main() {
	cfg := config.FromEnv()
	if err := cfg.Validate(); err != nil {
		log.Fatal(err)
	}

	log.Printf("CertHarbor listening on %s", cfg.Addr)
	if err := http.ListenAndServe(cfg.Addr, httpapi.NewServer(cfg).Handler()); err != nil {
		log.Fatal(err)
	}
}
