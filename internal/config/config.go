package config

import (
	"errors"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Env           string
	Addr          string
	AdminToken    string
	ViewerToken   string
	EncryptionKey string
	WebDir        string
	Demo          bool
	FixturePath   string
}

func FromEnv() Config {
	return Config{
		Env:           valueOrDefault("CERT_HARBOR_ENV", "development"),
		Addr:          valueOrDefault("CERT_HARBOR_ADDR", ":8080"),
		AdminToken:    os.Getenv("CERT_HARBOR_ADMIN_TOKEN"),
		ViewerToken:   os.Getenv("CERT_HARBOR_VIEWER_TOKEN"),
		EncryptionKey: os.Getenv("CERT_HARBOR_ENCRYPTION_KEY"),
		WebDir:        valueOrDefault("CERT_HARBOR_WEB_DIR", "web/dist"),
		Demo:          boolFromEnv("CERT_HARBOR_DEMO"),
		FixturePath:   valueOrDefault("CERT_HARBOR_FIXTURE_PATH", "examples/demo-fixture.json"),
	}
}

func (c Config) Validate() error {
	if !strings.EqualFold(c.Env, "production") {
		return nil
	}
	if c.EncryptionKey == "" {
		return errors.New("CERT_HARBOR_ENCRYPTION_KEY is required in production")
	}
	if c.AdminToken == "" || c.ViewerToken == "" {
		return errors.New("CERT_HARBOR_ADMIN_TOKEN and CERT_HARBOR_VIEWER_TOKEN are required in production")
	}
	return nil
}

func valueOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func boolFromEnv(name string) bool {
	value, _ := strconv.ParseBool(os.Getenv(name))
	return value
}
