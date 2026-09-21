package config

import "testing"

func TestDevelopmentConfigDoesNotRequireProductionSecrets(t *testing.T) {
	if err := (Config{Env: "development"}).Validate(); err != nil {
		t.Fatalf("development config should be valid without secrets: %v", err)
	}
}

func TestProductionConfigRequiresEncryptionAndTokens(t *testing.T) {
	if err := (Config{Env: "production"}).Validate(); err == nil {
		t.Fatal("production config should require encryption and authentication secrets")
	}
	if err := (Config{Env: "production", EncryptionKey: "key", AdminToken: "admin", ViewerToken: "viewer"}).Validate(); err != nil {
		t.Fatalf("complete production config should be valid: %v", err)
	}
}
