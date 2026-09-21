package syncer

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MamreTek/cert-harbor/internal/catalog"
	"github.com/MamreTek/cert-harbor/internal/providers"
	"github.com/MamreTek/cert-harbor/internal/providers/registry"
	"github.com/MamreTek/cert-harbor/internal/security"
)

func TestSyncPreservesAssetsWhenProviderFixtureFails(t *testing.T) {
	fixture := filepath.Join("..", "..", "examples", "demo-fixture.json")
	store := catalog.NewStore()
	if err := store.AddConnection(catalog.Connection{ID: "demo", Name: "Demo", Provider: providers.Cloudflare, Enabled: true, FixturePath: fixture}); err != nil {
		t.Fatal(err)
	}
	service := New(store, registry.New(fixture))
	if run, err := service.Sync(context.Background(), "demo"); err != nil || run.Status != "succeeded" {
		t.Fatalf("initial sync = %#v, %v", run, err)
	}
	connection, ok := store.GetConnection("demo")
	if !ok || connection.NextSyncAt == nil || !connection.NextSyncAt.After(connection.LastSyncAt.Add(-time.Second)) {
		t.Fatalf("successful sync did not schedule next run: %#v", connection)
	}
	if run, err := service.Sync(context.Background(), "demo"); err != nil || run.Status != "succeeded" {
		t.Fatalf("repeat sync = %#v, %v", run, err)
	}
	if runs := store.ListSyncRuns(); len(runs) != 2 || runs[0].Status != "succeeded" || runs[1].Status != "succeeded" {
		t.Fatalf("repeat sync runs = %#v", runs)
	}
	// A cancelled provider request must not affect the successful connection's inventory.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.Sync(ctx, "demo"); err == nil {
		t.Fatal("expected cancelled sync to fail")
	}
	items, total := store.ListDomains(catalog.Filter{Page: 1, PageSize: 50})
	if total != 1 || len(items) != 1 || items[0].Stale {
		t.Fatalf("failed sync changed last-known inventory: total=%d items=%#v", total, items)
	}
}

type credentialProbeAdapter struct {
	credentials providers.Credentials
}

func (a *credentialProbeAdapter) Provider() providers.Provider { return providers.Cloudflare }

func (a *credentialProbeAdapter) Capabilities() providers.Capabilities {
	return providers.Capabilities{Provider: providers.Cloudflare}
}

func (a *credentialProbeAdapter) Test(_ context.Context, credentials providers.Credentials) (providers.TestResult, error) {
	a.credentials = credentials
	return providers.TestResult{Provider: providers.Cloudflare, RequestID: "probe"}, nil
}

func (a *credentialProbeAdapter) ListDomains(context.Context, providers.Credentials, string) (providers.DomainPage, error) {
	return providers.DomainPage{}, nil
}

func (a *credentialProbeAdapter) ListCertificates(context.Context, providers.Credentials, string) (providers.CertificatePage, error) {
	return providers.CertificatePage{}, nil
}

func TestServiceDecryptsConnectionCredentialsBeforeProviderCalls(t *testing.T) {
	box, err := security.NewSecretBox("encryption-key")
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := box.EncryptMap(map[string]string{"token": "provider-secret"})
	if err != nil {
		t.Fatal(err)
	}
	store := catalog.NewStore()
	if err := store.AddConnection(catalog.Connection{ID: "connection", Name: "Connection", Provider: providers.Cloudflare, Enabled: true, CredentialsStored: true, CredentialsCiphertext: ciphertext}); err != nil {
		t.Fatal(err)
	}
	probe := &credentialProbeAdapter{}
	service := New(store, map[providers.Provider]providers.Adapter{providers.Cloudflare: probe}, box)
	if _, err := service.Test(context.Background(), "connection"); err != nil {
		t.Fatal(err)
	}
	if probe.credentials.Values["token"] != "provider-secret" {
		t.Fatalf("provider credentials = %#v", probe.credentials.Values)
	}
}

func TestSyncRejectsRepeatedProviderPageCursor(t *testing.T) {
	store := catalog.NewStore()
	if err := store.AddConnection(catalog.Connection{ID: "loop", Name: "Loop", Provider: providers.Cloudflare, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	adapter := &repeatingCursorAdapter{}
	service := New(store, map[providers.Provider]providers.Adapter{providers.Cloudflare: adapter})
	_, err := service.Sync(context.Background(), "loop")
	if err == nil || !strings.Contains(err.Error(), "repeated domain page cursor") {
		t.Fatalf("repeated cursor error = %v", err)
	}
	runs := store.ListSyncRuns()
	if len(runs) != 1 || runs[0].Status != "failed" {
		t.Fatalf("repeated cursor sync run = %#v", runs)
	}
}

type repeatingCursorAdapter struct{}

func (a *repeatingCursorAdapter) Provider() providers.Provider { return providers.Cloudflare }

func (a *repeatingCursorAdapter) Capabilities() providers.Capabilities {
	return providers.Capabilities{Provider: providers.Cloudflare, Domains: true, Certificates: true}
}

func (a *repeatingCursorAdapter) Test(context.Context, providers.Credentials) (providers.TestResult, error) {
	return providers.TestResult{Provider: providers.Cloudflare}, nil
}

func (a *repeatingCursorAdapter) ListDomains(context.Context, providers.Credentials, string) (providers.DomainPage, error) {
	return providers.DomainPage{NextCursor: "same"}, nil
}

func (a *repeatingCursorAdapter) ListCertificates(context.Context, providers.Credentials, string) (providers.CertificatePage, error) {
	return providers.CertificatePage{}, nil
}

var _ providers.Adapter = (*credentialProbeAdapter)(nil)
