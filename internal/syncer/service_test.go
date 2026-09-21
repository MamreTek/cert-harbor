package syncer

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/MamreTek/cert-harbor/internal/catalog"
	"github.com/MamreTek/cert-harbor/internal/providers"
	"github.com/MamreTek/cert-harbor/internal/providers/registry"
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
