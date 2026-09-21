package scheduler

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/MamreTek/cert-harbor/internal/catalog"
	"github.com/MamreTek/cert-harbor/internal/providers"
	"github.com/MamreTek/cert-harbor/internal/providers/registry"
	"github.com/MamreTek/cert-harbor/internal/syncer"
)

func TestRunOnceSynchronizesEnabledConnections(t *testing.T) {
	fixture := filepath.Join("..", "..", "examples", "demo-fixture.json")
	store := catalog.NewStore()
	if err := store.AddConnection(catalog.Connection{ID: "enabled", Name: "Enabled", Provider: providers.Cloudflare, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := store.AddConnection(catalog.Connection{ID: "disabled", Name: "Disabled", Provider: providers.Cloudflare, Enabled: false}); err != nil {
		t.Fatal(err)
	}
	service := syncer.New(store, registry.New(fixture))
	scheduler := New(store, service)
	scheduler.logf = func(string, ...any) {}
	scheduler.RunOnce(context.Background())
	items, total := store.ListDomains(catalog.Filter{Page: 1, PageSize: 50})
	if total != 1 || len(items) != 1 || items[0].ConnectionID != "enabled" {
		t.Fatalf("scheduled inventory = total %d items %#v", total, items)
	}
}

func TestRunOnceRunsMonitorCallbackAfterSynchronization(t *testing.T) {
	fixture := filepath.Join("..", "..", "examples", "demo-fixture.json")
	store := catalog.NewStore()
	if err := store.AddConnection(catalog.Connection{ID: "enabled", Name: "Enabled", Provider: providers.Cloudflare, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	service := syncer.New(store, registry.New(fixture))
	var callbackCount atomic.Int32
	scheduler := New(store, service, func(context.Context) { callbackCount.Add(1) })
	scheduler.logf = func(string, ...any) {}
	scheduler.RunOnce(context.Background())
	if callbackCount.Load() != 1 {
		t.Fatalf("monitor callback count = %d, want 1", callbackCount.Load())
	}
}
