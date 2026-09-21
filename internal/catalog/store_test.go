package catalog

import (
	"testing"
	"time"

	"github.com/MamreTek/cert-harbor/internal/domain"
	"github.com/MamreTek/cert-harbor/internal/providers"
)

func TestReplaceAssetsIsIdempotentAndMarksMissingAssetsStale(t *testing.T) {
	store := NewStore()
	if err := store.AddConnection(Connection{ID: "connection", Name: "Connection", Provider: providers.Cloudflare, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	item := domain.Domain{ID: "connection:domain:one", ConnectionID: "connection", Provider: string(providers.Cloudflare), Name: "one.example", LastSeenAt: now}
	store.ReplaceAssets("connection", now, []domain.Domain{item}, nil)
	store.ReplaceAssets("connection", now.Add(time.Minute), []domain.Domain{item}, nil)
	items, total := store.ListDomains(Filter{Page: 1, PageSize: 50})
	if total != 1 || len(items) != 1 || items[0].Stale {
		t.Fatalf("expected one fresh idempotent asset, got total=%d items=%#v", total, items)
	}
	store.ReplaceAssets("connection", now.Add(2*time.Minute), nil, nil)
	items, total = store.ListDomains(Filter{Stale: boolPtr(true), Page: 1, PageSize: 50})
	if total != 1 || len(items) != 1 || !items[0].Stale {
		t.Fatalf("expected missing asset to become stale, got total=%d items=%#v", total, items)
	}
}

func boolPtr(value bool) *bool { return &value }
