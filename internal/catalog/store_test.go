package catalog

import (
	"testing"
	"time"

	"github.com/MamreTek/cert-harbor/internal/domain"
	"github.com/MamreTek/cert-harbor/internal/providers"
)

func TestInventoryFiltersOwnerTagExpiryAndSort(t *testing.T) {
	store := NewStore()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := store.ReplaceAssets("connection", now, []domain.Domain{
		{ID: "domain-1", Provider: string(providers.Cloudflare), Name: "later.example", Owner: "team-a", Environment: "production", Tags: []string{"critical"}, ExpiresAt: timePtr(now.Add(90 * 24 * time.Hour)), LastSeenAt: now},
		{ID: "domain-2", Provider: string(providers.Cloudflare), Name: "soon.example", Owner: "team-b", Environment: "staging", Tags: []string{"test"}, ExpiresAt: timePtr(now.Add(7 * 24 * time.Hour)), LastSeenAt: now},
	}, nil); err != nil {
		t.Fatal(err)
	}
	items, total := store.ListDomains(Filter{Owner: "team-b", Tag: "test", ExpiresBefore: timePtr(now.Add(30 * 24 * time.Hour)), Sort: "expires_at", Page: 1, PageSize: 50})
	if total != 1 || len(items) != 1 || items[0].Name != "soon.example" {
		t.Fatalf("filtered domains = total %d items %#v", total, items)
	}
}

func timePtr(value time.Time) *time.Time { return &value }
