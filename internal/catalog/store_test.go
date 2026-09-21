package catalog

import (
	"strconv"
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

func TestInventoryFiltersExpiryState(t *testing.T) {
	store := NewStore()
	now := time.Now().UTC()
	if err := store.ReplaceAssets("connection", now, []domain.Domain{
		{ID: "healthy", Provider: string(providers.Cloudflare), Name: "healthy.example", ExpiresAt: timePtr(now.Add(180 * 24 * time.Hour))},
		{ID: "expiring", Provider: string(providers.Cloudflare), Name: "expiring.example", ExpiresAt: timePtr(now.Add(10 * 24 * time.Hour))},
		{ID: "expired", Provider: string(providers.Cloudflare), Name: "expired.example", ExpiresAt: timePtr(now.Add(-24 * time.Hour))},
		{ID: "unknown", Provider: string(providers.Cloudflare), Name: "unknown.example"},
		{ID: "stale", Provider: string(providers.Cloudflare), Name: "stale.example", ExpiresAt: timePtr(now.Add(180 * 24 * time.Hour)), Stale: true},
	}, nil); err != nil {
		t.Fatal(err)
	}
	for state, want := range map[string]string{"healthy": "healthy.example", "expiring": "expiring.example", "expired": "expired.example", "unknown": "unknown.example", "stale": "stale.example"} {
		items, total := store.ListDomains(Filter{ExpiryState: state, Page: 1, PageSize: 50})
		if total != 1 || len(items) != 1 || items[0].Name != want {
			t.Fatalf("expiry state %q = total %d items %#v", state, total, items)
		}
	}
}

func TestExportQueriesAreNotCappedByAPIPageSize(t *testing.T) {
	store := NewStore()
	domains := make([]domain.Domain, 0, 205)
	for index := 0; index < 205; index++ {
		number := strconv.Itoa(index)
		domains = append(domains, domain.Domain{ID: "domain-" + number, Provider: string(providers.Cloudflare), Name: "example-" + number + ".com"})
	}
	if err := store.ReplaceAssets("connection", time.Now().UTC(), domains, nil); err != nil {
		t.Fatal(err)
	}
	items := store.ListDomainsForExport(Filter{Provider: string(providers.Cloudflare)})
	if len(items) != 205 {
		t.Fatalf("export query returned %d domains, want 205", len(items))
	}
}

func timePtr(value time.Time) *time.Time { return &value }
