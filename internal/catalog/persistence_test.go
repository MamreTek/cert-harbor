package catalog

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/MamreTek/cert-harbor/internal/domain"
	"github.com/MamreTek/cert-harbor/internal/providers"
)

func TestOpenStoreRestoresCatalogAfterRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "catalog.json")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AddConnection(Connection{ID: "connection", Name: "Connection", Provider: providers.Cloudflare, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	if err := store.ReplaceAssets("connection", now, []domain.Domain{{ID: "connection:domain:one", ConnectionID: "connection", Provider: string(providers.Cloudflare), Name: "one.example", LastSeenAt: now}}, nil); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	items, total := reopened.ListDomains(Filter{Page: 1, PageSize: 50})
	if total != 1 || len(items) != 1 || items[0].Name != "one.example" {
		t.Fatalf("restored catalog = total %d items %#v", total, items)
	}
	connections := reopened.ListConnections()
	if len(connections) != 1 || connections[0].ID != "connection" {
		t.Fatalf("restored connections = %#v", connections)
	}
	if err := store.AddMember(Member{ID: "viewer", Email: "viewer@example.com", Name: "Viewer", Role: "viewer"}); err != nil {
		t.Fatal(err)
	}
	reopened, err = OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	members := reopened.ListMembers()
	if len(members) != 2 || members[0].Email != "admin@localhost" || members[1].Email != "viewer@example.com" {
		t.Fatalf("restored members = %#v", members)
	}
}
