package providers

import (
	"context"
	"path/filepath"
	"testing"
)

func TestFixtureAdapterPaginatesAndDoesNotExposeCredentials(t *testing.T) {
	fixture := filepath.Join("..", "..", "examples", "demo-fixture.json")
	adapter := NewFixtureAdapter(Cloudflare, fixture, Capabilities{Provider: Cloudflare, Domains: true, Certificates: true})

	page, err := adapter.ListDomains(context.Background(), Credentials{Values: map[string]string{"token": "secret"}}, "")
	if err != nil {
		t.Fatalf("list domains: %v", err)
	}
	if len(page.Items) != 1 || page.Items[0].SourceID != "zone-demo-example" {
		t.Fatalf("unexpected domain page: %#v", page.Items)
	}
	if page.NextCursor != "" {
		t.Fatalf("single-page fixture returned next cursor %q", page.NextCursor)
	}
	result, err := adapter.Test(context.Background(), Credentials{Values: map[string]string{"token": "secret"}})
	if err != nil {
		t.Fatalf("test connection: %v", err)
	}
	if result.RequestID == "secret" || result.Capabilities.Provider != Cloudflare {
		t.Fatalf("unsafe or incorrect test result: %#v", result)
	}
}
