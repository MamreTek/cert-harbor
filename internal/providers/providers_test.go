package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/MamreTek/cert-harbor/internal/domain"
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

func TestFixtureAdapterPaginatesMultiplePages(t *testing.T) {
	fixture := filepath.Join(t.TempDir(), "fixture.json")
	domains := make([]domain.Domain, 101)
	for index := range domains {
		domains[index] = domain.Domain{SourceID: "domain-" + string(rune(index)), Name: "example-" + string(rune(index)) + ".com"}
	}
	payload, err := json.Marshal(fixturePayload{Domains: domains})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	adapter := NewFixtureAdapter(Cloudflare, fixture, Capabilities{Provider: Cloudflare, Domains: true})
	first, err := adapter.ListDomains(context.Background(), Credentials{}, "")
	if err != nil || len(first.Items) != 100 || first.NextCursor != "100" {
		t.Fatalf("first fixture page = %#v err=%v", first, err)
	}
	second, err := adapter.ListDomains(context.Background(), Credentials{}, first.NextCursor)
	if err != nil || len(second.Items) != 1 || second.NextCursor != "" || second.Items[0].SourceID != domains[100].SourceID {
		t.Fatalf("second fixture page = %#v err=%v", second, err)
	}
}

func TestAPIErrorHelpersPreserveSafeClassification(t *testing.T) {
	err := fmt.Errorf("sync failed: %w", NewAPIError(Cloudflare, "ray-123", 429, true, "API returned an error"))
	if !IsRetryable(err) || RequestID(err) != "ray-123" {
		t.Fatalf("helpers returned retryable=%v request_id=%q", IsRetryable(err), RequestID(err))
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Provider != Cloudflare || apiErr.StatusCode != 429 {
		t.Fatalf("wrapped API error = %#v", err)
	}
}
