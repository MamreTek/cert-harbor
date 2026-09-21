package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/MamreTek/cert-harbor/internal/catalog"
	"github.com/MamreTek/cert-harbor/internal/config"
	"github.com/MamreTek/cert-harbor/internal/providers"
	"github.com/MamreTek/cert-harbor/internal/providers/registry"
	"github.com/MamreTek/cert-harbor/internal/syncer"
)

func TestHealthAndReadinessEndpoints(t *testing.T) {
	server := NewServer(config.Config{Env: "development"})

	for _, test := range []struct {
		path string
		want int
	}{
		{path: "/healthz", want: http.StatusOK},
		{path: "/readyz", want: http.StatusOK},
		{path: "/api/v1/meta", want: http.StatusOK},
	} {
		req := httptest.NewRequest(http.MethodGet, test.path, nil)
		res := httptest.NewRecorder()
		server.Handler().ServeHTTP(res, req)
		if res.Code != test.want {
			t.Errorf("GET %s status = %d, want %d", test.path, res.Code, test.want)
		}
	}
}

func TestReadinessRejectsIncompleteProductionConfig(t *testing.T) {
	server := NewServer(config.Config{Env: "production"})
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /readyz status = %d, want %d", res.Code, http.StatusServiceUnavailable)
	}
}

func TestSyncAndInventoryEndpoints(t *testing.T) {
	fixture := filepath.Join("..", "..", "examples", "demo-fixture.json")
	store := catalog.NewStore()
	if err := store.AddConnection(catalog.Connection{
		ID:           "demo-cloudflare",
		Name:         "Demo Cloudflare",
		Provider:     providers.Cloudflare,
		Enabled:      true,
		Source:       "fixture",
		FixturePath:  fixture,
		Capabilities: registry.New(fixture)[providers.Cloudflare].Capabilities(),
	}); err != nil {
		t.Fatal(err)
	}
	server := NewServer(config.Config{Env: "development", FixturePath: fixture}, Dependencies{
		Store:  store,
		Syncer: syncer.New(store, registry.New(fixture)),
	})

	request := httptest.NewRequest(http.MethodPost, "/api/v1/provider-connections/demo-cloudflare/sync", nil)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("sync status = %d, body = %s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet, "/api/v1/domains?provider=cloudflare&page=1&page_size=10", nil)
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("domains status = %d", response.Code)
	}
	var body struct {
		Items []map[string]any `json:"items"`
		Total int              `json:"total"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Total != 1 || len(body.Items) != 1 || body.Items[0]["source_id"] != "zone-demo-example" {
		t.Fatalf("unexpected domain response: %#v", body)
	}

	request = httptest.NewRequest(http.MethodPost, "/api/v1/provider-connections/demo-cloudflare/test", nil)
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() == "" {
		t.Fatalf("test connection response = %d %s", response.Code, response.Body.String())
	}
}
