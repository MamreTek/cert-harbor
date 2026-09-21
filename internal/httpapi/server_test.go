package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	alerting "github.com/MamreTek/cert-harbor/internal/alerts"
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

func TestViewerCanReadButCannotMutate(t *testing.T) {
	server := NewServer(config.Config{Env: "production", AdminToken: "admin-secret", ViewerToken: "viewer-secret", EncryptionKey: "encryption-key"})

	request := httptest.NewRequest(http.MethodGet, "/api/v1/domains", nil)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated read status = %d, want %d", response.Code, http.StatusUnauthorized)
	}

	request = httptest.NewRequest(http.MethodGet, "/api/v1/domains", nil)
	request.Header.Set("Authorization", "Bearer viewer-secret")
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("viewer read status = %d, want %d", response.Code, http.StatusOK)
	}

	request = httptest.NewRequest(http.MethodPost, "/api/v1/monitor/evaluate", nil)
	request.Header.Set("X-CertHarbor-Token", "viewer-secret")
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("viewer mutation status = %d, want %d", response.Code, http.StatusForbidden)
	}

	request = httptest.NewRequest(http.MethodPost, "/api/v1/monitor/evaluate", nil)
	request.Header.Set("X-CertHarbor-Token", "admin-secret")
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("administrator mutation status = %d, want %d", response.Code, http.StatusOK)
	}
}

func TestConnectionCredentialsAreEncryptedAndNeverReturned(t *testing.T) {
	server := NewServer(config.Config{Env: "development", EncryptionKey: "test-encryption-key"})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/provider-connections", strings.NewReader(`{"name":"Cloudflare Production","provider":"cloudflare","credentials":{"token":"provider-secret"}}`))
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("create connection status = %d, body = %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "provider-secret") || !strings.Contains(response.Body.String(), "credentials_stored") {
		t.Fatalf("connection response exposed credentials: %s", response.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet, "/api/v1/provider-connections", nil)
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "provider-secret") {
		t.Fatalf("connection listing exposed credentials: %d %s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodPatch, "/api/v1/provider-connections/cloudflare-production", strings.NewReader(`{"enabled":false}`))
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"enabled":false`) {
		t.Fatalf("disable connection response = %d %s", response.Code, response.Body.String())
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
		Alerts: alerting.NewEngine(store),
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

	request = httptest.NewRequest(http.MethodGet, "/api/v1/export/certificates.csv?provider=cloudflare", nil)
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Header().Get("Content-Type"), "text/csv") || !strings.Contains(response.Body.String(), "cert-demo-example") {
		t.Fatalf("certificate export response = %d %s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodPost, "/api/v1/provider-connections/demo-cloudflare/test", nil)
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() == "" {
		t.Fatalf("test connection response = %d %s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodPost, "/api/v1/monitor/evaluate", nil)
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "expiring") {
		t.Fatalf("evaluate alerts response = %d %s", response.Code, response.Body.String())
	}
}
