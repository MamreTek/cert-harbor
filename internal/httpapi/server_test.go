package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MamreTek/cert-harbor/internal/config"
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
