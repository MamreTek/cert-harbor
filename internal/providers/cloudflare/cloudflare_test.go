package cloudflare

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MamreTek/cert-harbor/internal/providers"
)

func TestLiveAdapterMapsZonesAndCertificatePacks(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer live-token" {
			t.Fatalf("authorization header = %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("CF-Ray", "ray-test")
		switch r.URL.Path {
		case "/zones":
			_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"zone-1","name":"example.com","status":"active","name_servers":["ns1.example.net"],"original_name_servers":["ns2.example.net"]}],"result_info":{"page":1,"total_pages":1}}`))
		case "/zones/zone-1/ssl/certificate_packs":
			_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"pack-1","hosts":["example.com","www.example.com"],"status":"active","certificate_authority":"Lets Encrypt","issued_on":"2026-01-01T00:00:00Z","expires_on":"2026-10-01T00:00:00Z"}],"result_info":{"page":1,"total_pages":1}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	adapter := newLiveAdapter(server.URL, server.Client())
	credentials := providers.Credentials{Values: map[string]string{"token": "live-token", "zone_id": "zone-1"}}
	result, err := adapter.Test(context.Background(), credentials)
	if err != nil || result.RequestID != "ray-test" {
		t.Fatalf("test result = %#v, err = %v", result, err)
	}
	domains, err := adapter.ListDomains(context.Background(), credentials, "")
	if err != nil || len(domains.Items) != 1 || domains.Items[0].SourceID != "zone-1" || len(domains.Items[0].Nameservers) != 2 {
		t.Fatalf("domains = %#v, err = %v", domains, err)
	}
	certificates, err := adapter.ListCertificates(context.Background(), credentials, "")
	if err != nil || len(certificates.Items) != 1 || certificates.Items[0].SourceID != "pack-1" || certificates.Items[0].CommonName != "example.com" || certificates.Items[0].ValidTo.IsZero() {
		t.Fatalf("certificates = %#v, err = %v", certificates, err)
	}
}

func TestLiveAdapterRetriesRateLimits(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("CF-Ray", "retry-ray")
		_, _ = w.Write([]byte(`{"success":true,"result":[],"result_info":{"page":1,"total_pages":1}}`))
	}))
	defer server.Close()
	adapter := newLiveAdapter(server.URL, server.Client())
	result, err := adapter.Test(context.Background(), providers.Credentials{Values: map[string]string{"token": "live-token"}})
	if err != nil || result.RequestID != "retry-ray" || calls != 2 {
		t.Fatalf("retry test result=%#v err=%v calls=%d", result, err, calls)
	}
}

func TestLiveAdapterClassifiesPermanentFailures(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("CF-Ray", "permanent-ray")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	adapter := newLiveAdapter(server.URL, server.Client())
	_, err := adapter.Test(context.Background(), providers.Credentials{Values: map[string]string{"token": "live-token"}})
	if err == nil || providers.IsRetryable(err) || providers.RequestID(err) != "permanent-ray" {
		t.Fatalf("permanent failure = %v, retryable=%v, request_id=%q", err, providers.IsRetryable(err), providers.RequestID(err))
	}
	var apiErr *providers.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("error classification = %#v", err)
	}
}
