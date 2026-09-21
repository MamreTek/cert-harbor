package notifications

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MamreTek/cert-harbor/internal/alerts"
	"github.com/MamreTek/cert-harbor/internal/security"
)

func TestWebhookDeliverySignsAndRetries(t *testing.T) {
	box, err := security.NewSecretBox("notification-key")
	if err != nil {
		t.Fatal(err)
	}
	secret, err := box.Encrypt([]byte("webhook-secret"))
	if err != nil {
		t.Fatal(err)
	}
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if !strings.HasPrefix(r.Header.Get("X-CertHarbor-Signature"), "sha256=") {
			t.Error("missing webhook signature")
		}
		if attempts < 2 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	service := NewService(box)
	if err := service.AddChannel(Channel{ID: "webhook", Name: "Webhook", Kind: KindWebhook, Endpoint: server.URL, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := service.SetSigningSecret("webhook", secret); err != nil {
		t.Fatal(err)
	}
	delivery, err := service.Test(context.Background(), "webhook")
	if err != nil || delivery.Status != "delivered" || delivery.Attempts != 2 {
		t.Fatalf("delivery = %#v, err = %v", delivery, err)
	}
}

func TestDispatchDeduplicatesDeliveredAlertState(t *testing.T) {
	box, err := security.NewSecretBox("notification-key")
	if err != nil {
		t.Fatal(err)
	}
	secret, err := box.Encrypt([]byte("webhook-secret"))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	service := NewService(box)
	if err := service.AddChannel(Channel{ID: "webhook", Name: "Webhook", Kind: KindWebhook, Endpoint: server.URL, Enabled: true, SigningSecretCiphertext: secret}); err != nil {
		t.Fatal(err)
	}
	alert := alerts.Alert{ID: "alert-1", State: alerts.StateOpen}
	first := service.Dispatch(context.Background(), alert)
	second := service.Dispatch(context.Background(), alert)
	if len(first) != 1 || len(second) != 1 || first[0].ID != second[0].ID || len(service.Deliveries()) != 1 {
		t.Fatalf("expected one deduplicated delivery, first=%#v second=%#v history=%#v", first, second, service.Deliveries())
	}
}
