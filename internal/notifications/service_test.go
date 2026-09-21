package notifications

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestOpenServiceRestoresChannelsAndDeliveries(t *testing.T) {
	box, err := security.NewSecretBox("notification-key")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "notifications", "state.json")
	service, err := OpenService(box, path)
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
	if err := service.AddChannel(Channel{ID: "webhook", Name: "Webhook", Kind: KindWebhook, Endpoint: "https://example.test/hook", Enabled: false, SigningSecretCiphertext: secret, CredentialsStored: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.UpdateChannel("webhook", "Webhook", server.URL, true); err != nil {
		t.Fatal(err)
	}
	deliveries := service.Dispatch(context.Background(), alerts.Alert{ID: "alert-1", State: alerts.StateOpen})
	if len(deliveries) != 1 || deliveries[0].Status != "delivered" {
		t.Fatalf("delivery = %#v", deliveries)
	}
	reopened, err := OpenService(box, path)
	if err != nil {
		t.Fatal(err)
	}
	channels := reopened.Channels()
	if len(channels) != 1 || channels[0].ID != "webhook" || channels[0].Enabled != true || !channels[0].CredentialsStored || channels[0].SigningSecretCiphertext == "" {
		t.Fatalf("restored channels = %#v", channels)
	}
	if len(reopened.Deliveries()) != 1 || reopened.Deliveries()[0].ID != deliveries[0].ID {
		t.Fatalf("unexpected restored deliveries = %#v", reopened.Deliveries())
	}
}

func TestEmailDeliveryUsesEncryptedSMTPCredentials(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		_, _ = fmt.Fprint(connection, "220 localhost ESMTP\r\n")
		scanner := bufio.NewScanner(connection)
		for scanner.Scan() {
			line := scanner.Text()
			switch {
			case len(line) >= 4 && line[:4] == "EHLO":
				_, _ = fmt.Fprint(connection, "250-localhost\r\n250 OK\r\n")
			case len(line) >= 10 && line[:10] == "MAIL FROM:":
				_, _ = fmt.Fprint(connection, "250 OK\r\n")
			case len(line) >= 8 && line[:8] == "RCPT TO:":
				_, _ = fmt.Fprint(connection, "250 OK\r\n")
			case line == "DATA":
				_, _ = fmt.Fprint(connection, "354 End data with <CR><LF>.<CR><LF>\r\n")
				for scanner.Scan() && scanner.Text() != "." {
				}
				accepted <- struct{}{}
				_, _ = fmt.Fprint(connection, "250 OK\r\n")
			case line == "QUIT":
				_, _ = fmt.Fprint(connection, "221 Bye\r\n")
				return
			default:
				_, _ = fmt.Fprint(connection, "250 OK\r\n")
			}
		}
	}()

	box, err := security.NewSecretBox("notification-key")
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := box.EncryptMap(map[string]string{"from": "cert-harbor@example.com", "to": "ops@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(box)
	if err := service.AddChannel(Channel{ID: "email", Name: "Email", Kind: KindEmail, Endpoint: "smtp://" + listener.Addr().String(), Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := service.SetCredentials("email", credentials); err != nil {
		t.Fatal(err)
	}
	delivery, err := service.Test(context.Background(), "email")
	if err != nil || delivery.Status != "delivered" || delivery.Attempts != 1 {
		t.Fatalf("email delivery = %#v, err = %v", delivery, err)
	}
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("SMTP server did not receive the message")
	}
}
