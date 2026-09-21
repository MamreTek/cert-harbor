package notifications

import (
	"bufio"
	"context"
	"fmt"
	"io"
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

type notificationMemoryBackend struct {
	payload []byte
}

func (b *notificationMemoryBackend) LoadState(string) ([]byte, error) {
	return append([]byte(nil), b.payload...), nil
}

func (b *notificationMemoryBackend) SaveState(_ string, payload []byte) error {
	b.payload = append([]byte(nil), payload...)
	return nil
}

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
	var payload []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		payload, _ = io.ReadAll(r.Body)
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
	if err != nil || delivery.Status != "delivered" || delivery.Attempts != 2 || delivery.CorrelationID == "" {
		t.Fatalf("delivery = %#v, err = %v", delivery, err)
	}
	if !strings.Contains(string(payload), `"deep_link":"/alerts/test-alert"`) || !strings.Contains(string(payload), `"correlation_id":"`+delivery.CorrelationID+`"`) {
		t.Fatalf("webhook payload missing default deep link: %s", payload)
	}
	expiresAt, _ := time.Parse(time.RFC3339, "2026-10-03T00:00:00Z")
	contextAlert := alerts.Alert{ID: "context-alert", AssetName: "example.com", AssetKind: "certificate", Provider: "cloudflare", State: alerts.StateOpen, Severity: "high", ExpiresAt: &expiresAt, SourceURL: "https://provider.example/certificate", Freshness: "stale", DeepLink: "/alerts/context-alert"}
	contextDelivery := service.Dispatch(context.Background(), contextAlert)
	if len(contextDelivery) != 1 || contextDelivery[0].Status != "delivered" {
		t.Fatalf("context delivery = %#v", contextDelivery)
	}
	for _, expected := range []string{`"deep_link":"/alerts/context-alert"`, `"source_url":"https://provider.example/certificate"`, `"freshness":"stale"`, `"expires_at":"2026-10-03T00:00:00Z"`} {
		if !strings.Contains(string(payload), expected) {
			t.Fatalf("webhook payload missing %q: %s", expected, payload)
		}
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

func TestOpenServiceUsesSharedStateBackend(t *testing.T) {
	backend := &notificationMemoryBackend{}
	service, err := OpenService(nil, "", backend)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.AddChannel(Channel{ID: "ops", Name: "Ops", Kind: KindWebhook, Endpoint: "https://example.test", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenService(nil, "", backend)
	if err != nil {
		t.Fatal(err)
	}
	if channels := reopened.Channels(); len(channels) != 1 || channels[0].ID != "ops" {
		t.Fatalf("shared backend did not restore notification channel: %#v", channels)
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

func TestQueuedAlertSurvivesRestartUntilDelivered(t *testing.T) {
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
	path := filepath.Join(t.TempDir(), "notifications", "state.json")
	service, err := OpenService(box, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.AddChannel(Channel{ID: "webhook", Name: "Webhook", Kind: KindWebhook, Endpoint: server.URL, Enabled: true, SigningSecretCiphertext: secret}); err != nil {
		t.Fatal(err)
	}
	alert := alerts.Alert{ID: "queued-alert", State: alerts.StateOpen}
	if err := service.Queue(alert); err != nil {
		t.Fatal(err)
	}
	restarted, err := OpenService(box, path)
	if err != nil {
		t.Fatal(err)
	}
	deliveries := restarted.DeliverOutbox(context.Background())
	if len(deliveries) != 1 || deliveries[0].Status != "delivered" || len(restarted.Deliveries()) != 1 {
		t.Fatalf("restarted outbox deliveries = %#v history=%#v", deliveries, restarted.Deliveries())
	}
}

func TestRotateNotificationSecrets(t *testing.T) {
	oldBox, err := security.NewSecretBox("old-key")
	if err != nil {
		t.Fatal(err)
	}
	newBox, err := security.NewSecretBox("new-key")
	if err != nil {
		t.Fatal(err)
	}
	signingSecret, err := oldBox.Encrypt([]byte("signing-secret"))
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := oldBox.EncryptMap(map[string]string{"username": "ops", "password": "secret"})
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(newBox)
	if err := service.AddChannel(Channel{ID: "ops", Name: "Ops", Kind: KindWebhook, Endpoint: "https://example.test", Enabled: true, SigningSecretCiphertext: signingSecret, CredentialsCiphertext: credentials, CredentialsStored: true}); err != nil {
		t.Fatal(err)
	}
	rotated, err := service.RotateSecrets(newBox, oldBox)
	if err != nil || rotated != 2 {
		t.Fatalf("rotated=%d err=%v", rotated, err)
	}
	channel := service.Channels()[0]
	if value, err := newBox.Decrypt(channel.SigningSecretCiphertext); err != nil || string(value) != "signing-secret" {
		t.Fatalf("signing secret = %q err=%v", value, err)
	}
	values, err := newBox.DecryptMap(channel.CredentialsCiphertext)
	if err != nil || values["password"] != "secret" {
		t.Fatalf("credentials = %#v err=%v", values, err)
	}
}
