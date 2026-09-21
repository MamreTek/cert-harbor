package notifications

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MamreTek/cert-harbor/internal/alerts"
	"github.com/MamreTek/cert-harbor/internal/catalog"
	"github.com/MamreTek/cert-harbor/internal/security"
)

const (
	KindEmail   = "email"
	KindWebhook = "webhook"
)

type Channel struct {
	ID                      string `json:"id"`
	Name                    string `json:"name"`
	Kind                    string `json:"kind"`
	Endpoint                string `json:"endpoint"`
	Enabled                 bool   `json:"enabled"`
	CredentialsStored       bool   `json:"credentials_stored"`
	SigningSecretCiphertext string `json:"-"`
	CredentialsCiphertext   string `json:"-"`
}

type persistedChannel struct {
	ID                      string `json:"id"`
	Name                    string `json:"name"`
	Kind                    string `json:"kind"`
	Endpoint                string `json:"endpoint"`
	Enabled                 bool   `json:"enabled"`
	CredentialsStored       bool   `json:"credentials_stored"`
	SigningSecretCiphertext string `json:"signing_secret_ciphertext,omitempty"`
	CredentialsCiphertext   string `json:"credentials_ciphertext,omitempty"`
}

type Delivery struct {
	ID            string    `json:"id"`
	CorrelationID string    `json:"correlation_id"`
	ChannelID     string    `json:"channel_id"`
	AlertID       string    `json:"alert_id"`
	AlertState    string    `json:"alert_state"`
	Status        string    `json:"status"`
	Attempts      int       `json:"attempts"`
	LastError     string    `json:"last_error,omitempty"`
	DeliveredAt   time.Time `json:"delivered_at,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

type outboxItem struct {
	ID        string       `json:"id"`
	Alert     alerts.Alert `json:"alert"`
	CreatedAt time.Time    `json:"created_at"`
}

type Service struct {
	mu         sync.RWMutex
	deliveryMu sync.Mutex
	channels   map[string]Channel
	deliveries []Delivery
	outbox     []outboxItem
	nextID     uint64
	filePath   string
	backend    catalog.StateBackend
	secrets    *security.SecretBox
	client     *http.Client
	now        func() time.Time
}

func NewService(secrets *security.SecretBox) *Service {
	return &Service{channels: make(map[string]Channel), secrets: secrets, client: &http.Client{Timeout: 5 * time.Second}, now: func() time.Time { return time.Now().UTC() }}
}

// OpenService restores notification channels and delivery history from an
// atomically written snapshot. An absent path or file starts empty.
func OpenService(secrets *security.SecretBox, path string, backends ...catalog.StateBackend) (*Service, error) {
	service := NewService(secrets)
	service.filePath = path
	if len(backends) > 0 {
		service.backend = backends[0]
	}
	var data []byte
	migratedFromFile := false
	if service.backend != nil {
		loaded, err := service.backend.LoadState("notifications")
		if err != nil {
			return nil, err
		}
		data = loaded
		if len(data) == 0 && path != "" {
			legacyData, legacyErr := os.ReadFile(path)
			if legacyErr == nil && len(legacyData) > 0 {
				data = legacyData
				migratedFromFile = true
			} else if legacyErr != nil && !errors.Is(legacyErr, os.ErrNotExist) {
				return nil, legacyErr
			}
		}
	} else if path != "" {
		loaded, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			return service, nil
		}
		if err != nil {
			return nil, err
		}
		data = loaded
	}
	if len(data) == 0 {
		return service, nil
	}
	var snapshot struct {
		Version    int                         `json:"version"`
		Channels   map[string]persistedChannel `json:"channels"`
		Deliveries []Delivery                  `json:"deliveries"`
		Outbox     []outboxItem                `json:"outbox"`
	}
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return nil, err
	}
	if snapshot.Channels != nil {
		for id, channel := range snapshot.Channels {
			service.channels[id] = Channel{
				ID: channel.ID, Name: channel.Name, Kind: channel.Kind, Endpoint: channel.Endpoint,
				Enabled: channel.Enabled, CredentialsStored: channel.CredentialsStored,
				SigningSecretCiphertext: channel.SigningSecretCiphertext,
				CredentialsCiphertext:   channel.CredentialsCiphertext,
			}
		}
	}
	service.deliveries = snapshot.Deliveries
	service.outbox = snapshot.Outbox
	legacyCorrelation := false
	for index := range service.deliveries {
		delivery := &service.deliveries[index]
		if delivery.CorrelationID == "" {
			delivery.CorrelationID = "corr-" + delivery.ID
			legacyCorrelation = true
		}
		if len(delivery.ID) > len("delivery-") {
			if id, parseErr := strconv.ParseUint(delivery.ID[len("delivery-"):], 10, 64); parseErr == nil && id > service.nextID {
				service.nextID = id
			}
		}
	}
	for _, item := range service.outbox {
		if len(item.ID) > len("outbox-") {
			if id, parseErr := strconv.ParseUint(item.ID[len("outbox-"):], 10, 64); parseErr == nil && id > service.nextID {
				service.nextID = id
			}
		}
	}
	if migratedFromFile || legacyCorrelation {
		if err := service.persistLocked(); err != nil {
			return nil, fmt.Errorf("migrate legacy notification state: %w", err)
		}
	}
	return service, nil
}

func (s *Service) AddChannel(channel Channel) error {
	if channel.ID == "" || channel.Name == "" || channel.Endpoint == "" || (channel.Kind != KindEmail && channel.Kind != KindWebhook) {
		return errors.New("channel id, name, supported kind, and endpoint are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.channels[channel.ID]; ok {
		return errors.New("notification channel already exists")
	}
	s.channels[channel.ID] = channel
	return s.persistLocked()
}

func (s *Service) UpdateChannel(id, name, endpoint string, enabled bool) (Channel, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	channel, ok := s.channels[id]
	if !ok {
		return Channel{}, errors.New("notification channel not found")
	}
	if name != "" {
		channel.Name = name
	}
	if endpoint != "" {
		channel.Endpoint = endpoint
	}
	channel.Enabled = enabled
	s.channels[id] = channel
	if err := s.persistLocked(); err != nil {
		return Channel{}, err
	}
	return channel, nil
}

func (s *Service) DeleteChannel(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.channels[id]; !ok {
		return errors.New("notification channel not found")
	}
	delete(s.channels, id)
	return s.persistLocked()
}

func (s *Service) SetSigningSecret(id, ciphertext string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	channel, ok := s.channels[id]
	if !ok {
		return errors.New("notification channel not found")
	}
	channel.SigningSecretCiphertext = ciphertext
	channel.CredentialsStored = ciphertext != ""
	s.channels[id] = channel
	return s.persistLocked()
}

func (s *Service) SetCredentials(id, ciphertext string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	channel, ok := s.channels[id]
	if !ok {
		return errors.New("notification channel not found")
	}
	channel.CredentialsCiphertext = ciphertext
	channel.CredentialsStored = ciphertext != "" || channel.SigningSecretCiphertext != ""
	s.channels[id] = channel
	return s.persistLocked()
}

func (s *Service) RotateSecrets(current, previous *security.SecretBox) (int, error) {
	if current == nil {
		return 0, errors.New("current encryption key is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rotated := 0
	for id, channel := range s.channels {
		if channel.SigningSecretCiphertext != "" {
			ciphertext, changed, err := current.Reencrypt(channel.SigningSecretCiphertext, previous)
			if err != nil {
				return rotated, fmt.Errorf("rotate signing secret for channel %s: %w", id, err)
			}
			if changed {
				channel.SigningSecretCiphertext = ciphertext
				rotated++
			}
		}
		if channel.CredentialsCiphertext != "" {
			ciphertext, changed, err := current.Reencrypt(channel.CredentialsCiphertext, previous)
			if err != nil {
				return rotated, fmt.Errorf("rotate credentials for channel %s: %w", id, err)
			}
			if changed {
				channel.CredentialsCiphertext = ciphertext
				rotated++
			}
		}
		s.channels[id] = channel
	}
	if rotated == 0 {
		return 0, nil
	}
	return rotated, s.persistLocked()
}

func (s *Service) Channels() []Channel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]Channel, 0, len(s.channels))
	for _, channel := range s.channels {
		items = append(items, channel)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Name == items[j].Name {
			return items[i].ID < items[j].ID
		}
		return items[i].Name < items[j].Name
	})
	return items
}

func (s *Service) Deliveries() []Delivery {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Delivery(nil), s.deliveries...)
}

func (s *Service) Test(ctx context.Context, id string) (Delivery, error) {
	s.deliveryMu.Lock()
	defer s.deliveryMu.Unlock()
	alert := alerts.Alert{ID: "test-alert", AssetID: "test-asset", AssetKind: "test", AssetName: "CertHarbor test", Provider: "cert-harbor", State: alerts.StateOpen, Severity: "info", UpdatedAt: s.now()}
	return s.dispatchChannel(ctx, id, alert)
}

func (s *Service) Dispatch(ctx context.Context, alert alerts.Alert) []Delivery {
	s.deliveryMu.Lock()
	defer s.deliveryMu.Unlock()
	return s.dispatch(ctx, alert)
}

func (s *Service) dispatch(ctx context.Context, alert alerts.Alert) []Delivery {
	channels := s.Channels()
	items := make([]Delivery, 0, len(channels))
	for _, channel := range channels {
		if !channel.Enabled {
			continue
		}
		if previous, ok := s.deliveredFor(channel.ID, alert.ID, alert.State); ok {
			items = append(items, previous)
			continue
		}
		delivery, _ := s.dispatchChannel(ctx, channel.ID, alert)
		items = append(items, delivery)
	}
	return items
}

func (s *Service) Queue(alert alerts.Alert) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hasDeliveredForAllEnabledLocked(alert) || s.hasQueuedLocked(alert) {
		return nil
	}
	s.nextID++
	s.outbox = append(s.outbox, outboxItem{ID: fmt.Sprintf("outbox-%d", s.nextID), Alert: alert, CreatedAt: s.now()})
	return s.persistLocked()
}

func (s *Service) DeliverOutbox(ctx context.Context) []Delivery {
	s.deliveryMu.Lock()
	defer s.deliveryMu.Unlock()
	s.mu.RLock()
	items := append([]outboxItem(nil), s.outbox...)
	s.mu.RUnlock()
	deliveries := make([]Delivery, 0)
	for _, item := range items {
		current := s.dispatch(ctx, item.Alert)
		deliveries = append(deliveries, current...)
		if len(current) == 0 || allDelivered(current) {
			s.mu.Lock()
			s.removeOutboxLocked(item.ID)
			_ = s.persistLocked()
			s.mu.Unlock()
		}
	}
	return deliveries
}

func allDelivered(deliveries []Delivery) bool {
	for _, delivery := range deliveries {
		if delivery.Status != "delivered" {
			return false
		}
	}
	return true
}

func (s *Service) hasDeliveredForAllEnabledLocked(alert alerts.Alert) bool {
	for _, channel := range s.channels {
		if !channel.Enabled {
			continue
		}
		delivered := false
		for _, delivery := range s.deliveries {
			if delivery.ChannelID == channel.ID && delivery.AlertID == alert.ID && delivery.AlertState == alert.State && delivery.Status == "delivered" {
				delivered = true
				break
			}
		}
		if !delivered {
			return false
		}
	}
	return true
}

func (s *Service) hasQueuedLocked(alert alerts.Alert) bool {
	for _, item := range s.outbox {
		if item.Alert.ID == alert.ID && item.Alert.State == alert.State {
			return true
		}
	}
	return false
}

func (s *Service) removeOutboxLocked(id string) {
	for index, item := range s.outbox {
		if item.ID == id {
			s.outbox = append(s.outbox[:index], s.outbox[index+1:]...)
			return
		}
	}
}

func (s *Service) deliveredFor(channelID, alertID, alertState string) (Delivery, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := len(s.deliveries) - 1; i >= 0; i-- {
		delivery := s.deliveries[i]
		if delivery.ChannelID == channelID && delivery.AlertID == alertID && delivery.AlertState == alertState && delivery.Status == "delivered" {
			return delivery, true
		}
	}
	return Delivery{}, false
}

func (s *Service) dispatchChannel(ctx context.Context, channelID string, alert alerts.Alert) (Delivery, error) {
	s.mu.RLock()
	channel, ok := s.channels[channelID]
	s.mu.RUnlock()
	if !ok {
		return Delivery{}, errors.New("notification channel not found")
	}
	s.mu.Lock()
	s.nextID++
	delivery := Delivery{ID: fmt.Sprintf("delivery-%d", s.nextID), CorrelationID: fmt.Sprintf("corr-delivery-%d", s.nextID), ChannelID: channel.ID, AlertID: alert.ID, AlertState: alert.State, Status: "failed", CreatedAt: s.now()}
	s.mu.Unlock()
	var err error
	switch channel.Kind {
	case KindWebhook:
		err = s.sendWebhook(ctx, channel, alert, &delivery)
	case KindEmail:
		for attempt := 1; attempt <= 3; attempt++ {
			delivery.Attempts = attempt
			err = s.sendEmail(ctx, channel, alert, &delivery)
			if err == nil || attempt == 3 {
				break
			}
			if waitErr := retryWait(ctx, attempt); waitErr != nil {
				err = waitErr
				break
			}
		}
	default:
		err = errors.New("unsupported notification channel")
	}
	if err == nil {
		delivery.Status = "delivered"
		delivery.DeliveredAt = s.now()
	} else {
		delivery.LastError = err.Error()
	}
	s.mu.Lock()
	s.deliveries = append(s.deliveries, delivery)
	persistErr := s.persistLocked()
	s.mu.Unlock()
	if persistErr != nil && err == nil {
		err = persistErr
		delivery.Status = "failed"
		delivery.LastError = persistErr.Error()
	}
	return delivery, err
}

func (s *Service) sendEmail(ctx context.Context, channel Channel, alert alerts.Alert, delivery *Delivery) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.secrets == nil || channel.CredentialsCiphertext == "" {
		return errors.New("email SMTP credentials are not configured")
	}
	credentials, err := s.secrets.DecryptMap(channel.CredentialsCiphertext)
	if err != nil {
		return errors.New("email SMTP credentials cannot be decrypted")
	}
	endpoint, err := url.Parse(channel.Endpoint)
	if err != nil || (endpoint.Scheme != "smtp" && endpoint.Scheme != "smtps") || endpoint.Host == "" {
		return errors.New("email endpoint must be an smtp:// or smtps:// URL")
	}
	from := endpoint.Query().Get("from")
	if from == "" {
		from = credentials["from"]
	}
	to := endpoint.Query().Get("to")
	if to == "" {
		to = credentials["to"]
	}
	if from == "" || to == "" {
		return errors.New("email sender and recipient are required")
	}
	recipients := strings.FieldsFunc(to, func(r rune) bool { return r == ',' || r == ';' || r == ' ' })
	if len(recipients) == 0 {
		return errors.New("email recipient is required")
	}
	host := endpoint.Hostname()
	port := endpoint.Port()
	if port == "" {
		port = "25"
	}
	server := host + ":" + port
	var auth smtp.Auth
	if username := credentials["username"]; username != "" {
		auth = smtp.PlainAuth("", username, credentials["password"], host)
	}
	body := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: CertHarbor alert: %s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nAlert %s\nAsset: %s (%s)\nProvider: %s\nState: %s\nSeverity: %s\nDays remaining: %s\nExpires at: %s\nFreshness: %s\nSource: %s\nDeep link: %s\nCorrelation ID: %s\n", from, strings.Join(recipients, ", "), alert.AssetName, alert.ID, alert.AssetName, alert.AssetKind, alert.Provider, alert.State, alert.Severity, formatDays(alert.DaysRemaining), formatTime(alert.ExpiresAt), valueOrUnknown(alert.Freshness), valueOrUnknown(alert.SourceURL), valueOrUnknown(alert.DeepLink), delivery.CorrelationID)
	if err := sendSMTP(ctx, endpoint.Scheme == "smtps", server, host, auth, from, recipients, []byte(body)); err != nil {
		return fmt.Errorf("send SMTP email: %w", err)
	}
	return nil
}

func sendSMTP(ctx context.Context, secure bool, server, host string, auth smtp.Auth, from string, recipients []string, message []byte) error {
	if !secure {
		return smtp.SendMail(server, auth, from, recipients, message)
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	connection, err := tls.DialWithDialer(dialer, "tcp", server, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	if err != nil {
		return err
	}
	client, err := smtp.NewClient(connection, host)
	if err != nil {
		_ = connection.Close()
		return err
	}
	defer client.Close()
	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return err
		}
	}
	if err := client.Mail(from); err != nil {
		return err
	}
	for _, recipient := range recipients {
		if err := client.Rcpt(recipient); err != nil {
			return err
		}
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := writer.Write(message); err != nil {
		_ = writer.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return client.Quit()
}

func formatDays(days *int) string {
	if days == nil {
		return "unknown"
	}
	return strconv.Itoa(*days)
}

func (s *Service) persistLocked() error {
	snapshot := struct {
		Version    int                         `json:"version"`
		Channels   map[string]persistedChannel `json:"channels"`
		Deliveries []Delivery                  `json:"deliveries"`
		Outbox     []outboxItem                `json:"outbox"`
	}{Version: 1, Channels: make(map[string]persistedChannel, len(s.channels)), Deliveries: s.deliveries, Outbox: s.outbox}
	for id, channel := range s.channels {
		snapshot.Channels[id] = persistedChannel{
			ID: channel.ID, Name: channel.Name, Kind: channel.Kind, Endpoint: channel.Endpoint,
			Enabled: channel.Enabled, CredentialsStored: channel.CredentialsStored,
			SigningSecretCiphertext: channel.SigningSecretCiphertext,
			CredentialsCiphertext:   channel.CredentialsCiphertext,
		}
	}
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	if s.backend != nil {
		return s.backend.SaveState("notifications", data)
	}
	if s.filePath == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.filePath), 0o700); err != nil {
		return err
	}
	temporary := s.filePath + ".tmp"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(temporary, s.filePath); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

func (s *Service) sendWebhook(ctx context.Context, channel Channel, alert alerts.Alert, delivery *Delivery) error {
	if s.secrets == nil || channel.SigningSecretCiphertext == "" {
		return errors.New("webhook signing secret is not configured")
	}
	secret, err := s.secrets.Decrypt(channel.SigningSecretCiphertext)
	if err != nil {
		return errors.New("webhook signing secret cannot be decrypted")
	}
	deepLink := alert.DeepLink
	if deepLink == "" {
		deepLink = "/alerts/" + alert.ID
	}
	body, err := json.Marshal(map[string]any{"alert": alert, "deep_link": deepLink, "correlation_id": delivery.CorrelationID, "sent_at": s.now().Format(time.RFC3339)})
	if err != nil {
		return err
	}
	for attempt := 1; attempt <= 3; attempt++ {
		delivery.Attempts = attempt
		timestamp := fmt.Sprintf("%d", s.now().Unix())
		mac := hmac.New(sha256.New, secret)
		_, _ = mac.Write([]byte(timestamp + "."))
		_, _ = mac.Write(body)
		req, requestErr := http.NewRequestWithContext(ctx, http.MethodPost, channel.Endpoint, bytes.NewReader(body))
		if requestErr != nil {
			return requestErr
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CertHarbor-Timestamp", timestamp)
		req.Header.Set("X-CertHarbor-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
		response, requestErr := s.client.Do(req)
		if requestErr == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode >= 200 && response.StatusCode < 300 {
				return nil
			}
			err = fmt.Errorf("webhook returned HTTP %d", response.StatusCode)
		} else {
			err = requestErr
		}
		if attempt < 3 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * 10 * time.Millisecond):
			}
		}
	}
	return err
}

func formatTime(value *time.Time) string {
	if value == nil {
		return "unknown"
	}
	return value.UTC().Format(time.RFC3339)
}

func valueOrUnknown(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}
	return value
}

func retryWait(ctx context.Context, attempt int) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(time.Duration(attempt) * 10 * time.Millisecond):
		return nil
	}
}
