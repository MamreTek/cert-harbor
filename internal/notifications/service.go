package notifications

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/MamreTek/cert-harbor/internal/alerts"
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
}

type persistedChannel struct {
	ID                      string `json:"id"`
	Name                    string `json:"name"`
	Kind                    string `json:"kind"`
	Endpoint                string `json:"endpoint"`
	Enabled                 bool   `json:"enabled"`
	CredentialsStored       bool   `json:"credentials_stored"`
	SigningSecretCiphertext string `json:"signing_secret_ciphertext,omitempty"`
}

type Delivery struct {
	ID          string    `json:"id"`
	ChannelID   string    `json:"channel_id"`
	AlertID     string    `json:"alert_id"`
	AlertState  string    `json:"alert_state"`
	Status      string    `json:"status"`
	Attempts    int       `json:"attempts"`
	LastError   string    `json:"last_error,omitempty"`
	DeliveredAt time.Time `json:"delivered_at,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

type Service struct {
	mu         sync.RWMutex
	channels   map[string]Channel
	deliveries []Delivery
	nextID     uint64
	filePath   string
	secrets    *security.SecretBox
	client     *http.Client
	now        func() time.Time
}

func NewService(secrets *security.SecretBox) *Service {
	return &Service{channels: make(map[string]Channel), secrets: secrets, client: &http.Client{Timeout: 5 * time.Second}, now: func() time.Time { return time.Now().UTC() }}
}

// OpenService restores notification channels and delivery history from an
// atomically written snapshot. An absent path or file starts empty.
func OpenService(secrets *security.SecretBox, path string) (*Service, error) {
	service := NewService(secrets)
	service.filePath = path
	if path == "" {
		return service, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return service, nil
	}
	if err != nil {
		return nil, err
	}
	var snapshot struct {
		Version    int                         `json:"version"`
		Channels   map[string]persistedChannel `json:"channels"`
		Deliveries []Delivery                  `json:"deliveries"`
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
			}
		}
	}
	service.deliveries = snapshot.Deliveries
	for _, delivery := range service.deliveries {
		if len(delivery.ID) > len("delivery-") {
			if id, parseErr := strconv.ParseUint(delivery.ID[len("delivery-"):], 10, 64); parseErr == nil && id > service.nextID {
				service.nextID = id
			}
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

func (s *Service) Channels() []Channel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]Channel, 0, len(s.channels))
	for _, channel := range s.channels {
		items = append(items, channel)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	return items
}

func (s *Service) Deliveries() []Delivery {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Delivery(nil), s.deliveries...)
}

func (s *Service) Test(ctx context.Context, id string) (Delivery, error) {
	alert := alerts.Alert{ID: "test-alert", AssetID: "test-asset", AssetKind: "test", AssetName: "CertHarbor test", Provider: "cert-harbor", State: alerts.StateOpen, Severity: "info", UpdatedAt: s.now()}
	return s.dispatchChannel(ctx, id, alert)
}

func (s *Service) Dispatch(ctx context.Context, alert alerts.Alert) []Delivery {
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
	delivery := Delivery{ID: fmt.Sprintf("delivery-%d", s.nextID), ChannelID: channel.ID, AlertID: alert.ID, AlertState: alert.State, Status: "failed", CreatedAt: s.now()}
	s.mu.Unlock()
	var err error
	switch channel.Kind {
	case KindWebhook:
		err = s.sendWebhook(ctx, channel, alert, &delivery)
	case KindEmail:
		err = errors.New("email delivery is not configured")
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

func (s *Service) persistLocked() error {
	if s.filePath == "" {
		return nil
	}
	snapshot := struct {
		Version    int                         `json:"version"`
		Channels   map[string]persistedChannel `json:"channels"`
		Deliveries []Delivery                  `json:"deliveries"`
	}{Version: 1, Channels: make(map[string]persistedChannel, len(s.channels)), Deliveries: s.deliveries}
	for id, channel := range s.channels {
		snapshot.Channels[id] = persistedChannel{
			ID: channel.ID, Name: channel.Name, Kind: channel.Kind, Endpoint: channel.Endpoint,
			Enabled: channel.Enabled, CredentialsStored: channel.CredentialsStored,
			SigningSecretCiphertext: channel.SigningSecretCiphertext,
		}
	}
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
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
	body, err := json.Marshal(map[string]any{"alert": alert, "sent_at": s.now().Format(time.RFC3339)})
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
