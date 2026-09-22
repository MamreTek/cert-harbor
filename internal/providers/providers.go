package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/MamreTek/cert-harbor/internal/domain"
)

type Provider string

const (
	AlibabaCloud Provider = "alibaba_cloud"
	Tencent      Provider = "tencent"
	AWS          Provider = "aws"
	Cloudflare   Provider = "cloudflare"
)

func Supported(provider Provider) bool {
	definition, ok := DefinitionFor(provider)
	return ok && definition.Enabled
}

// Definition is the provider catalog entry exposed to the console. Keeping
// this metadata beside the adapter contract prevents the UI from maintaining
// a second, potentially stale provider list.
type Definition struct {
	ID           Provider     `json:"id"`
	Name         string       `json:"name"`
	Enabled      bool         `json:"enabled"`
	Capabilities Capabilities `json:"capabilities"`
}

var definitions = []Definition{
	{ID: AlibabaCloud, Name: "Alibaba Cloud", Enabled: true, Capabilities: Capabilities{Provider: AlibabaCloud, Domains: true, Certificates: true, CredentialGuidance: "Alibaba Cloud RAM credentials with DNS and certificate inventory permissions", SupportedSourceTypes: []string{"dns", "certificate"}}},
	{ID: Tencent, Name: "Tencent Cloud / DNSPod", Enabled: true, Capabilities: Capabilities{Provider: Tencent, Domains: true, Certificates: true, CredentialGuidance: "Tencent Cloud API credentials with DNSPod and certificate inventory permissions", SupportedSourceTypes: []string{"dns", "certificate"}}},
	{ID: AWS, Name: "Amazon Web Services", Enabled: true, Capabilities: Capabilities{Provider: AWS, Domains: true, Certificates: true, CredentialGuidance: "AWS IAM credentials with Route 53 and ACM read permissions", SupportedSourceTypes: []string{"dns", "certificate"}}},
	{ID: Cloudflare, Name: "Cloudflare", Enabled: true, Capabilities: Capabilities{Provider: Cloudflare, Domains: true, Certificates: true, CredentialGuidance: "Cloudflare API token scoped to zone and certificate read permissions", SupportedSourceTypes: []string{"dns", "certificate"}}},
}

// Definitions returns a copy so callers cannot mutate the provider registry.
func Definitions() []Definition {
	items := make([]Definition, len(definitions))
	copy(items, definitions)
	return items
}

func DefinitionFor(provider Provider) (Definition, bool) {
	for _, definition := range definitions {
		if definition.ID == provider {
			return definition, true
		}
	}
	return Definition{}, false
}

type Credentials struct {
	Values map[string]string
}

// APIError is a safe provider failure classification. It carries the
// provider request ID without retaining response bodies or credentials.
type APIError struct {
	Provider   Provider
	RequestID  string
	StatusCode int
	Retryable  bool
	Message    string
}

func (e *APIError) Error() string {
	requestID := e.RequestID
	if requestID == "" {
		requestID = "unknown"
	}
	if e.StatusCode > 0 {
		return fmt.Sprintf("%s provider request failed (status=%d, request_id=%s): %s", e.Provider, e.StatusCode, requestID, e.Message)
	}
	return fmt.Sprintf("%s provider request failed (request_id=%s): %s", e.Provider, requestID, e.Message)
}

func (e *APIError) Unwrap() error { return nil }

func IsRetryable(err error) bool {
	var providerErr *APIError
	return errors.As(err, &providerErr) && providerErr.Retryable
}

func RequestID(err error) string {
	var providerErr *APIError
	if errors.As(err, &providerErr) {
		return providerErr.RequestID
	}
	return ""
}

func NewAPIError(provider Provider, requestID string, statusCode int, retryable bool, message string) error {
	return &APIError{Provider: provider, RequestID: requestID, StatusCode: statusCode, Retryable: retryable, Message: message}
}

type Capabilities struct {
	Provider             Provider `json:"provider"`
	Domains              bool     `json:"domains"`
	Certificates         bool     `json:"certificates"`
	CredentialGuidance   string   `json:"credential_guidance"`
	SupportedSourceTypes []string `json:"supported_source_types"`
}

type TestResult struct {
	Provider     Provider     `json:"provider"`
	RequestID    string       `json:"request_id"`
	Capabilities Capabilities `json:"capabilities"`
}

type DomainPage struct {
	Items      []domain.Domain
	NextCursor string
}

type CertificatePage struct {
	Items      []domain.Certificate
	NextCursor string
}

type Adapter interface {
	Provider() Provider
	Capabilities() Capabilities
	Test(context.Context, Credentials) (TestResult, error)
	ListDomains(context.Context, Credentials, string) (DomainPage, error)
	ListCertificates(context.Context, Credentials, string) (CertificatePage, error)
}

// CredentialSwitchAdapter uses the live adapter when credentials are present
// and keeps the deterministic fixture adapter available for demo mode.
type CredentialSwitchAdapter struct {
	fixture Adapter
	live    Adapter
}

func NewCredentialSwitchAdapter(fixture, live Adapter) Adapter {
	return &CredentialSwitchAdapter{fixture: fixture, live: live}
}

func (a *CredentialSwitchAdapter) Provider() Provider { return a.fixture.Provider() }

func (a *CredentialSwitchAdapter) Capabilities() Capabilities { return a.fixture.Capabilities() }

func (a *CredentialSwitchAdapter) selected(credentials Credentials) Adapter {
	if a.live != nil && len(credentials.Values) > 0 {
		return a.live
	}
	return a.fixture
}

func (a *CredentialSwitchAdapter) Test(ctx context.Context, credentials Credentials) (TestResult, error) {
	return a.selected(credentials).Test(ctx, credentials)
}

func (a *CredentialSwitchAdapter) ListDomains(ctx context.Context, credentials Credentials, cursor string) (DomainPage, error) {
	return a.selected(credentials).ListDomains(ctx, credentials, cursor)
}

func (a *CredentialSwitchAdapter) ListCertificates(ctx context.Context, credentials Credentials, cursor string) (CertificatePage, error) {
	return a.selected(credentials).ListCertificates(ctx, credentials, cursor)
}

type fixturePayload struct {
	Domains      []domain.Domain      `json:"domains"`
	Certificates []domain.Certificate `json:"certificates"`
}

type FixtureAdapter struct {
	provider     Provider
	fixturePath  string
	capabilities Capabilities
}

func NewFixtureAdapter(provider Provider, fixturePath string, capabilities Capabilities) Adapter {
	return &FixtureAdapter{provider: provider, fixturePath: fixturePath, capabilities: capabilities}
}

func (a *FixtureAdapter) Provider() Provider {
	return a.provider
}

func (a *FixtureAdapter) Capabilities() Capabilities {
	return a.capabilities
}

func (a *FixtureAdapter) Test(ctx context.Context, _ Credentials) (TestResult, error) {
	if err := ctx.Err(); err != nil {
		return TestResult{}, err
	}
	if _, err := a.load(); err != nil {
		return TestResult{}, err
	}
	return TestResult{
		Provider:     a.provider,
		RequestID:    "fixture-" + string(a.provider),
		Capabilities: a.capabilities,
	}, nil
}

func (a *FixtureAdapter) ListDomains(ctx context.Context, _ Credentials, cursor string) (DomainPage, error) {
	if err := ctx.Err(); err != nil {
		return DomainPage{}, err
	}
	payload, err := a.load()
	if err != nil {
		return DomainPage{}, err
	}
	items, next, err := page(payload.Domains, cursor)
	return DomainPage{Items: items, NextCursor: next}, err
}

func (a *FixtureAdapter) ListCertificates(ctx context.Context, _ Credentials, cursor string) (CertificatePage, error) {
	if err := ctx.Err(); err != nil {
		return CertificatePage{}, err
	}
	payload, err := a.load()
	if err != nil {
		return CertificatePage{}, err
	}
	items, next, err := page(payload.Certificates, cursor)
	return CertificatePage{Items: items, NextCursor: next}, err
}

func (a *FixtureAdapter) load() (fixturePayload, error) {
	if a.fixturePath == "" {
		return fixturePayload{}, errors.New("provider fixture path is empty")
	}
	file, err := os.Open(a.fixturePath)
	if err != nil {
		return fixturePayload{}, fmt.Errorf("open provider fixture: %w", err)
	}
	defer file.Close()

	var payload fixturePayload
	if err := json.NewDecoder(file).Decode(&payload); err != nil {
		return fixturePayload{}, fmt.Errorf("decode provider fixture: %w", err)
	}
	return payload, nil
}

func page[T any](items []T, cursor string) ([]T, string, error) {
	start := 0
	if cursor != "" {
		parsed, err := strconv.Atoi(cursor)
		if err != nil || parsed < 0 {
			return nil, "", fmt.Errorf("invalid provider page cursor %q", cursor)
		}
		start = parsed
	}
	if start > len(items) {
		return nil, "", fmt.Errorf("provider page cursor %q is out of range", cursor)
	}
	end := start + 100
	if end > len(items) {
		end = len(items)
	}
	next := ""
	if end < len(items) {
		next = strconv.Itoa(end)
	}
	return items[start:end], next, nil
}
