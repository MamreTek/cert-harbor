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

type Credentials struct {
	Values map[string]string
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
