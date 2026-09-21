package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/MamreTek/cert-harbor/internal/domain"
	"github.com/MamreTek/cert-harbor/internal/providers"
)

func New(fixturePath string) providers.Adapter {
	capabilities := providers.Capabilities{
		Provider:             providers.Cloudflare,
		Domains:              true,
		Certificates:         true,
		CredentialGuidance:   "Fixture mode needs no credential. Live mode uses a scoped API token with Zone Read, DNS Read when nameserver metadata is required, and SSL and Certificates Read; set zone_id for certificate-pack inventory.",
		SupportedSourceTypes: []string{"zone", "certificate"},
	}
	fixture := providers.NewFixtureAdapter(providers.Cloudflare, fixturePath, capabilities)
	return providers.NewCredentialSwitchAdapter(fixture, NewLiveAdapter())
}

type LiveAdapter struct {
	baseURL string
	client  *http.Client
}

func NewLiveAdapter() providers.Adapter {
	return &LiveAdapter{baseURL: "https://api.cloudflare.com/client/v4", client: &http.Client{Timeout: 15 * time.Second}}
}

func newLiveAdapter(baseURL string, client *http.Client) *LiveAdapter {
	return &LiveAdapter{baseURL: strings.TrimRight(baseURL, "/"), client: client}
}

func (a *LiveAdapter) Provider() providers.Provider { return providers.Cloudflare }

func (a *LiveAdapter) Capabilities() providers.Capabilities {
	return providers.Capabilities{
		Provider:             providers.Cloudflare,
		Domains:              true,
		Certificates:         true,
		CredentialGuidance:   "Use a scoped API token with Zone Read, DNS Read when nameserver metadata is required, and SSL and Certificates Read; set zone_id for certificate-pack inventory.",
		SupportedSourceTypes: []string{"zone", "certificate"},
	}
}

func (a *LiveAdapter) Test(ctx context.Context, credentials providers.Credentials) (providers.TestResult, error) {
	response, requestID, err := a.get(ctx, credentials, "/zones", url.Values{"page": {"1"}, "per_page": {"1"}})
	if err != nil {
		return providers.TestResult{}, err
	}
	_ = response
	return providers.TestResult{Provider: providers.Cloudflare, RequestID: requestID, Capabilities: a.Capabilities()}, nil
}

func (a *LiveAdapter) ListDomains(ctx context.Context, credentials providers.Credentials, cursor string) (providers.DomainPage, error) {
	page := 1
	if cursor != "" {
		parsed, err := strconv.Atoi(cursor)
		if err != nil || parsed < 1 {
			return providers.DomainPage{}, fmt.Errorf("invalid Cloudflare zone page cursor")
		}
		page = parsed
	}
	response, _, err := a.get(ctx, credentials, "/zones", url.Values{"page": {strconv.Itoa(page)}, "per_page": {"100"}})
	if err != nil {
		return providers.DomainPage{}, err
	}
	var payload struct {
		Result []struct {
			ID                  string    `json:"id"`
			Name                string    `json:"name"`
			Status              string    `json:"status"`
			NameServers         []string  `json:"name_servers"`
			OriginalNameServers []string  `json:"original_name_servers"`
			CreatedOn           time.Time `json:"created_on"`
			ModifiedOn          time.Time `json:"modified_on"`
		} `json:"result"`
		ResultInfo struct {
			Page       int `json:"page"`
			TotalPages int `json:"total_pages"`
		} `json:"result_info"`
	}
	if err := json.Unmarshal(response, &payload); err != nil {
		return providers.DomainPage{}, fmt.Errorf("decode Cloudflare zones: %w", err)
	}
	items := make([]domain.Domain, 0, len(payload.Result))
	for _, zone := range payload.Result {
		items = append(items, domain.Domain{SourceID: zone.ID, Name: zone.Name, RegistrableDomain: zone.Name, Zone: zone.Name, Status: zone.Status, Nameservers: append(zone.NameServers, zone.OriginalNameServers...), SourceURL: a.baseURL + "/zones/" + zone.ID})
	}
	next := ""
	if payload.ResultInfo.TotalPages > page {
		next = strconv.Itoa(page + 1)
	}
	return providers.DomainPage{Items: items, NextCursor: next}, nil
}

func (a *LiveAdapter) ListCertificates(ctx context.Context, credentials providers.Credentials, cursor string) (providers.CertificatePage, error) {
	zoneID := strings.TrimSpace(credentials.Values["zone_id"])
	if zoneID == "" {
		return providers.CertificatePage{}, errors.New("Cloudflare live certificate inventory requires credential field zone_id")
	}
	page := 1
	if cursor != "" {
		parsed, err := strconv.Atoi(cursor)
		if err != nil || parsed < 1 {
			return providers.CertificatePage{}, fmt.Errorf("invalid Cloudflare certificate page cursor")
		}
		page = parsed
	}
	path := "/zones/" + url.PathEscape(zoneID) + "/ssl/certificate_packs"
	response, _, err := a.get(ctx, credentials, path, url.Values{"page": {strconv.Itoa(page)}, "per_page": {"100"}})
	if err != nil {
		return providers.CertificatePage{}, err
	}
	var payload struct {
		Result []struct {
			ID                   string     `json:"id"`
			Hosts                []string   `json:"hosts"`
			Status               string     `json:"status"`
			CertificateAuthority string     `json:"certificate_authority"`
			IssuedOn             *time.Time `json:"issued_on"`
			ExpiresOn            *time.Time `json:"expires_on"`
		} `json:"result"`
		ResultInfo struct {
			Page       int `json:"page"`
			TotalPages int `json:"total_pages"`
		} `json:"result_info"`
	}
	if err := json.Unmarshal(response, &payload); err != nil {
		return providers.CertificatePage{}, fmt.Errorf("decode Cloudflare certificate packs: %w", err)
	}
	items := make([]domain.Certificate, 0, len(payload.Result))
	for _, certificate := range payload.Result {
		commonName := ""
		if len(certificate.Hosts) > 0 {
			commonName = certificate.Hosts[0]
		}
		validFrom := time.Time{}
		validTo := time.Time{}
		if certificate.IssuedOn != nil {
			validFrom = *certificate.IssuedOn
		}
		if certificate.ExpiresOn != nil {
			validTo = *certificate.ExpiresOn
		}
		items = append(items, domain.Certificate{SourceID: certificate.ID, CommonName: commonName, SANs: certificate.Hosts, Issuer: certificate.CertificateAuthority, Status: certificate.Status, ValidFrom: validFrom, ValidTo: validTo, SourceURL: a.baseURL + "/zones/" + zoneID + "/ssl/certificate_packs/" + certificate.ID})
	}
	next := ""
	if payload.ResultInfo.TotalPages > page {
		next = strconv.Itoa(page + 1)
	}
	return providers.CertificatePage{Items: items, NextCursor: next}, nil
}

func (a *LiveAdapter) get(ctx context.Context, credentials providers.Credentials, endpoint string, query url.Values) ([]byte, string, error) {
	token := strings.TrimSpace(credentials.Values["token"])
	if token == "" {
		token = strings.TrimSpace(credentials.Values["api_token"])
	}
	if token == "" {
		return nil, "", errors.New("Cloudflare API token is required")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, a.baseURL+endpoint+"?"+query.Encode(), nil)
	if err != nil {
		return nil, "", err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")
	var body []byte
	requestID := ""
	for attempt := 1; attempt <= 3; attempt++ {
		response, requestErr := a.client.Do(request)
		if requestErr != nil {
			if attempt == 3 {
				return nil, requestID, fmt.Errorf("Cloudflare request failed: %w", requestErr)
			}
			if err := retryWait(ctx, attempt); err != nil {
				return nil, requestID, err
			}
			continue
		}
		requestID = response.Header.Get("CF-Ray")
		body, err = io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil {
			return nil, requestID, fmt.Errorf("read Cloudflare response: %w", err)
		}
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			break
		}
		if (response.StatusCode != http.StatusTooManyRequests && response.StatusCode < 500) || attempt == 3 {
			return nil, requestID, fmt.Errorf("Cloudflare API returned HTTP %d", response.StatusCode)
		}
		if err := retryWait(ctx, attempt); err != nil {
			return nil, requestID, err
		}
	}
	var envelope struct {
		Success bool `json:"success"`
		Errors  []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, requestID, fmt.Errorf("decode Cloudflare response: %w", err)
	}
	if !envelope.Success {
		return nil, requestID, errors.New("Cloudflare API rejected the request")
	}
	return body, requestID, nil
}

func retryWait(ctx context.Context, attempt int) error {
	timer := time.NewTimer(time.Duration(attempt*100) * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
