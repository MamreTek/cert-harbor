package alibaba

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/MamreTek/cert-harbor/internal/domain"
	"github.com/MamreTek/cert-harbor/internal/providers"
)

func New(fixturePath string) providers.Adapter {
	capabilities := providers.Capabilities{
		Provider:             providers.AlibabaCloud,
		Domains:              true,
		Certificates:         true,
		CredentialGuidance:   "Fixture mode needs no credential. Live mode uses a RAM user or role with alidns:DescribeDomains, alidns:DescribeDomainInfo, and certificate list permissions such as yundun-cert:ListCert or yundun-cert:ListUserCertificateOrder; set access_key_id and access_key_secret.",
		SupportedSourceTypes: []string{"dns_zone", "certificate"},
	}
	fixture := providers.NewFixtureAdapter(providers.AlibabaCloud, fixturePath, capabilities)
	return providers.NewCredentialSwitchAdapter(fixture, NewLiveAdapter())
}

type LiveAdapter struct {
	dnsEndpoint string
	casEndpoint string
	client      *http.Client
}

func NewLiveAdapter() providers.Adapter {
	return &LiveAdapter{dnsEndpoint: "https://alidns.aliyuncs.com", casEndpoint: "https://cas.aliyuncs.com", client: &http.Client{Timeout: 15 * time.Second}}
}

func newLiveAdapter(dnsEndpoint, casEndpoint string, client *http.Client) *LiveAdapter {
	return &LiveAdapter{dnsEndpoint: strings.TrimRight(dnsEndpoint, "/"), casEndpoint: strings.TrimRight(casEndpoint, "/"), client: client}
}

func (a *LiveAdapter) Provider() providers.Provider { return providers.AlibabaCloud }

func (a *LiveAdapter) Capabilities() providers.Capabilities {
	return providers.Capabilities{
		Provider:             providers.AlibabaCloud,
		Domains:              true,
		Certificates:         true,
		CredentialGuidance:   "Use a RAM user or role with alidns:DescribeDomains, alidns:DescribeDomainInfo, and certificate list permissions such as yundun-cert:ListCert or yundun-cert:ListUserCertificateOrder; set access_key_id and access_key_secret.",
		SupportedSourceTypes: []string{"dns_zone", "certificate"},
	}
}

func (a *LiveAdapter) Test(ctx context.Context, credentials providers.Credentials) (providers.TestResult, error) {
	response, requestID, err := a.call(ctx, credentials, a.dnsEndpoint, "alidns", "2015-01-09", "DescribeDomains", map[string]string{"PageNumber": "1", "PageSize": "1"})
	if err != nil {
		return providers.TestResult{}, err
	}
	requestID = responseRequestID(response, requestID)
	return providers.TestResult{Provider: providers.AlibabaCloud, RequestID: requestID, Capabilities: a.Capabilities()}, nil
}

func (a *LiveAdapter) ListDomains(ctx context.Context, credentials providers.Credentials, cursor string) (providers.DomainPage, error) {
	page, err := parsePage(cursor)
	if err != nil {
		return providers.DomainPage{}, err
	}
	response, _, err := a.call(ctx, credentials, a.dnsEndpoint, "alidns", "2015-01-09", "DescribeDomains", map[string]string{"PageNumber": fmt.Sprintf("%d", page), "PageSize": "100"})
	if err != nil {
		return providers.DomainPage{}, err
	}
	var payload struct {
		TotalCount int `json:"TotalCount"`
		PageNumber int `json:"PageNumber"`
		PageSize   int `json:"PageSize"`
		Domains    struct {
			Domain []struct {
				DomainID   string   `json:"DomainId"`
				DomainName string   `json:"DomainName"`
				Status     string   `json:"DomainStatus"`
				NameServer []string `json:"NameServer"`
			} `json:"Domain"`
		} `json:"Domains"`
	}
	if err := json.Unmarshal(response, &payload); err != nil {
		return providers.DomainPage{}, fmt.Errorf("decode Alibaba DNS domains: %w", err)
	}
	items := make([]domain.Domain, 0, len(payload.Domains.Domain))
	for _, item := range payload.Domains.Domain {
		items = append(items, domain.Domain{SourceID: item.DomainID, Name: item.DomainName, RegistrableDomain: item.DomainName, Zone: item.DomainName, Status: item.Status, Nameservers: item.NameServer, SourceURL: "https://dns.console.aliyun.com/#/dns/domain/" + item.DomainName})
	}
	next := ""
	pageSize := payload.PageSize
	if pageSize == 0 {
		pageSize = 100
	}
	if page*pageSize < payload.TotalCount && len(items) > 0 {
		next = fmt.Sprintf("%d", page+1)
	}
	return providers.DomainPage{Items: items, NextCursor: next}, nil
}

func (a *LiveAdapter) ListCertificates(ctx context.Context, credentials providers.Credentials, cursor string) (providers.CertificatePage, error) {
	page, err := parsePage(cursor)
	if err != nil {
		return providers.CertificatePage{}, err
	}
	response, _, err := a.call(ctx, credentials, a.casEndpoint, "yundun-cert", "2020-06-30", "ListCert", map[string]string{"CurrentPage": fmt.Sprintf("%d", page), "ShowSize": "100"})
	if err != nil {
		return providers.CertificatePage{}, err
	}
	var payload struct {
		TotalCount      int `json:"TotalCount"`
		ShowSize        int `json:"ShowSize"`
		CertificateList []struct {
			CertificateID           string   `json:"CertificateId"`
			CertIdentifier          string   `json:"CertIdentifier"`
			CommonName              string   `json:"CommonName"`
			SubjectAlternativeNames []string `json:"SubjectAlternativeNames"`
			Issuer                  string   `json:"Issuer"`
			Serial                  string   `json:"Serial"`
			FingerPrint             string   `json:"FingerPrint"`
			Status                  string   `json:"Status"`
			NotBefore               int64    `json:"NotBefore"`
			NotAfter                int64    `json:"NotAfter"`
		} `json:"CertificateList"`
	}
	if err := json.Unmarshal(response, &payload); err != nil {
		return providers.CertificatePage{}, fmt.Errorf("decode Alibaba certificates: %w", err)
	}
	items := make([]domain.Certificate, 0, len(payload.CertificateList))
	for _, item := range payload.CertificateList {
		id := item.CertificateID
		if id == "" {
			id = item.CertIdentifier
		}
		items = append(items, domain.Certificate{SourceID: id, CommonName: item.CommonName, SANs: item.SubjectAlternativeNames, Issuer: item.Issuer, Status: item.Status, SerialNumber: item.Serial, Fingerprint: item.FingerPrint, ValidFrom: milliseconds(item.NotBefore), ValidTo: milliseconds(item.NotAfter), SourceURL: "https://yundun.console.aliyun.com/?p=cas#/certDetail/" + id})
	}
	pageSize := payload.ShowSize
	if pageSize == 0 {
		pageSize = 100
	}
	next := ""
	if page*pageSize < payload.TotalCount && len(items) > 0 {
		next = fmt.Sprintf("%d", page+1)
	}
	return providers.CertificatePage{Items: items, NextCursor: next}, nil
}

func (a *LiveAdapter) call(ctx context.Context, credentials providers.Credentials, endpoint, service, version, action string, values map[string]string) ([]byte, string, error) {
	accessKey := strings.TrimSpace(credentials.Values["access_key_id"])
	secret := strings.TrimSpace(credentials.Values["access_key_secret"])
	if accessKey == "" || secret == "" {
		return nil, "", errors.New("Alibaba access_key_id and access_key_secret are required")
	}
	params := map[string]string{"AccessKeyId": accessKey, "Action": action, "Format": "JSON", "SignatureMethod": "HMAC-SHA1", "SignatureNonce": fmt.Sprintf("%d", time.Now().UnixNano()), "SignatureVersion": "1.0", "Timestamp": time.Now().UTC().Format("2006-01-02T15:04:05Z"), "Version": version}
	for key, value := range values {
		params[key] = value
	}
	params["Signature"] = signature(http.MethodGet, params, secret)
	query := url.Values{}
	for key, value := range params {
		query.Set(key, value)
	}
	var lastErr error
	lastRequestID := ""
	lastStatus := 0
	for attempt := 1; attempt <= 3; attempt++ {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?"+query.Encode(), nil)
		if err != nil {
			return nil, "", err
		}
		response, requestErr := a.client.Do(request)
		if requestErr != nil {
			lastErr = requestErr
		} else {
			body, readErr := io.ReadAll(response.Body)
			requestID := response.Header.Get("x-acs-request-id")
			lastRequestID = requestID
			lastStatus = response.StatusCode
			_ = response.Body.Close()
			if readErr != nil {
				return nil, requestID, providers.NewAPIError(providers.AlibabaCloud, requestID, response.StatusCode, true, "response could not be read")
			}
			if response.StatusCode >= 200 && response.StatusCode < 300 {
				if code, ok := apiError(body); ok {
					return nil, requestID, providers.NewAPIError(providers.AlibabaCloud, requestID, http.StatusBadRequest, false, "API rejected the request: "+code)
				}
				return body, requestID, nil
			}
			lastErr = fmt.Errorf("Alibaba %s API returned HTTP %d", service, response.StatusCode)
			if response.StatusCode != http.StatusTooManyRequests && response.StatusCode < 500 {
				return nil, requestID, providers.NewAPIError(providers.AlibabaCloud, requestID, response.StatusCode, false, "API returned an error")
			}
		}
		if attempt < 3 {
			timer := time.NewTimer(time.Duration(attempt*100) * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, "", ctx.Err()
			case <-timer.C:
			}
		}
	}
	if lastErr == nil {
		lastErr = errors.New("request failed")
	}
	return nil, lastRequestID, providers.NewAPIError(providers.AlibabaCloud, lastRequestID, lastStatus, true, "request failed after bounded retries")
}

func signature(method string, params map[string]string, secret string) string {
	keys := make([]string, 0, len(params))
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	canonical := make([]string, 0, len(keys))
	for _, key := range keys {
		canonical = append(canonical, percentEncode(key)+"="+percentEncode(params[key]))
	}
	canonicalQuery := strings.Join(canonical, "&")
	stringToSign := method + "&%2F&" + percentEncode(canonicalQuery)
	mac := hmac.New(sha1.New, []byte(secret+"&"))
	_, _ = mac.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func percentEncode(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(url.QueryEscape(value), "+", "%20"), "%7E", "~"), "%2A", "*")
}

func responseRequestID(body []byte, fallback string) string {
	var payload struct {
		RequestID string `json:"RequestId"`
	}
	if json.Unmarshal(body, &payload) == nil && payload.RequestID != "" {
		return payload.RequestID
	}
	return fallback
}

func apiError(body []byte) (string, bool) {
	var payload struct {
		Code    string `json:"Code"`
		Message string `json:"Message"`
	}
	if json.Unmarshal(body, &payload) == nil && payload.Code != "" {
		return payload.Code, true
	}
	return "", false
}

func parsePage(cursor string) (int, error) {
	if cursor == "" {
		return 1, nil
	}
	var page int
	if _, err := fmt.Sscanf(cursor, "%d", &page); err != nil || page < 1 {
		return 0, errors.New("invalid Alibaba pagination cursor")
	}
	return page, nil
}

func milliseconds(value int64) time.Time {
	if value == 0 {
		return time.Time{}
	}
	return time.UnixMilli(value).UTC()
}
