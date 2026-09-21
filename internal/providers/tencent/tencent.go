package tencent

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/MamreTek/cert-harbor/internal/domain"
	"github.com/MamreTek/cert-harbor/internal/providers"
)

func New(fixturePath string) providers.Adapter {
	capabilities := providers.Capabilities{
		Provider:             providers.Tencent,
		Domains:              true,
		Certificates:         true,
		CredentialGuidance:   "Fixture mode needs no credential. Live mode uses a CAM user or role with read-only DNSPod DescribeDomainList/DescribeDomain and SSL DescribeCertificates/DescribeCertificate permissions; set secret_id and secret_key.",
		SupportedSourceTypes: []string{"dns_zone", "certificate"},
	}
	fixture := providers.NewFixtureAdapter(providers.Tencent, fixturePath, capabilities)
	return providers.NewCredentialSwitchAdapter(fixture, NewLiveAdapter())
}

type LiveAdapter struct {
	dnsEndpoint string
	sslEndpoint string
	client      *http.Client
}

func NewLiveAdapter() providers.Adapter {
	return &LiveAdapter{dnsEndpoint: "https://dnspod.tencentcloudapi.com", sslEndpoint: "https://ssl.tencentcloudapi.com", client: &http.Client{Timeout: 15 * time.Second}}
}

func newLiveAdapter(dnsEndpoint, sslEndpoint string, client *http.Client) *LiveAdapter {
	return &LiveAdapter{dnsEndpoint: strings.TrimRight(dnsEndpoint, "/"), sslEndpoint: strings.TrimRight(sslEndpoint, "/"), client: client}
}

func (a *LiveAdapter) Provider() providers.Provider { return providers.Tencent }

func (a *LiveAdapter) Capabilities() providers.Capabilities {
	return providers.Capabilities{
		Provider:             providers.Tencent,
		Domains:              true,
		Certificates:         true,
		CredentialGuidance:   "Use a CAM user or role with read-only DNSPod DescribeDomainList/DescribeDomain and SSL DescribeCertificates/DescribeCertificate permissions; set secret_id and secret_key.",
		SupportedSourceTypes: []string{"dns_zone", "certificate"},
	}
}

func (a *LiveAdapter) Test(ctx context.Context, credentials providers.Credentials) (providers.TestResult, error) {
	response, requestID, err := a.call(ctx, credentials, a.dnsEndpoint, "dnspod", "DescribeDomainList", map[string]any{"Type": "ALL", "Offset": 0, "Limit": 1})
	if err != nil {
		return providers.TestResult{}, err
	}
	var envelope struct {
		Response struct {
			RequestID string `json:"RequestId"`
		} `json:"Response"`
	}
	if json.Unmarshal(response, &envelope) == nil && envelope.Response.RequestID != "" {
		requestID = envelope.Response.RequestID
	}
	return providers.TestResult{Provider: providers.Tencent, RequestID: requestID, Capabilities: a.Capabilities()}, nil
}

func (a *LiveAdapter) ListDomains(ctx context.Context, credentials providers.Credentials, cursor string) (providers.DomainPage, error) {
	offset := 0
	if cursor != "" {
		parsed, err := parseOffset(cursor)
		if err != nil {
			return providers.DomainPage{}, err
		}
		offset = parsed
	}
	response, _, err := a.call(ctx, credentials, a.dnsEndpoint, "dnspod", "DescribeDomainList", map[string]any{"Type": "ALL", "Offset": offset, "Limit": 100})
	if err != nil {
		return providers.DomainPage{}, err
	}
	var payload struct {
		Response struct {
			DomainCountInfo struct {
				AllTotal    int `json:"AllTotal"`
				DomainTotal int `json:"DomainTotal"`
			} `json:"DomainCountInfo"`
			DomainList []struct {
				DomainID     int      `json:"DomainId"`
				Name         string   `json:"Name"`
				Status       string   `json:"Status"`
				EffectiveDNS []string `json:"EffectiveDNS"`
			} `json:"DomainList"`
		} `json:"Response"`
	}
	if err := json.Unmarshal(response, &payload); err != nil {
		return providers.DomainPage{}, fmt.Errorf("decode Tencent DNSPod domains: %w", err)
	}
	items := make([]domain.Domain, 0, len(payload.Response.DomainList))
	for _, item := range payload.Response.DomainList {
		items = append(items, domain.Domain{SourceID: fmt.Sprintf("%d", item.DomainID), Name: item.Name, RegistrableDomain: item.Name, Zone: item.Name, Status: item.Status, Nameservers: item.EffectiveDNS, SourceURL: "https://console.cloud.tencent.com/dnspod/domain/record.html?domain=" + item.Name})
	}
	total := payload.Response.DomainCountInfo.DomainTotal
	if total == 0 {
		total = payload.Response.DomainCountInfo.AllTotal
	}
	next := ""
	if offset+len(items) < total && len(items) > 0 {
		next = fmt.Sprintf("%d", offset+len(items))
	}
	return providers.DomainPage{Items: items, NextCursor: next}, nil
}

func (a *LiveAdapter) ListCertificates(ctx context.Context, credentials providers.Credentials, cursor string) (providers.CertificatePage, error) {
	offset := 0
	if cursor != "" {
		parsed, err := parseOffset(cursor)
		if err != nil {
			return providers.CertificatePage{}, err
		}
		offset = parsed
	}
	response, _, err := a.call(ctx, credentials, a.sslEndpoint, "ssl", "DescribeCertificates", map[string]any{"Offset": offset, "Limit": 100})
	if err != nil {
		return providers.CertificatePage{}, err
	}
	var payload struct {
		Response struct {
			TotalCount   int `json:"TotalCount"`
			Certificates []struct {
				CertificateID  string   `json:"CertificateId"`
				CertID         string   `json:"CertId"`
				Domain         string   `json:"Domain"`
				SubjectAltName []string `json:"SubjectAltName"`
				Issuer         string   `json:"Issuer"`
				CertBeginTime  string   `json:"CertBeginTime"`
				CertEndTime    string   `json:"CertEndTime"`
				SerialNumber   string   `json:"SerialNumber"`
				Fingerprint    string   `json:"Fingerprint"`
				Status         string   `json:"Status"`
			} `json:"Certificates"`
		} `json:"Response"`
	}
	if err := json.Unmarshal(response, &payload); err != nil {
		return providers.CertificatePage{}, fmt.Errorf("decode Tencent SSL certificates: %w", err)
	}
	items := make([]domain.Certificate, 0, len(payload.Response.Certificates))
	for _, item := range payload.Response.Certificates {
		id := item.CertificateID
		if id == "" {
			id = item.CertID
		}
		validFrom, _ := parseTencentTime(item.CertBeginTime)
		validTo, _ := parseTencentTime(item.CertEndTime)
		items = append(items, domain.Certificate{SourceID: id, CommonName: item.Domain, SANs: item.SubjectAltName, Issuer: item.Issuer, Status: item.Status, SerialNumber: item.SerialNumber, Fingerprint: item.Fingerprint, ValidFrom: validFrom, ValidTo: validTo, SourceURL: "https://console.cloud.tencent.com/ssl"})
	}
	next := ""
	if offset+len(items) < payload.Response.TotalCount && len(items) > 0 {
		next = fmt.Sprintf("%d", offset+len(items))
	}
	return providers.CertificatePage{Items: items, NextCursor: next}, nil
}

func (a *LiveAdapter) call(ctx context.Context, credentials providers.Credentials, endpoint, service, action string, payload map[string]any) ([]byte, string, error) {
	secretID := strings.TrimSpace(credentials.Values["secret_id"])
	secretKey := strings.TrimSpace(credentials.Values["secret_key"])
	if secretID == "" || secretKey == "" {
		return nil, "", errors.New("Tencent secret_id and secret_key are required")
	}
	region := strings.TrimSpace(credentials.Values["region"])
	if region == "" {
		region = "ap-guangzhou"
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, "", err
	}
	var lastErr error
	lastRequestID := ""
	lastStatus := 0
	for attempt := 1; attempt <= 3; attempt++ {
		request, requestErr := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
		if requestErr != nil {
			return nil, "", requestErr
		}
		request.Header.Set("Content-Type", "application/json; charset=utf-8")
		request.Header.Set("X-TC-Action", action)
		request.Header.Set("X-TC-Version", map[string]string{"dnspod": "2021-03-23", "ssl": "2019-12-05"}[service])
		timestamp := time.Now().Unix()
		signTC3(request, body, secretID, secretKey, region, service, action, timestamp)
		response, doErr := a.client.Do(request)
		if doErr != nil {
			lastErr = doErr
		} else {
			responseBody, readErr := io.ReadAll(response.Body)
			requestID := response.Header.Get("X-TC-RequestId")
			lastRequestID = requestID
			lastStatus = response.StatusCode
			_ = response.Body.Close()
			if readErr != nil {
				return nil, requestID, providers.NewAPIError(providers.Tencent, requestID, response.StatusCode, true, "response could not be read")
			}
			if response.StatusCode >= 200 && response.StatusCode < 300 {
				var envelope struct {
					Response struct {
						Error *struct {
							Code    string `json:"Code"`
							Message string `json:"Message"`
						} `json:"Error"`
						RequestID string `json:"RequestId"`
					} `json:"Response"`
				}
				if json.Unmarshal(responseBody, &envelope) == nil {
					if envelope.Response.RequestID != "" {
						requestID = envelope.Response.RequestID
					}
					if envelope.Response.Error != nil {
						return nil, requestID, providers.NewAPIError(providers.Tencent, requestID, http.StatusBadRequest, false, "API rejected the request")
					}
				}
				return responseBody, requestID, nil
			}
			lastErr = fmt.Errorf("Tencent %s API returned HTTP %d", service, response.StatusCode)
			if response.StatusCode != http.StatusTooManyRequests && response.StatusCode < 500 {
				return nil, requestID, providers.NewAPIError(providers.Tencent, requestID, response.StatusCode, false, "API returned an error")
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
	return nil, lastRequestID, providers.NewAPIError(providers.Tencent, lastRequestID, lastStatus, true, "request failed after bounded retries")
}

func signTC3(request *http.Request, body []byte, secretID, secretKey, region, service, action string, timestamp int64) {
	contentType := "application/json; charset=utf-8"
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("Host", request.URL.Host)
	request.Header.Set("X-TC-Timestamp", fmt.Sprintf("%d", timestamp))
	payloadHash := sha256Hex(body)
	canonicalHeaders := "content-type:" + contentType + "\nhost:" + request.URL.Host + "\nx-tc-action:" + action + "\n"
	signedHeaders := "content-type;host;x-tc-action"
	canonicalRequest := strings.Join([]string{http.MethodPost, "/", "", canonicalHeaders, signedHeaders, payloadHash}, "\n")
	date := time.Unix(timestamp, 0).UTC().Format("2006-01-02")
	scope := date + "/" + service + "/tc3_request"
	stringToSign := "TC3-HMAC-SHA256\n" + fmt.Sprintf("%d", timestamp) + "\n" + scope + "\n" + sha256Hex([]byte(canonicalRequest))
	kDate := hmacSHA256([]byte("TC3"+secretKey), date)
	kService := hmacSHA256(kDate, service)
	kSigning := hmacSHA256(kService, "tc3_request")
	signature := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))
	request.Header.Set("Authorization", "TC3-HMAC-SHA256 Credential="+secretID+"/"+scope+", SignedHeaders="+signedHeaders+", Signature="+signature)
}

func hmacSHA256(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func parseOffset(cursor string) (int, error) {
	var offset int
	if _, err := fmt.Sscanf(cursor, "%d", &offset); err != nil || offset < 0 {
		return 0, errors.New("invalid Tencent pagination cursor")
	}
	return offset, nil
}

func parseTencentTime(value string) (time.Time, error) {
	return time.ParseInLocation("2006-01-02 15:04:05", value, time.UTC)
}
