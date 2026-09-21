package aws

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
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
		Provider:             providers.AWS,
		Domains:              true,
		Certificates:         true,
		CredentialGuidance:   "Fixture mode needs no credential. Live mode uses an IAM role or user with route53:ListHostedZones, route53:GetHostedZone, acm:ListCertificates, acm:DescribeCertificate, and acm:ListTagsForCertificate; set region for ACM.",
		SupportedSourceTypes: []string{"hosted_zone", "acm_certificate"},
	}
	fixture := providers.NewFixtureAdapter(providers.AWS, fixturePath, capabilities)
	return providers.NewCredentialSwitchAdapter(fixture, NewLiveAdapter())
}

type LiveAdapter struct {
	route53URL string
	acmURL     string
	client     *http.Client
}

func NewLiveAdapter() providers.Adapter {
	return &LiveAdapter{route53URL: "https://route53.amazonaws.com", client: &http.Client{Timeout: 15 * time.Second}}
}

func newLiveAdapter(route53URL, acmURL string, client *http.Client) *LiveAdapter {
	return &LiveAdapter{route53URL: strings.TrimRight(route53URL, "/"), acmURL: strings.TrimRight(acmURL, "/"), client: client}
}

func (a *LiveAdapter) Provider() providers.Provider { return providers.AWS }

func (a *LiveAdapter) Capabilities() providers.Capabilities {
	return providers.Capabilities{
		Provider:             providers.AWS,
		Domains:              true,
		Certificates:         true,
		CredentialGuidance:   "Use an IAM role or user with route53:ListHostedZones, route53:GetHostedZone, acm:ListCertificates, acm:DescribeCertificate, and acm:ListTagsForCertificate; set region for ACM.",
		SupportedSourceTypes: []string{"hosted_zone", "acm_certificate"},
	}
}

func (a *LiveAdapter) Test(ctx context.Context, credentials providers.Credentials) (providers.TestResult, error) {
	_, requestID, err := a.listHostedZones(ctx, credentials, "", 1)
	if err != nil {
		return providers.TestResult{}, err
	}
	return providers.TestResult{Provider: providers.AWS, RequestID: requestID, Capabilities: a.Capabilities()}, nil
}

func (a *LiveAdapter) ListDomains(ctx context.Context, credentials providers.Credentials, cursor string) (providers.DomainPage, error) {
	zones, _, err := a.listHostedZones(ctx, credentials, cursor, 100)
	if err != nil {
		return providers.DomainPage{}, err
	}
	items := make([]domain.Domain, 0, len(zones.Items))
	for _, zone := range zones.Items {
		name := strings.TrimSuffix(zone.Name, ".")
		zoneID := strings.TrimPrefix(zone.ID, "/hostedzone/")
		status := "public"
		if zone.Private {
			status = "private"
		}
		items = append(items, domain.Domain{SourceID: zoneID, Name: name, RegistrableDomain: name, Zone: name, Status: status, SourceURL: "https://console.aws.amazon.com/route53/v2/hostedzones#ListRecordSets/" + zoneID})
	}
	return providers.DomainPage{Items: items, NextCursor: zones.NextMarker}, nil
}

func (a *LiveAdapter) ListCertificates(ctx context.Context, credentials providers.Credentials, cursor string) (providers.CertificatePage, error) {
	region := strings.TrimSpace(credentials.Values["region"])
	if region == "" {
		region = "us-east-1"
	}
	acmURL := a.acmURL
	if acmURL == "" {
		acmURL = "https://acm." + region + ".amazonaws.com"
	}
	body := map[string]any{"MaxItems": 100}
	if cursor != "" {
		body["NextToken"] = cursor
	}
	response, _, err := a.acmRequest(ctx, credentials, region, acmURL, "ListCertificates", body)
	if err != nil {
		return providers.CertificatePage{}, err
	}
	var listed struct {
		CertificateSummaryList []struct {
			CertificateArn          string   `json:"CertificateArn"`
			DomainName              string   `json:"DomainName"`
			SubjectAlternativeNames []string `json:"SubjectAlternativeNameSummaries"`
		} `json:"CertificateSummaryList"`
		NextToken string `json:"NextToken"`
	}
	if err := json.Unmarshal(response, &listed); err != nil {
		return providers.CertificatePage{}, fmt.Errorf("decode AWS ACM certificate list: %w", err)
	}
	items := make([]domain.Certificate, 0, len(listed.CertificateSummaryList))
	for _, summary := range listed.CertificateSummaryList {
		detail, _, detailErr := a.acmRequest(ctx, credentials, region, acmURL, "DescribeCertificate", map[string]any{"CertificateArn": summary.CertificateArn})
		if detailErr != nil {
			return providers.CertificatePage{}, detailErr
		}
		var described struct {
			Certificate struct {
				DomainName              string    `json:"DomainName"`
				SubjectAlternativeNames []string  `json:"SubjectAlternativeNames"`
				Issuer                  string    `json:"Issuer"`
				Status                  string    `json:"Status"`
				Serial                  string    `json:"Serial"`
				NotBefore               time.Time `json:"NotBefore"`
				NotAfter                time.Time `json:"NotAfter"`
			} `json:"Certificate"`
		}
		if err := json.Unmarshal(detail, &described); err != nil {
			return providers.CertificatePage{}, fmt.Errorf("decode AWS ACM certificate: %w", err)
		}
		certificate := described.Certificate
		commonName := certificate.DomainName
		if commonName == "" {
			commonName = summary.DomainName
		}
		sans := certificate.SubjectAlternativeNames
		if len(sans) == 0 {
			sans = summary.SubjectAlternativeNames
		}
		items = append(items, domain.Certificate{SourceID: summary.CertificateArn, CommonName: commonName, SANs: sans, Issuer: certificate.Issuer, Status: certificate.Status, SerialNumber: certificate.Serial, ValidFrom: certificate.NotBefore, ValidTo: certificate.NotAfter, Region: region, SourceURL: "https://" + region + ".console.aws.amazon.com/acm/home?region=" + url.QueryEscape(region) + "#/certificates/" + url.PathEscape(summary.CertificateArn)})
	}
	return providers.CertificatePage{Items: items, NextCursor: listed.NextToken}, nil
}

type hostedZonePage struct {
	Items []struct {
		ID      string `xml:"Id"`
		Name    string `xml:"Name"`
		Private bool   `xml:"Config>PrivateZone"`
	} `xml:"HostedZone"`
	NextMarker string `xml:"NextMarker"`
}

func (a *LiveAdapter) listHostedZones(ctx context.Context, credentials providers.Credentials, cursor string, maxItems int) (hostedZonePage, string, error) {
	query := url.Values{"maxitems": {fmt.Sprintf("%d", maxItems)}}
	if cursor != "" {
		query.Set("marker", cursor)
	}
	response, requestID, err := a.awsRequest(ctx, credentials, "route53", "us-east-1", http.MethodGet, a.route53URL+"/2013-04-01/hostedzone?"+query.Encode(), nil, "")
	if err != nil {
		return hostedZonePage{}, requestID, err
	}
	var payload hostedZonePage
	if err := xml.Unmarshal(response, &payload); err != nil {
		return hostedZonePage{}, requestID, fmt.Errorf("decode AWS Route 53 zones: %w", err)
	}
	return payload, requestID, nil
}

func (a *LiveAdapter) acmRequest(ctx context.Context, credentials providers.Credentials, region, endpoint, target string, payload map[string]any) ([]byte, string, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, "", err
	}
	return a.awsRequest(ctx, credentials, "acm", region, http.MethodPost, endpoint+"/", body, "CertificateManager."+target)
}

func (a *LiveAdapter) awsRequest(ctx context.Context, credentials providers.Credentials, service, region, method, endpoint string, body []byte, target string) ([]byte, string, error) {
	accessKey := strings.TrimSpace(credentials.Values["access_key_id"])
	secretKey := strings.TrimSpace(credentials.Values["secret_access_key"])
	if accessKey == "" || secretKey == "" {
		return nil, "", errors.New("AWS access_key_id and secret_access_key are required")
	}
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		request, err := http.NewRequestWithContext(ctx, method, endpoint, strings.NewReader(string(body)))
		if err != nil {
			return nil, "", err
		}
		if target != "" {
			request.Header.Set("X-Amz-Target", target)
			request.Header.Set("Content-Type", "application/x-amz-json-1.1")
		}
		request.Header.Set("Accept", "application/json")
		if service == "route53" {
			request.Header.Set("Accept", "application/xml")
		}
		signAWSRequest(request, body, accessKey, secretKey, credentials.Values["session_token"], service, region, time.Now().UTC())
		response, requestErr := a.client.Do(request)
		if requestErr != nil {
			lastErr = requestErr
		} else {
			responseBody, readErr := io.ReadAll(response.Body)
			requestID := response.Header.Get("x-amzn-requestid")
			_ = response.Body.Close()
			if readErr != nil {
				return nil, requestID, fmt.Errorf("read AWS response: %w", readErr)
			}
			if response.StatusCode >= 200 && response.StatusCode < 300 {
				return responseBody, requestID, nil
			}
			lastErr = fmt.Errorf("AWS %s API returned HTTP %d", service, response.StatusCode)
			if response.StatusCode != http.StatusTooManyRequests && response.StatusCode < 500 {
				return nil, requestID, lastErr
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
	return nil, "", lastErr
}

func signAWSRequest(request *http.Request, body []byte, accessKey, secretKey, sessionToken, service, region string, now time.Time) {
	amzDate := now.Format("20060102T150405Z")
	date := now.Format("20060102")
	payloadHash := sha256Hex(body)
	request.Header.Set("Host", request.URL.Host)
	request.Header.Set("X-Amz-Date", amzDate)
	request.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if sessionToken != "" {
		request.Header.Set("X-Amz-Security-Token", sessionToken)
	}
	canonicalHeaders := map[string]string{"host": request.URL.Host, "x-amz-content-sha256": payloadHash, "x-amz-date": amzDate}
	if sessionToken != "" {
		canonicalHeaders["x-amz-security-token"] = sessionToken
	}
	names := make([]string, 0, len(canonicalHeaders))
	for name := range canonicalHeaders {
		names = append(names, name)
	}
	sort.Strings(names)
	var headerBuilder strings.Builder
	for _, name := range names {
		headerBuilder.WriteString(name)
		headerBuilder.WriteByte(':')
		headerBuilder.WriteString(strings.TrimSpace(canonicalHeaders[name]))
		headerBuilder.WriteByte('\n')
	}
	signedHeaders := strings.Join(names, ";")
	canonicalRequest := strings.Join([]string{request.Method, request.URL.EscapedPath(), request.URL.Query().Encode(), headerBuilder.String(), signedHeaders, payloadHash}, "\n")
	scope := date + "/" + region + "/" + service + "/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + sha256Hex([]byte(canonicalRequest))
	kDate := hmacSHA256([]byte("AWS4"+secretKey), date)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))
	request.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+accessKey+"/"+scope+", SignedHeaders="+signedHeaders+", Signature="+signature)
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
