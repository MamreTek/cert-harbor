package aws

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MamreTek/cert-harbor/internal/providers"
)

func TestLiveAdapterMapsRoute53AndACM(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" || !strings.Contains(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256") {
			t.Fatalf("authorization header = %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("x-amzn-requestid", "request-test")
		if r.URL.Path == "/2013-04-01/hostedzone" {
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(`<ListHostedZonesResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><HostedZone><Id>/hostedzone/Z123</Id><Name>example.com.</Name><Config><PrivateZone>false</PrivateZone></Config></HostedZone><IsTruncated>false</IsTruncated></ListHostedZonesResponse>`))
			return
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		switch r.Header.Get("X-Amz-Target") {
		case "CertificateManager.ListCertificates":
			_, _ = w.Write([]byte(`{"CertificateSummaryList":[{"CertificateArn":"arn:aws:acm:us-east-1:123:certificate/abc","DomainName":"example.com"}],"NextToken":""}`))
		case "CertificateManager.DescribeCertificate":
			_, _ = w.Write([]byte(`{"Certificate":{"DomainName":"example.com","SubjectAlternativeNames":["example.com","www.example.com"],"Issuer":"Example CA","Serial":"123","NotBefore":"2026-01-01T00:00:00Z","NotAfter":"2026-10-01T00:00:00Z"}}`))
		default:
			http.Error(w, "unknown target", http.StatusBadRequest)
		}
	}))
	defer server.Close()
	adapter := newLiveAdapter(server.URL, server.URL, server.Client())
	credentials := providers.Credentials{Values: map[string]string{"access_key_id": "AKID", "secret_access_key": "secret", "region": "us-east-1"}}
	result, err := adapter.Test(context.Background(), credentials)
	if err != nil || result.RequestID != "request-test" {
		t.Fatalf("test result = %#v, err = %v", result, err)
	}
	domains, err := adapter.ListDomains(context.Background(), credentials, "")
	if err != nil || len(domains.Items) != 1 || domains.Items[0].SourceID != "Z123" || domains.Items[0].Name != "example.com" {
		t.Fatalf("domains = %#v, err = %v", domains, err)
	}
	certificates, err := adapter.ListCertificates(context.Background(), credentials, "")
	if err != nil || len(certificates.Items) != 1 || certificates.Items[0].Region != "us-east-1" || certificates.Items[0].Issuer != "Example CA" || certificates.Items[0].ValidTo.IsZero() {
		t.Fatalf("certificates = %#v, err = %v", certificates, err)
	}
}
