package tencent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MamreTek/cert-harbor/internal/providers"
)

func TestLiveAdapterMapsDNSPodAndSSLCertificates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" || !strings.HasPrefix(r.Header.Get("Authorization"), "TC3-HMAC-SHA256") {
			t.Fatalf("authorization header = %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-TC-RequestId", "request-test")
		switch r.Header.Get("X-TC-Action") {
		case "DescribeDomainList":
			_, _ = w.Write([]byte(`{"Response":{"DomainCountInfo":{"DomainTotal":1},"DomainList":[{"DomainId":123,"Name":"example.com","Status":"ENABLE","EffectiveDNS":["ns1.example.net"]}],"RequestId":"dns-request"}}`))
		case "DescribeCertificates":
			_, _ = w.Write([]byte(`{"Response":{"TotalCount":1,"Certificates":[{"CertificateId":"cert-1","Domain":"example.com","SubjectAltName":["example.com","www.example.com"],"CertificateType":"DV","Issuer":"Example CA","CertBeginTime":"2026-01-01 00:00:00","CertEndTime":"2026-10-01 00:00:00"}],"RequestId":"ssl-request"}}`))
		default:
			http.Error(w, "unknown action", http.StatusBadRequest)
		}
	}))
	defer server.Close()
	adapter := newLiveAdapter(server.URL, server.URL, server.Client())
	credentials := providers.Credentials{Values: map[string]string{"secret_id": "secret-id", "secret_key": "secret-key", "region": "ap-guangzhou"}}
	result, err := adapter.Test(context.Background(), credentials)
	if err != nil || result.RequestID != "dns-request" {
		t.Fatalf("test result = %#v, err = %v", result, err)
	}
	domains, err := adapter.ListDomains(context.Background(), credentials, "")
	if err != nil || len(domains.Items) != 1 || domains.Items[0].SourceID != "123" || domains.Items[0].Nameservers[0] != "ns1.example.net" {
		t.Fatalf("domains = %#v, err = %v", domains, err)
	}
	certificates, err := adapter.ListCertificates(context.Background(), credentials, "")
	if err != nil || len(certificates.Items) != 1 || certificates.Items[0].SourceID != "cert-1" || certificates.Items[0].Issuer != "Example CA" || certificates.Items[0].CertificateType != "DV" || len(certificates.Items[0].LinkedDomains) != 2 || certificates.Items[0].ValidTo.IsZero() {
		t.Fatalf("certificates = %#v, err = %v", certificates, err)
	}
}
