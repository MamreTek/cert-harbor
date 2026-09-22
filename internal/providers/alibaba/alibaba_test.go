package alibaba

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MamreTek/cert-harbor/internal/providers"
)

func TestLiveAdapterMapsAliDNSAndCertificates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("Signature") == "" || r.URL.Query().Get("AccessKeyId") != "access-key" {
			t.Fatalf("missing or unsafe Alibaba signature query: %s", r.URL.RawQuery)
		}
		w.Header().Set("x-acs-request-id", "request-header")
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("Action") {
		case "DescribeDomains":
			_, _ = w.Write([]byte(`{"RequestId":"dns-request","TotalCount":1,"PageNumber":1,"PageSize":100,"Domains":{"Domain":[{"DomainId":"domain-1","DomainName":"example.com","DomainStatus":"Enable","NameServer":["ns1.example.net"]}]}}`))
		case "ListCert":
			_, _ = w.Write([]byte(`{"RequestId":"cert-request","TotalCount":1,"ShowSize":100,"CertificateList":[{"CertificateId":"cert-1","CommonName":"example.com","SubjectAlternativeNames":["example.com","www.example.com"],"CertType":"DV","Issuer":"Example CA","Serial":"123","FingerPrint":"fingerprint","NotBefore":1767225600000,"NotAfter":1790812800000}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	adapter := newLiveAdapter(server.URL, server.URL, server.Client())
	credentials := providers.Credentials{Values: map[string]string{"access_key_id": "access-key", "access_key_secret": "access-secret"}}
	result, err := adapter.Test(context.Background(), credentials)
	if err != nil || result.RequestID != "dns-request" {
		t.Fatalf("test result = %#v, err = %v", result, err)
	}
	domains, err := adapter.ListDomains(context.Background(), credentials, "")
	if err != nil || len(domains.Items) != 1 || domains.Items[0].SourceID != "domain-1" || domains.Items[0].Nameservers[0] != "ns1.example.net" {
		t.Fatalf("domains = %#v, err = %v", domains, err)
	}
	certificates, err := adapter.ListCertificates(context.Background(), credentials, "")
	if err != nil || len(certificates.Items) != 1 || certificates.Items[0].SourceID != "cert-1" || certificates.Items[0].Issuer != "Example CA" || certificates.Items[0].Fingerprint != "fingerprint" || certificates.Items[0].CertificateType != "DV" || len(certificates.Items[0].LinkedDomains) != 2 || certificates.Items[0].ValidTo.IsZero() {
		t.Fatalf("certificates = %#v, err = %v", certificates, err)
	}
	if strings.Contains(certificates.Items[0].SourceURL, "access-secret") {
		t.Fatal("certificate source URL exposed a credential")
	}
}
