package catalog

import (
	"testing"
	"time"

	"github.com/MamreTek/cert-harbor/internal/domain"
	"github.com/MamreTek/cert-harbor/internal/providers"
)

func BenchmarkListNormalizedAssets100k(b *testing.B) {
	store := NewStore()
	if err := store.AddConnection(Connection{ID: "benchmark", Name: "Benchmark", Provider: providers.Cloudflare, Enabled: true}); err != nil {
		b.Fatal(err)
	}
	now := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	domains := make([]domain.Domain, 100000)
	certificates := make([]domain.Certificate, 100000)
	for index := range domains {
		name := "asset-" + padBenchmarkIndex(index) + ".example.com"
		domains[index] = domain.Domain{ID: "domain-" + name, ConnectionID: "benchmark", Provider: string(providers.Cloudflare), Name: name, Owner: "platform", Environment: "production", LastSeenAt: now}
		certificates[index] = domain.Certificate{ID: "certificate-" + name, ConnectionID: "benchmark", Provider: string(providers.Cloudflare), CommonName: name, Owner: "platform", Environment: "production", ValidTo: now.Add(30 * 24 * time.Hour), LastSeenAt: now}
	}
	if err := store.ReplaceAssets("benchmark", now, domains, certificates); err != nil {
		b.Fatal(err)
	}

	b.Run("domains", func(b *testing.B) {
		b.ReportAllocs()
		for index := 0; index < b.N; index++ {
			items, total := store.ListDomains(Filter{Search: "asset-", Sort: "name", Page: 1, PageSize: 50})
			if total != 100000 || len(items) != 50 {
				b.Fatalf("domains total=%d items=%d", total, len(items))
			}
		}
	})
	b.Run("certificates", func(b *testing.B) {
		b.ReportAllocs()
		for index := 0; index < b.N; index++ {
			items, total := store.ListCertificates(Filter{Search: "asset-", Sort: "common_name", Page: 1, PageSize: 50})
			if total != 100000 || len(items) != 50 {
				b.Fatalf("certificates total=%d items=%d", total, len(items))
			}
		}
	})
}

func padBenchmarkIndex(index int) string {
	value := "000000" + formatBenchmarkIndex(index)
	return value[len(value)-6:]
}

func formatBenchmarkIndex(index int) string {
	if index == 0 {
		return "0"
	}
	result := make([]byte, 0, 6)
	for index > 0 {
		result = append([]byte{byte('0' + index%10)}, result...)
		index /= 10
	}
	return string(result)
}
