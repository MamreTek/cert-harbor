package alerts

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MamreTek/cert-harbor/internal/catalog"
	"github.com/MamreTek/cert-harbor/internal/domain"
	"github.com/MamreTek/cert-harbor/internal/providers"
)

type memoryStateBackend struct {
	mu     sync.Mutex
	values map[string][]byte
}

func (b *memoryStateBackend) LoadState(key string) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.values[key]...), nil
}

func (b *memoryStateBackend) SaveState(key string, payload []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.values == nil {
		b.values = make(map[string][]byte)
	}
	b.values[key] = append([]byte(nil), payload...)
	return nil
}

func TestEvaluateCreatesStableExpiringAlertAndTransitions(t *testing.T) {
	store := catalog.NewStore()
	if err := store.AddConnection(catalog.Connection{ID: "connection", Name: "Connection", Provider: providers.Cloudflare, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	expires := now.Add(11 * 24 * time.Hour)
	store.ReplaceAssets("connection", now, nil, []domain.Certificate{{
		ID: "connection:certificate:cert", ConnectionID: "connection", Provider: string(providers.Cloudflare), SourceID: "cert", CommonName: "example.com", ValidTo: expires, LastSeenAt: now,
	}})
	engine := NewEngine(store)
	engine.now = func() time.Time { return now }
	alerts := engine.Evaluate()
	if len(alerts) != 1 || alerts[0].State != StateOpen || alerts[0].DaysRemaining == nil || *alerts[0].DaysRemaining != 11 {
		t.Fatalf("unexpected alerts: %#v", alerts)
	}
	engine.Evaluate()
	if len(engine.Alerts()) != 1 {
		t.Fatalf("repeated evaluation created duplicates: %#v", engine.Alerts())
	}
	if _, err := engine.Transition(alerts[0].ID, StateAcknowledged, "admin", "tracking"); err != nil {
		t.Fatal(err)
	}
	if len(engine.Events()) != 1 || engine.Alerts()[0].State != StateAcknowledged {
		t.Fatalf("missing acknowledgement event: %#v %#v", engine.Alerts(), engine.Events())
	}
}

func TestOpenEngineRestoresAlertStateAndEvents(t *testing.T) {
	store := catalog.NewStore()
	if err := store.AddConnection(catalog.Connection{ID: "connection", Name: "Connection", Provider: providers.Cloudflare, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "alerts", "state.json")
	engine, err := OpenEngine(store, path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	engine.now = func() time.Time { return now }
	store.ReplaceAssets("connection", now, nil, []domain.Certificate{{
		ID: "connection:certificate:cert", ConnectionID: "connection", Provider: string(providers.Cloudflare), CommonName: "example.com", ValidTo: now.Add(11 * 24 * time.Hour), LastSeenAt: now,
	}})
	items := engine.Evaluate()
	if len(items) != 1 {
		t.Fatalf("expected one persisted alert, got %#v", items)
	}
	if _, err := engine.Transition(items[0].ID, StateAcknowledged, "admin", "note"); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenEngine(store, path)
	if err != nil {
		t.Fatal(err)
	}
	if len(reopened.Rules()) != 1 || len(reopened.Alerts()) != 1 || reopened.Alerts()[0].State != StateAcknowledged || len(reopened.Events()) != 1 {
		t.Fatalf("unexpected restored state: rules=%#v alerts=%#v events=%#v", reopened.Rules(), reopened.Alerts(), reopened.Events())
	}
}

func TestOpenEngineUsesSharedStateBackend(t *testing.T) {
	store := catalog.NewStore()
	backend := &memoryStateBackend{}
	engine, err := OpenEngine(store, "", backend)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.AddRule(Rule{ID: "backend-rule", Name: "Backend rule", Enabled: true, DomainThresholds: []int{30}, CertificateThresholds: []int{30}, StaleAfterHours: 24}); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenEngine(store, "", backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.GetRule("backend-rule"); !ok {
		t.Fatalf("shared backend did not restore alert rule: %#v", reopened.Rules())
	}
}

func TestEvaluatePreservesHistoricalAlertWhenAssetBecomesHealthy(t *testing.T) {
	store := catalog.NewStore()
	if err := store.AddConnection(catalog.Connection{ID: "connection", Name: "Connection", Provider: providers.Cloudflare, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	expires := now.Add(11 * 24 * time.Hour)
	certificate := domain.Certificate{ID: "connection:certificate:cert", ConnectionID: "connection", Provider: string(providers.Cloudflare), CommonName: "example.com", ValidTo: expires, LastSeenAt: now}
	store.ReplaceAssets("connection", now, nil, []domain.Certificate{certificate})
	engine := NewEngine(store)
	engine.now = func() time.Time { return now }
	engine.Evaluate()
	certificate.ValidTo = now.Add(180 * 24 * time.Hour)
	store.ReplaceAssets("connection", now, nil, []domain.Certificate{certificate})
	engine.Evaluate()
	if len(engine.Alerts()) != 1 || engine.Alerts()[0].State != StateResolved {
		t.Fatalf("expected historical alert to resolve: %#v", engine.Alerts())
	}
}

func TestEvaluateCreatesInvalidCertificateAlertFromProviderStatus(t *testing.T) {
	store := catalog.NewStore()
	if err := store.AddConnection(catalog.Connection{ID: "connection", Name: "Connection", Provider: providers.Cloudflare, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	store.ReplaceAssets("connection", now, nil, []domain.Certificate{{ID: "certificate", ConnectionID: "connection", Provider: string(providers.Cloudflare), CommonName: "example.com", Status: "REVOKED", ValidTo: now.Add(180 * 24 * time.Hour), LastSeenAt: now}})
	engine := NewEngine(store)
	engine.now = func() time.Time { return now }
	items := engine.Evaluate()
	if len(items) != 1 || items[0].State != StateOpen || !strings.Contains(items[0].ID, ":revoked") || items[0].Severity != "critical" {
		t.Fatalf("revoked certificate alert = %#v", items)
	}
}

func TestListAlertsPaginatesAndFilters(t *testing.T) {
	store := catalog.NewStore()
	if err := store.AddConnection(catalog.Connection{ID: "connection", Name: "Connection", Provider: providers.Cloudflare, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	certificates := make([]domain.Certificate, 0, 3)
	for index := 0; index < 3; index++ {
		certificates = append(certificates, domain.Certificate{ID: "certificate-" + string(rune('a'+index)), ConnectionID: "connection", Provider: string(providers.Cloudflare), CommonName: "example-" + string(rune('a'+index)) + ".com", ValidTo: now.Add(3 * 24 * time.Hour), LastSeenAt: now})
	}
	if err := store.ReplaceAssets("connection", now, nil, certificates); err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(store)
	engine.now = func() time.Time { return now }
	engine.Evaluate()
	items, total := engine.ListAlerts(1, 2, StateOpen, "cloudflare")
	if total != 3 || len(items) != 2 {
		t.Fatalf("paged alerts = total %d items %#v", total, items)
	}
	items, total = engine.ListAlerts(2, 2, StateOpen, "cloudflare")
	if total != 3 || len(items) != 1 {
		t.Fatalf("second alert page = total %d items %#v", total, items)
	}
}

func TestAlertRuleCRUDNormalizesThresholdsAndProtectsDefault(t *testing.T) {
	engine := NewEngine(catalog.NewStore())
	if err := engine.AddRule(Rule{ID: "team", Name: "Team policy", Enabled: true, DomainThresholds: []int{30, 90, 30}, CertificateThresholds: []int{14, 3}, StaleAfterHours: 12}); err != nil {
		t.Fatal(err)
	}
	rule, ok := engine.GetRule("team")
	if !ok || len(rule.DomainThresholds) != 2 || rule.DomainThresholds[0] != 30 || rule.DomainThresholds[1] != 90 {
		t.Fatalf("normalized rule = %#v", rule)
	}
	if err := engine.DeleteRule("default"); err == nil {
		t.Fatal("expected default rule deletion to fail")
	}
	if err := engine.DeleteRule("team"); err != nil {
		t.Fatal(err)
	}
}

func TestEvaluateAppliesTagScopeAcrossTheFullCatalog(t *testing.T) {
	store := catalog.NewStore()
	if err := store.AddConnection(catalog.Connection{ID: "connection", Name: "Connection", Provider: providers.Cloudflare, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	certificates := make([]domain.Certificate, 0, 205)
	for index := 0; index < 205; index++ {
		certificate := domain.Certificate{
			ID:           "connection:certificate:cert-" + string(rune('a'+index)),
			ConnectionID: "connection",
			Provider:     string(providers.Cloudflare),
			SourceID:     "cert-" + string(rune('a'+index)),
			CommonName:   "example-" + string(rune('a'+index)) + ".com",
			ValidTo:      now.Add(3 * 24 * time.Hour),
			LastSeenAt:   now,
			Tags:         []string{"production"},
		}
		if index == 204 {
			certificate.Tags = []string{"staging"}
		}
		certificates = append(certificates, certificate)
	}
	if err := store.ReplaceAssets("connection", now, nil, certificates); err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(store)
	engine.now = func() time.Time { return now }
	if err := engine.AddRule(Rule{ID: "staging", Name: "Staging only", Enabled: true, DomainThresholds: []int{30}, CertificateThresholds: []int{30}, StaleAfterHours: 24, Tags: []string{"staging"}}); err != nil {
		t.Fatal(err)
	}
	items := engine.Evaluate()
	matching := 0
	for _, item := range items {
		if item.RuleID == "staging" {
			matching++
		}
	}
	if matching != 1 {
		t.Fatalf("tag-scoped full-catalog alerts = %d, want 1; alerts=%#v", matching, items)
	}
}
