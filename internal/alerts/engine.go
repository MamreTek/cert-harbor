package alerts

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/MamreTek/cert-harbor/internal/catalog"
	"github.com/MamreTek/cert-harbor/internal/domain"
)

const (
	StateOpen         = "open"
	StateAcknowledged = "acknowledged"
	StateResolved     = "resolved"
	StateSuppressed   = "suppressed"
)

type Rule struct {
	ID                    string   `json:"id"`
	Name                  string   `json:"name"`
	Enabled               bool     `json:"enabled"`
	DomainThresholds      []int    `json:"domain_thresholds"`
	CertificateThresholds []int    `json:"certificate_thresholds"`
	StaleAfterHours       int      `json:"stale_after_hours"`
	Providers             []string `json:"providers,omitempty"`
	Owners                []string `json:"owners,omitempty"`
	Environments          []string `json:"environments,omitempty"`
}

type Alert struct {
	ID            string     `json:"id"`
	RuleID        string     `json:"rule_id"`
	AssetID       string     `json:"asset_id"`
	AssetKind     string     `json:"asset_kind"`
	AssetName     string     `json:"asset_name"`
	Provider      string     `json:"provider"`
	State         string     `json:"state"`
	Severity      string     `json:"severity"`
	DaysRemaining *int       `json:"days_remaining,omitempty"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	UpdatedAt     time.Time  `json:"updated_at"`
	Actor         string     `json:"actor,omitempty"`
	Note          string     `json:"note,omitempty"`
}

type Event struct {
	ID        string    `json:"id"`
	AlertID   string    `json:"alert_id"`
	FromState string    `json:"from_state,omitempty"`
	ToState   string    `json:"to_state"`
	Actor     string    `json:"actor"`
	Note      string    `json:"note,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type Engine struct {
	mu      sync.RWMutex
	catalog *catalog.Store
	rules   map[string]Rule
	alerts  map[string]Alert
	events  []Event
	now     func() time.Time
}

func NewEngine(store *catalog.Store) *Engine {
	engine := &Engine{
		catalog: store,
		rules:   make(map[string]Rule),
		alerts:  make(map[string]Alert),
		now:     func() time.Time { return time.Now().UTC() },
	}
	engine.rules["default"] = Rule{
		ID:                    "default",
		Name:                  "Default expiry policy",
		Enabled:               true,
		DomainThresholds:      []int{90, 30, 14, 7, 3},
		CertificateThresholds: []int{90, 30, 14, 7, 3},
		StaleAfterHours:       26,
	}
	return engine
}

func (e *Engine) Evaluate() []Alert {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	for _, rule := range e.rules {
		if !rule.Enabled {
			continue
		}
		domains, _ := e.catalog.ListDomains(catalog.Filter{Page: 1, PageSize: 200})
		for _, item := range domains {
			evaluateDomain(e, rule, item, now)
		}
		certificates, _ := e.catalog.ListCertificates(catalog.Filter{Page: 1, PageSize: 200})
		for _, item := range certificates {
			evaluateCertificate(e, rule, item, now)
		}
		for _, connection := range e.catalog.ListConnections() {
			if connection.Status == "unhealthy" || (connection.LastSyncAt != nil && now.Sub(*connection.LastSyncAt) > time.Duration(rule.StaleAfterHours)*time.Hour) {
				id := rule.ID + ":" + connection.ID + ":sync-stale"
				e.upsertAlert(Alert{ID: id, RuleID: rule.ID, AssetID: connection.ID, AssetKind: "connection", AssetName: connection.Name, Provider: string(connection.Provider), State: StateOpen, Severity: "high", UpdatedAt: now})
			} else {
				e.resolveByAsset(rule.ID, connection.ID, "connection", now)
			}
		}
	}
	return e.listAlertsLocked()
}

func (e *Engine) Rules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	items := make([]Rule, 0, len(e.rules))
	for _, rule := range e.rules {
		items = append(items, rule)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	return items
}

func (e *Engine) Alerts() []Alert {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.listAlertsLocked()
}

func (e *Engine) Events() []Event {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]Event(nil), e.events...)
}

func (e *Engine) Transition(id, state, actor, note string) (Alert, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	alert, ok := e.alerts[id]
	if !ok {
		return Alert{}, errors.New("alert not found")
	}
	if !validTransition(alert.State, state) {
		return Alert{}, fmt.Errorf("cannot transition alert from %s to %s", alert.State, state)
	}
	now := e.now()
	e.events = append(e.events, Event{ID: fmt.Sprintf("event-%d", len(e.events)+1), AlertID: id, FromState: alert.State, ToState: state, Actor: actor, Note: note, CreatedAt: now})
	alert.State = state
	alert.Actor = actor
	alert.Note = note
	alert.UpdatedAt = now
	e.alerts[id] = alert
	return alert, nil
}

func (e *Engine) upsertAlert(alert Alert) {
	if existing, ok := e.alerts[alert.ID]; ok {
		if existing.State == StateSuppressed {
			return
		}
		if existing.State == StateResolved {
			e.events = append(e.events, Event{ID: fmt.Sprintf("event-%d", len(e.events)+1), AlertID: alert.ID, FromState: StateResolved, ToState: StateOpen, Actor: "system", CreatedAt: alert.UpdatedAt})
			e.alerts[alert.ID] = alert
			return
		}
		alert.State = existing.State
		alert.Actor = existing.Actor
		alert.Note = existing.Note
	}
	e.alerts[alert.ID] = alert
}

func (e *Engine) closeOtherStates(ruleID, assetID, kind, currentState string, now time.Time) {
	for id, alert := range e.alerts {
		if alert.RuleID != ruleID || alert.AssetID != assetID || alert.AssetKind != kind || strings.HasSuffix(id, ":"+currentState) || alert.State == StateResolved {
			continue
		}
		fromState := alert.State
		alert.State = StateResolved
		alert.UpdatedAt = now
		e.alerts[id] = alert
		e.events = append(e.events, Event{ID: fmt.Sprintf("event-%d", len(e.events)+1), AlertID: id, FromState: fromState, ToState: StateResolved, Actor: "system", CreatedAt: now})
	}
}

func (e *Engine) resolveByAsset(ruleID, assetID, kind string, now time.Time) {
	for id, alert := range e.alerts {
		if alert.RuleID == ruleID && alert.AssetID == assetID && alert.AssetKind == kind && alert.State != StateResolved {
			fromState := alert.State
			alert.State = StateResolved
			alert.UpdatedAt = now
			e.alerts[id] = alert
			e.events = append(e.events, Event{ID: fmt.Sprintf("event-%d", len(e.events)+1), AlertID: id, FromState: fromState, ToState: StateResolved, Actor: "system", CreatedAt: now})
		}
	}
}

func (e *Engine) listAlertsLocked() []Alert {
	items := make([]Alert, 0, len(e.alerts))
	for _, alert := range e.alerts {
		items = append(items, alert)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].UpdatedAt.After(items[j].UpdatedAt) })
	return items
}

func evaluateDomain(e *Engine, rule Rule, item domain.Domain, now time.Time) {
	if !matchesRule(rule, item.Provider, item.Owner, item.Environment) {
		return
	}
	state, severity, days := expiryState(item.ExpiresAt, item.Stale, rule.DomainThresholds, now)
	if state == "healthy" {
		e.resolveByAsset(rule.ID, item.ID, "domain", now)
		return
	}
	e.closeOtherStates(rule.ID, item.ID, "domain", state, now)
	e.upsertAlert(Alert{ID: rule.ID + ":" + item.ID + ":" + state, RuleID: rule.ID, AssetID: item.ID, AssetKind: "domain", AssetName: item.Name, Provider: item.Provider, State: StateOpen, Severity: severity, DaysRemaining: days, ExpiresAt: item.ExpiresAt, UpdatedAt: now})
}

func evaluateCertificate(e *Engine, rule Rule, item domain.Certificate, now time.Time) {
	if !matchesRule(rule, item.Provider, item.Owner, item.Environment) {
		return
	}
	expiresAt := item.ValidTo
	state, severity, days := expiryState(&expiresAt, item.Stale, rule.CertificateThresholds, now)
	if state == "healthy" {
		e.resolveByAsset(rule.ID, item.ID, "certificate", now)
		return
	}
	e.closeOtherStates(rule.ID, item.ID, "certificate", state, now)
	e.upsertAlert(Alert{ID: rule.ID + ":" + item.ID + ":" + state, RuleID: rule.ID, AssetID: item.ID, AssetKind: "certificate", AssetName: item.CommonName, Provider: item.Provider, State: StateOpen, Severity: severity, DaysRemaining: days, ExpiresAt: &expiresAt, UpdatedAt: now})
}

func expiryState(expiresAt *time.Time, stale bool, thresholds []int, now time.Time) (string, string, *int) {
	if stale {
		return "stale", "high", nil
	}
	if expiresAt == nil {
		return "healthy", "", nil
	}
	days := int(expiresAt.Sub(now) / (24 * time.Hour))
	if expiresAt.Before(now) {
		return "expired", "critical", &days
	}
	for _, threshold := range thresholds {
		if days <= threshold {
			return "expiring", severityForDays(days), &days
		}
	}
	return "healthy", "", &days
}

func severityForDays(days int) string {
	switch {
	case days <= 7:
		return "high"
	case days <= 30:
		return "medium"
	default:
		return "low"
	}
}

func matchesRule(rule Rule, provider, owner, environment string) bool {
	return matches(rule.Providers, provider) && matches(rule.Owners, owner) && matches(rule.Environments, environment)
}

func matches(values []string, value string) bool {
	if len(values) == 0 {
		return true
	}
	for _, candidate := range values {
		if strings.EqualFold(candidate, value) {
			return true
		}
	}
	return false
}

func validTransition(from, to string) bool {
	if from == to {
		return true
	}
	switch to {
	case StateAcknowledged:
		return from == StateOpen
	case StateResolved:
		return from == StateOpen || from == StateAcknowledged || from == StateSuppressed
	case StateSuppressed:
		return from == StateOpen || from == StateAcknowledged
	case StateOpen:
		return from == StateResolved || from == StateSuppressed
	default:
		return false
	}
}
