package alerts

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	AssetTypes            []string `json:"asset_types,omitempty"`
	Providers             []string `json:"providers,omitempty"`
	Owners                []string `json:"owners,omitempty"`
	Environments          []string `json:"environments,omitempty"`
	Tags                  []string `json:"tags,omitempty"`
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
	SourceURL     string     `json:"source_url,omitempty"`
	Freshness     string     `json:"freshness,omitempty"`
	DeepLink      string     `json:"deep_link"`
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
	mu       sync.RWMutex
	catalog  *catalog.Store
	rules    map[string]Rule
	alerts   map[string]Alert
	events   []Event
	filePath string
	backend  catalog.StateBackend
	now      func() time.Time
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

// OpenEngine restores alert rules, states, and transition events from an
// atomically written snapshot. An absent path or file starts with defaults.
func OpenEngine(store *catalog.Store, path string, backends ...catalog.StateBackend) (*Engine, error) {
	engine := NewEngine(store)
	engine.filePath = path
	if len(backends) > 0 {
		engine.backend = backends[0]
	}
	var data []byte
	migratedFromFile := false
	if engine.backend != nil {
		loaded, err := engine.backend.LoadState("alerts")
		if err != nil {
			return nil, err
		}
		data = loaded
		if len(data) == 0 && path != "" {
			legacyData, legacyErr := os.ReadFile(path)
			if legacyErr == nil && len(legacyData) > 0 {
				data = legacyData
				migratedFromFile = true
			} else if legacyErr != nil && !errors.Is(legacyErr, os.ErrNotExist) {
				return nil, legacyErr
			}
		}
	} else if path != "" {
		loaded, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			return engine, nil
		}
		if err != nil {
			return nil, err
		}
		data = loaded
	}
	if len(data) == 0 {
		return engine, nil
	}
	var snapshot struct {
		Version int              `json:"version"`
		Rules   map[string]Rule  `json:"rules"`
		Alerts  map[string]Alert `json:"alerts"`
		Events  []Event          `json:"events"`
	}
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return nil, err
	}
	for id, rule := range snapshot.Rules {
		engine.rules[id] = rule
	}
	if snapshot.Alerts != nil {
		engine.alerts = snapshot.Alerts
		for id, alert := range engine.alerts {
			if alert.DeepLink == "" {
				alert.DeepLink = "/alerts/" + id
			}
			if alert.Freshness == "" {
				alert.Freshness = "unknown"
			}
			engine.alerts[id] = alert
		}
	}
	engine.events = snapshot.Events
	if migratedFromFile {
		if err := engine.persistLocked(); err != nil {
			return nil, fmt.Errorf("migrate legacy alert state: %w", err)
		}
	}
	return engine, nil
}

func (e *Engine) Evaluate() []Alert {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	eventStart := len(e.events)
	for _, rule := range e.rules {
		if !rule.Enabled {
			continue
		}
		domains := e.catalog.ListAllDomains()
		for _, item := range domains {
			evaluateDomain(e, rule, item, now)
		}
		certificates := e.catalog.ListAllCertificates()
		for _, item := range certificates {
			evaluateCertificate(e, rule, item, now)
		}
		for _, connection := range e.catalog.ListConnections() {
			if !matchesRule(rule, "connection", string(connection.Provider), "", "", nil) {
				continue
			}
			missedInitialSync := connection.LastSyncAt == nil && connection.NextSyncAt != nil && now.After(*connection.NextSyncAt)
			if connection.Status == "unhealthy" || missedInitialSync || (connection.LastSyncAt != nil && now.Sub(*connection.LastSyncAt) > time.Duration(rule.StaleAfterHours)*time.Hour) {
				id := rule.ID + ":" + connection.ID + ":sync-stale"
				e.upsertAlert(Alert{ID: id, RuleID: rule.ID, AssetID: connection.ID, AssetKind: "connection", AssetName: connection.Name, Provider: string(connection.Provider), State: StateOpen, Severity: "high", Freshness: "stale", UpdatedAt: now})
			} else {
				e.resolveByAsset(rule.ID, connection.ID, "connection", now)
			}
		}
	}
	_ = e.persistLocked()
	e.auditEvaluationEvents(e.events[eventStart:], now)
	return e.listAlertsLocked()
}

func (e *Engine) auditEvaluationEvents(events []Event, now time.Time) {
	if len(events) == 0 {
		return
	}
	correlationID := "monitor-" + now.Format("20060102T150405.000000000Z")
	for _, event := range events {
		_ = e.catalog.AppendAudit(catalog.AuditEvent{
			Actor:         event.Actor,
			Action:        "alert." + event.ToState,
			ObjectType:    "alert",
			ObjectID:      event.AlertID,
			Outcome:       "succeeded",
			CorrelationID: correlationID,
			CreatedAt:     event.CreatedAt,
		})
	}
}

func (e *Engine) Rules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	items := make([]Rule, 0, len(e.rules))
	for _, rule := range e.rules {
		items = append(items, rule)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Name == items[j].Name {
			return items[i].ID < items[j].ID
		}
		return items[i].Name < items[j].Name
	})
	return items
}

func (e *Engine) GetRule(id string) (Rule, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	rule, ok := e.rules[id]
	return rule, ok
}

func (e *Engine) AddRule(rule Rule) error {
	if err := validateRule(rule); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, exists := e.rules[rule.ID]; exists {
		return errors.New("alert rule already exists")
	}
	rule = normalizeRule(rule)
	e.rules[rule.ID] = rule
	return e.persistLocked()
}

func (e *Engine) UpdateRule(rule Rule) (Rule, error) {
	if err := validateRule(rule); err != nil {
		return Rule{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, exists := e.rules[rule.ID]; !exists {
		return Rule{}, errors.New("alert rule not found")
	}
	rule = normalizeRule(rule)
	e.rules[rule.ID] = rule
	if err := e.persistLocked(); err != nil {
		return Rule{}, err
	}
	return rule, nil
}

func (e *Engine) DeleteRule(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if id == "default" {
		return errors.New("the default alert rule cannot be deleted")
	}
	if _, exists := e.rules[id]; !exists {
		return errors.New("alert rule not found")
	}
	delete(e.rules, id)
	for alertID, alert := range e.alerts {
		if alert.RuleID == id {
			delete(e.alerts, alertID)
		}
	}
	return e.persistLocked()
}

func (e *Engine) Alerts() []Alert {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.listAlertsLocked()
}

func (e *Engine) ListAlerts(page, pageSize int, state, provider string) ([]Alert, int) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	items := make([]Alert, 0, len(e.alerts))
	for _, alert := range e.alerts {
		if state != "" && !strings.EqualFold(alert.State, state) {
			continue
		}
		if provider != "" && !strings.EqualFold(alert.Provider, provider) {
			continue
		}
		items = append(items, alert)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].UpdatedAt.Equal(items[j].UpdatedAt) {
			return items[i].ID < items[j].ID
		}
		return items[i].UpdatedAt.After(items[j].UpdatedAt)
	})
	total := len(items)
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 200 {
		pageSize = 50
	}
	start := (page - 1) * pageSize
	if start >= total {
		return []Alert{}, total
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	return items[start:end], total
}

func (e *Engine) Get(id string) (Alert, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	alert, ok := e.alerts[id]
	return alert, ok
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
	if err := e.persistLocked(); err != nil {
		return Alert{}, err
	}
	return alert, nil
}

func (e *Engine) persistLocked() error {
	snapshot := struct {
		Version int              `json:"version"`
		Rules   map[string]Rule  `json:"rules"`
		Alerts  map[string]Alert `json:"alerts"`
		Events  []Event          `json:"events"`
	}{Version: 1, Rules: e.rules, Alerts: e.alerts, Events: e.events}
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	if e.backend != nil {
		return e.backend.SaveState("alerts", data)
	}
	if e.filePath == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(e.filePath), 0o700); err != nil {
		return err
	}
	temporary := e.filePath + ".tmp"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(temporary, e.filePath); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

func (e *Engine) upsertAlert(alert Alert) {
	if alert.DeepLink == "" {
		alert.DeepLink = "/alerts/" + alert.ID
	}
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
	} else {
		e.events = append(e.events, Event{ID: fmt.Sprintf("event-%d", len(e.events)+1), AlertID: alert.ID, ToState: alert.State, Actor: "system", CreatedAt: alert.UpdatedAt})
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
	sort.Slice(items, func(i, j int) bool {
		if items[i].UpdatedAt.Equal(items[j].UpdatedAt) {
			return items[i].ID < items[j].ID
		}
		return items[i].UpdatedAt.After(items[j].UpdatedAt)
	})
	return items
}

func evaluateDomain(e *Engine, rule Rule, item domain.Domain, now time.Time) {
	if !matchesRule(rule, "domain", item.Provider, item.Owner, item.Environment, item.Tags) {
		return
	}
	state, severity, days := expiryState(item.ExpiresAt, item.Stale, rule.DomainThresholds, now)
	if state == "healthy" {
		e.resolveByAsset(rule.ID, item.ID, "domain", now)
		return
	}
	e.closeOtherStates(rule.ID, item.ID, "domain", state, now)
	e.upsertAlert(Alert{ID: rule.ID + ":" + item.ID + ":" + state, RuleID: rule.ID, AssetID: item.ID, AssetKind: "domain", AssetName: item.Name, Provider: item.Provider, State: StateOpen, Severity: severity, DaysRemaining: days, ExpiresAt: item.ExpiresAt, SourceURL: item.SourceURL, Freshness: assetFreshness(item.Stale), UpdatedAt: now})
}

func evaluateCertificate(e *Engine, rule Rule, item domain.Certificate, now time.Time) {
	if !matchesRule(rule, "certificate", item.Provider, item.Owner, item.Environment, item.Tags) {
		return
	}
	expiresAt := item.ValidTo
	state, severity, days := expiryState(&expiresAt, item.Stale, rule.CertificateThresholds, now)
	if certificateState, certificateSeverity := certificateStatusState(item.Status); certificateState != "" {
		state = certificateState
		severity = certificateSeverity
	}
	if state == "healthy" {
		e.resolveByAsset(rule.ID, item.ID, "certificate", now)
		return
	}
	e.closeOtherStates(rule.ID, item.ID, "certificate", state, now)
	e.upsertAlert(Alert{ID: rule.ID + ":" + item.ID + ":" + state, RuleID: rule.ID, AssetID: item.ID, AssetKind: "certificate", AssetName: item.CommonName, Provider: item.Provider, State: StateOpen, Severity: severity, DaysRemaining: days, ExpiresAt: &expiresAt, SourceURL: item.SourceURL, Freshness: assetFreshness(item.Stale), UpdatedAt: now})
}

func assetFreshness(stale bool) string {
	if stale {
		return "stale"
	}
	return "current"
}

func certificateStatusState(status string) (string, string) {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "revoked":
		return "revoked", "critical"
	case "failed", "validation_failed", "invalid", "inactive":
		return "invalid", "critical"
	default:
		return "", ""
	}
}

func expiryState(expiresAt *time.Time, stale bool, thresholds []int, now time.Time) (string, string, *int) {
	if stale {
		return "stale", "high", nil
	}
	if expiresAt == nil || expiresAt.IsZero() {
		return "unknown", "high", nil
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

func matchesRule(rule Rule, assetType, provider, owner, environment string, tags []string) bool {
	return matches(rule.AssetTypes, assetType) && matches(rule.Providers, provider) && matches(rule.Owners, owner) && matches(rule.Environments, environment) && matchesAny(rule.Tags, tags)
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

func matchesAny(wanted, values []string) bool {
	if len(wanted) == 0 {
		return true
	}
	for _, candidate := range wanted {
		for _, value := range values {
			if strings.EqualFold(candidate, value) {
				return true
			}
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

func validateRule(rule Rule) error {
	if rule.ID == "" || rule.Name == "" {
		return errors.New("alert rule id and name are required")
	}
	if len(rule.DomainThresholds) == 0 || len(rule.CertificateThresholds) == 0 {
		return errors.New("domain and certificate thresholds are required")
	}
	if rule.StaleAfterHours <= 0 {
		return errors.New("stale_after_hours must be greater than zero")
	}
	for _, threshold := range append(append([]int{}, rule.DomainThresholds...), rule.CertificateThresholds...) {
		if threshold < 0 {
			return errors.New("thresholds cannot be negative")
		}
	}
	for _, assetType := range rule.AssetTypes {
		switch strings.ToLower(strings.TrimSpace(assetType)) {
		case "domain", "certificate", "connection":
		default:
			return fmt.Errorf("unsupported asset type %q", assetType)
		}
	}
	return nil
}

func normalizeRule(rule Rule) Rule {
	rule.DomainThresholds = uniqueSorted(rule.DomainThresholds)
	rule.CertificateThresholds = uniqueSorted(rule.CertificateThresholds)
	return rule
}

func uniqueSorted(values []int) []int {
	items := append([]int(nil), values...)
	sort.Ints(items)
	result := make([]int, 0, len(items))
	for _, item := range items {
		if len(result) == 0 || result[len(result)-1] != item {
			result = append(result, item)
		}
	}
	return result
}
