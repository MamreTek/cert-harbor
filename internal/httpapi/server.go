package httpapi

import (
	"crypto/subtle"
	"encoding/csv"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	alerting "github.com/MamreTek/cert-harbor/internal/alerts"
	"github.com/MamreTek/cert-harbor/internal/catalog"
	"github.com/MamreTek/cert-harbor/internal/config"
	"github.com/MamreTek/cert-harbor/internal/domain"
	observability "github.com/MamreTek/cert-harbor/internal/metrics"
	"github.com/MamreTek/cert-harbor/internal/notifications"
	"github.com/MamreTek/cert-harbor/internal/providers"
	"github.com/MamreTek/cert-harbor/internal/providers/registry"
	"github.com/MamreTek/cert-harbor/internal/security"
	"github.com/MamreTek/cert-harbor/internal/syncer"
)

type Server struct {
	config        config.Config
	store         *catalog.Store
	syncer        *syncer.Service
	alerts        *alerting.Engine
	secrets       *security.SecretBox
	notifications *notifications.Service
	metrics       *observability.Metrics
	logger        *slog.Logger
	mux           *http.ServeMux
}

type Dependencies struct {
	Store         *catalog.Store
	Syncer        *syncer.Service
	Alerts        *alerting.Engine
	Secrets       *security.SecretBox
	Notifications *notifications.Service
	Metrics       *observability.Metrics
	Logger        *slog.Logger
}

type role string

const (
	roleAdmin  role = "administrator"
	roleViewer role = "viewer"
)

func NewServer(cfg config.Config, dependencies ...Dependencies) *Server {
	deps := Dependencies{}
	if len(dependencies) > 0 {
		deps = dependencies[0]
	}
	if deps.Store == nil {
		deps.Store = catalog.NewStore()
	}
	if deps.Syncer == nil {
		deps.Syncer = syncer.New(deps.Store, registry.New(cfg.FixturePath))
	}
	if deps.Alerts == nil {
		deps.Alerts = alerting.NewEngine(deps.Store)
	}
	if deps.Secrets == nil && cfg.EncryptionKey != "" {
		deps.Secrets, _ = security.NewSecretBox(cfg.EncryptionKey)
	}
	if deps.Notifications == nil {
		deps.Notifications = notifications.NewService(deps.Secrets)
	}
	if deps.Metrics == nil {
		deps.Metrics = observability.New()
	}
	deps.Syncer.SetMetrics(deps.Metrics)
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	s := &Server{config: cfg, store: deps.Store, syncer: deps.Syncer, alerts: deps.Alerts, secrets: deps.Secrets, notifications: deps.Notifications, metrics: deps.Metrics, logger: deps.Logger, mux: http.NewServeMux()}
	s.mux.HandleFunc("GET /healthz", s.health)
	s.mux.HandleFunc("GET /readyz", s.ready)
	s.mux.HandleFunc("GET /metrics", s.metricsEndpoint)
	s.mux.HandleFunc("GET /api/v1/meta", s.meta)
	s.mux.HandleFunc("GET /api/v1/workspace", s.workspace)
	s.mux.HandleFunc("GET /api/v1/members", s.members)
	s.mux.HandleFunc("POST /api/v1/members", s.createMember)
	s.mux.HandleFunc("PATCH /api/v1/members/{id}", s.updateMember)
	s.mux.HandleFunc("DELETE /api/v1/members/{id}", s.deleteMember)
	s.mux.HandleFunc("GET /api/v1/catalog/summary", s.summary)
	s.mux.HandleFunc("GET /api/v1/provider-connections", s.connections)
	s.mux.HandleFunc("POST /api/v1/provider-connections", s.createConnection)
	s.mux.HandleFunc("PATCH /api/v1/provider-connections/{id}", s.updateConnection)
	s.mux.HandleFunc("DELETE /api/v1/provider-connections/{id}", s.deleteConnection)
	s.mux.HandleFunc("POST /api/v1/provider-connections/{id}/test", s.testConnection)
	s.mux.HandleFunc("POST /api/v1/provider-connections/{id}/sync", s.syncConnection)
	s.mux.HandleFunc("GET /api/v1/domains", s.domains)
	s.mux.HandleFunc("GET /api/v1/domains/{id}", s.domainDetail)
	s.mux.HandleFunc("GET /api/v1/certificates", s.certificates)
	s.mux.HandleFunc("GET /api/v1/certificates/{id}", s.certificateDetail)
	s.mux.HandleFunc("GET /api/v1/export/domains.csv", s.exportDomains)
	s.mux.HandleFunc("GET /api/v1/export/certificates.csv", s.exportCertificates)
	s.mux.HandleFunc("GET /api/v1/sync-runs", s.syncRuns)
	s.mux.HandleFunc("GET /api/v1/sync-runs/{id}", s.syncRunDetail)
	s.mux.HandleFunc("GET /api/v1/audit-events", s.auditEvents)
	s.mux.HandleFunc("GET /api/v1/alerts", s.alertList)
	s.mux.HandleFunc("GET /api/v1/alerts/{id}", s.alertDetail)
	s.mux.HandleFunc("GET /api/v1/alert-rules", s.alertRules)
	s.mux.HandleFunc("POST /api/v1/alert-rules", s.createAlertRule)
	s.mux.HandleFunc("PATCH /api/v1/alert-rules/{id}", s.updateAlertRule)
	s.mux.HandleFunc("DELETE /api/v1/alert-rules/{id}", s.deleteAlertRule)
	s.mux.HandleFunc("GET /api/v1/alert-events", s.alertEvents)
	s.mux.HandleFunc("POST /api/v1/monitor/evaluate", s.evaluateAlerts)
	s.mux.HandleFunc("POST /api/v1/alerts/{id}/acknowledge", s.acknowledgeAlert)
	s.mux.HandleFunc("POST /api/v1/alerts/{id}/resolve", s.resolveAlert)
	s.mux.HandleFunc("POST /api/v1/alerts/{id}/suppress", s.suppressAlert)
	s.mux.HandleFunc("POST /api/v1/alerts/{id}/notify", s.notifyAlert)
	s.mux.HandleFunc("GET /api/v1/notification-channels", s.notificationChannels)
	s.mux.HandleFunc("POST /api/v1/notification-channels", s.createNotificationChannel)
	s.mux.HandleFunc("PATCH /api/v1/notification-channels/{id}", s.updateNotificationChannel)
	s.mux.HandleFunc("DELETE /api/v1/notification-channels/{id}", s.deleteNotificationChannel)
	s.mux.HandleFunc("POST /api/v1/notification-channels/{id}/test", s.testNotificationChannel)
	s.mux.HandleFunc("GET /api/v1/notification-deliveries", s.notificationDeliveries)
	s.mux.HandleFunc("/", s.web)
	return s
}

func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		defer func() {
			s.logger.Info("http_request", "method", r.Method, "path", r.URL.Path, "request_id", r.Header.Get("X-Request-ID"), "duration_ms", time.Since(started).Milliseconds())
		}()
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" || r.URL.Path == "/metrics" || r.URL.Path == "/api/v1/meta" || !strings.HasPrefix(r.URL.Path, "/api/") {
			s.mux.ServeHTTP(w, r)
			return
		}
		requestRole, ok := s.authenticate(r)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
			return
		}
		if r.Method != http.MethodGet && requestRole != roleAdmin {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "administrator role required"})
			return
		}
		s.mux.ServeHTTP(w, r)
	})
}

func (s *Server) authenticate(r *http.Request) (role, bool) {
	if s.config.AdminToken == "" && s.config.ViewerToken == "" && !strings.EqualFold(s.config.Env, "production") {
		return roleAdmin, true
	}
	token := strings.TrimSpace(r.Header.Get("X-CertHarbor-Token"))
	if token == "" {
		const prefix = "Bearer "
		if strings.HasPrefix(r.Header.Get("Authorization"), prefix) {
			token = strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), prefix))
		}
	}
	if token == "" {
		return "", false
	}
	if equalSecret(token, s.config.AdminToken) {
		return roleAdmin, true
	}
	if equalSecret(token, s.config.ViewerToken) {
		return roleViewer, true
	}
	return "", false
}

func equalSecret(candidate, expected string) bool {
	if candidate == "" || expected == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(candidate), []byte(expected)) == 1
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) ready(w http.ResponseWriter, _ *http.Request) {
	if err := s.config.Validate(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not_ready", "error": err.Error()})
		return
	}
	if err := s.store.Ready(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not_ready", "error": "persistence dependency is unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) metricsEndpoint(w http.ResponseWriter, _ *http.Request) {
	summary := s.store.Summary()
	openAlerts := countOpenAlerts(s.alerts.Alerts())
	staleConnections := 0
	for _, connection := range s.store.ListConnections() {
		if connection.Status == "unhealthy" {
			staleConnections++
		}
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = w.Write([]byte(s.metrics.Render(summary, openAlerts, staleConnections)))
}

func (s *Server) meta(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"name":    "CertHarbor",
		"version": "0.2.0",
		"env":     s.config.Env,
	})
}

func (s *Server) workspace(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.store.Workspace())
}

func (s *Server) members(w http.ResponseWriter, r *http.Request) {
	allItems := s.store.ListMembers()
	pageNumber, pageLimit := page(r), pageSize(r)
	writeJSON(w, http.StatusOK, map[string]any{"items": pageItems(allItems, pageNumber, pageLimit), "total": len(allItems), "page": pageNumber, "page_size": pageLimit})
}

type memberRequest struct {
	ID     string `json:"id"`
	Email  string `json:"email"`
	Name   string `json:"name"`
	Role   string `json:"role"`
	Status string `json:"status"`
}

func (s *Server) createMember(w http.ResponseWriter, r *http.Request) {
	var request memberRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid member request"})
		return
	}
	if request.ID == "" {
		request.ID = slug(request.Email)
	}
	if request.Role == "" {
		request.Role = "viewer"
	}
	member := catalog.Member{ID: request.ID, Email: request.Email, Name: request.Name, Role: request.Role, Status: request.Status}
	if err := s.store.AddMember(member); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := s.audit(r, "member.invite", "member", request.ID, "succeeded"); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "member invited but audit event could not be recorded"})
		return
	}
	created, _ := findMember(s.store.ListMembers(), request.ID)
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) updateMember(w http.ResponseWriter, r *http.Request) {
	var request memberRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid member request"})
		return
	}
	member, err := s.store.UpdateMember(r.PathValue("id"), request.Name, request.Role, request.Status)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}
	if err := s.audit(r, "member.update", "member", member.ID, "succeeded"); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "member updated but audit event could not be recorded"})
		return
	}
	writeJSON(w, http.StatusOK, member)
}

func (s *Server) deleteMember(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteMember(r.PathValue("id")); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}
	if err := s.audit(r, "member.remove", "member", r.PathValue("id"), "succeeded"); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "member removed but audit event could not be recorded"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) summary(w http.ResponseWriter, _ *http.Request) {
	summary := s.store.Summary()
	summary["open_alerts"] = countOpenAlerts(s.alerts.Alerts())
	writeJSON(w, http.StatusOK, summary)
}

func countOpenAlerts(items []alerting.Alert) int {
	count := 0
	for _, item := range items {
		if item.State == alerting.StateOpen || item.State == alerting.StateAcknowledged {
			count++
		}
	}
	return count
}

func (s *Server) connections(w http.ResponseWriter, r *http.Request) {
	allItems := s.store.ListConnections()
	pageNumber, pageLimit := page(r), pageSize(r)
	writeJSON(w, http.StatusOK, map[string]any{"items": pageItems(allItems, pageNumber, pageLimit), "total": len(allItems), "page": pageNumber, "page_size": pageLimit})
}

type connectionRequest struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Provider     string            `json:"provider"`
	Enabled      *bool             `json:"enabled"`
	SyncInterval string            `json:"sync_interval"`
	Credentials  map[string]string `json:"credentials"`
}

func (s *Server) createConnection(w http.ResponseWriter, r *http.Request) {
	var request connectionRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid connection request"})
		return
	}
	provider := providers.Provider(request.Provider)
	if request.ID == "" {
		request.ID = slug(request.Name)
	}
	if !providers.Supported(provider) || request.ID == "" || request.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id, name, and a supported provider are required"})
		return
	}
	enabled := true
	if request.Enabled != nil {
		enabled = *request.Enabled
	}
	adapter := registry.New(s.config.FixturePath)[provider]
	connection := catalog.Connection{ID: request.ID, Name: request.Name, Provider: provider, Enabled: enabled, SyncInterval: request.SyncInterval, Source: "api", FixturePath: s.config.FixturePath, Capabilities: adapter.Capabilities()}
	if err := s.store.AddConnection(connection); err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	if len(request.Credentials) > 0 {
		if s.secrets == nil {
			_ = s.store.DeleteConnection(request.ID)
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "encryption key is required to store credentials"})
			return
		}
		ciphertext, err := s.secrets.EncryptMap(request.Credentials)
		if err != nil {
			_ = s.store.DeleteConnection(request.ID)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not encrypt credentials"})
			return
		}
		if err := s.store.SetCredentials(request.ID, ciphertext); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save credentials"})
			return
		}
	}
	connection, _ = s.store.GetConnection(request.ID)
	if err := s.audit(r, "provider_connection.create", "provider_connection", request.ID, "succeeded"); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "connection created but audit event could not be recorded"})
		return
	}
	writeJSON(w, http.StatusCreated, connection)
}

func (s *Server) updateConnection(w http.ResponseWriter, r *http.Request) {
	var request connectionRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid connection request"})
		return
	}
	current, ok := s.store.GetConnection(r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "connection not found"})
		return
	}
	enabled := current.Enabled
	if request.Enabled != nil {
		enabled = *request.Enabled
	}
	connection, err := s.store.UpdateConnection(current.ID, request.Name, enabled, request.SyncInterval)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if request.Credentials != nil {
		if s.secrets == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "encryption key is required to store credentials"})
			return
		}
		ciphertext, encryptErr := s.secrets.EncryptMap(request.Credentials)
		if encryptErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not encrypt credentials"})
			return
		}
		if err := s.store.SetCredentials(current.ID, ciphertext); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save credentials"})
			return
		}
		connection, _ = s.store.GetConnection(current.ID)
	}
	if err := s.audit(r, "provider_connection.update", "provider_connection", current.ID, "succeeded"); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "connection updated but audit event could not be recorded"})
		return
	}
	writeJSON(w, http.StatusOK, connection)
}

func (s *Server) deleteConnection(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteConnection(r.PathValue("id")); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	if err := s.audit(r, "provider_connection.delete", "provider_connection", r.PathValue("id"), "succeeded"); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "connection deleted but audit event could not be recorded"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func slug(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var builder strings.Builder
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') {
			builder.WriteRune(character)
		} else if builder.Len() > 0 && !strings.HasSuffix(builder.String(), "-") {
			builder.WriteRune('-')
		}
	}
	return strings.Trim(builder.String(), "-")
}

func (s *Server) testConnection(w http.ResponseWriter, r *http.Request) {
	result, err := s.syncer.Test(r.Context(), r.PathValue("id"))
	if err != nil {
		if auditErr := s.audit(r, "provider_connection.test", "provider_connection", r.PathValue("id"), "failed"); auditErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "provider test failed and audit event could not be recorded"})
			return
		}
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}
	if auditErr := s.audit(r, "provider_connection.test", "provider_connection", r.PathValue("id"), "succeeded"); auditErr != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "provider test succeeded but audit event could not be recorded"})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) syncConnection(w http.ResponseWriter, r *http.Request) {
	run, err := s.syncer.Sync(r.Context(), r.PathValue("id"))
	if err != nil {
		s.metrics.Inc("sync_failures_total")
		if auditErr := s.auditSyncRun(r, run, "failed"); auditErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "sync failed and audit event could not be recorded"})
			return
		}
		status := http.StatusUnprocessableEntity
		if strings.Contains(err.Error(), "not found") {
			status = http.StatusNotFound
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	s.metrics.Inc("sync_runs_total")
	s.dispatchAlerts(r, s.alerts.Evaluate())
	if auditErr := s.auditSyncRun(r, run, "succeeded"); auditErr != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "sync succeeded but audit event could not be recorded"})
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) domains(w http.ResponseWriter, r *http.Request) {
	items, total := s.store.ListDomains(parseFilter(r))
	decorateDomains(items)
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total, "page": page(r), "page_size": pageSize(r)})
}

func (s *Server) domainDetail(w http.ResponseWriter, r *http.Request) {
	item, ok := s.store.GetDomain(r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "domain not found"})
		return
	}
	item.ExpiryState = catalog.DeriveExpiryState(item.ExpiresAt, item.Stale)
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) certificates(w http.ResponseWriter, r *http.Request) {
	items, total := s.store.ListCertificates(parseFilter(r))
	decorateCertificates(items)
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total, "page": page(r), "page_size": pageSize(r)})
}

func (s *Server) certificateDetail(w http.ResponseWriter, r *http.Request) {
	item, ok := s.store.GetCertificate(r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "certificate not found"})
		return
	}
	item.ExpiryState = catalog.DeriveCertificateExpiryState(item)
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) exportDomains(w http.ResponseWriter, r *http.Request) {
	filter := parseFilter(r)
	items := s.store.ListDomainsForExport(filter)
	rows := [][]string{{"id", "provider", "source_id", "name", "registrable_domain", "zone", "registrar", "status", "nameservers", "owner", "environment", "tags", "notes", "expiry_state", "expires_at", "last_seen_at", "stale", "source_url"}}
	for _, item := range items {
		expiresAt := ""
		if item.ExpiresAt != nil {
			expiresAt = item.ExpiresAt.UTC().Format(time.RFC3339)
		}
		rows = append(rows, []string{item.ID, item.Provider, item.SourceID, item.Name, item.RegistrableDomain, item.Zone, item.Registrar, item.Status, strings.Join(item.Nameservers, ";"), item.Owner, item.Environment, strings.Join(item.Tags, ";"), item.Notes, catalog.DeriveExpiryState(item.ExpiresAt, item.Stale), expiresAt, item.LastSeenAt.UTC().Format(time.RFC3339), strconv.FormatBool(item.Stale), item.SourceURL})
	}
	writeCSV(w, "domains.csv", rows)
}

func (s *Server) exportCertificates(w http.ResponseWriter, r *http.Request) {
	filter := parseFilter(r)
	items := s.store.ListCertificatesForExport(filter)
	rows := [][]string{{"id", "provider", "source_id", "common_name", "sans", "linked_domains", "certificate_type", "issuer", "status", "serial_number", "fingerprint", "valid_from", "valid_to", "region", "owner", "environment", "tags", "notes", "expiry_state", "last_seen_at", "stale", "source_url"}}
	for _, item := range items {
		rows = append(rows, []string{item.ID, item.Provider, item.SourceID, item.CommonName, strings.Join(item.SANs, ";"), strings.Join(item.LinkedDomains, ";"), item.CertificateType, item.Issuer, item.Status, item.SerialNumber, item.Fingerprint, item.ValidFrom.UTC().Format(time.RFC3339), item.ValidTo.UTC().Format(time.RFC3339), item.Region, item.Owner, item.Environment, strings.Join(item.Tags, ";"), item.Notes, catalog.DeriveCertificateExpiryState(item), item.LastSeenAt.UTC().Format(time.RFC3339), strconv.FormatBool(item.Stale), item.SourceURL})
	}
	writeCSV(w, "certificates.csv", rows)
}

func writeCSV(w http.ResponseWriter, filename string, rows [][]string) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	writer := csv.NewWriter(w)
	for _, row := range rows {
		_ = writer.Write(row)
	}
	writer.Flush()
}

func decorateDomains(items []domain.Domain) {
	for index := range items {
		items[index].ExpiryState = catalog.DeriveExpiryState(items[index].ExpiresAt, items[index].Stale)
	}
}

func decorateCertificates(items []domain.Certificate) {
	for index := range items {
		items[index].ExpiryState = catalog.DeriveCertificateExpiryState(items[index])
	}
}

func (s *Server) syncRuns(w http.ResponseWriter, r *http.Request) {
	allItems := s.store.ListSyncRuns()
	pageNumber, pageLimit := page(r), pageSize(r)
	writeJSON(w, http.StatusOK, map[string]any{"items": pageItems(allItems, pageNumber, pageLimit), "total": len(allItems), "page": pageNumber, "page_size": pageLimit})
}

func (s *Server) syncRunDetail(w http.ResponseWriter, r *http.Request) {
	run, ok := s.store.GetSyncRun(r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "sync run not found"})
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) auditEvents(w http.ResponseWriter, r *http.Request) {
	allItems := s.store.ListAuditEvents()
	pageNumber := page(r)
	pageLimit := pageSize(r)
	start := (pageNumber - 1) * pageLimit
	items := []catalog.AuditEvent{}
	if start < len(allItems) {
		end := start + pageLimit
		if end > len(allItems) {
			end = len(allItems)
		}
		items = allItems[start:end]
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(allItems), "page": pageNumber, "page_size": pageLimit})
}

func (s *Server) alertList(w http.ResponseWriter, r *http.Request) {
	items, total := s.alerts.ListAlerts(page(r), pageSize(r), r.URL.Query().Get("state"), r.URL.Query().Get("provider"))
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total, "page": page(r), "page_size": pageSize(r)})
}

func (s *Server) alertDetail(w http.ResponseWriter, r *http.Request) {
	alert, ok := s.alerts.Get(r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "alert not found"})
		return
	}
	writeJSON(w, http.StatusOK, alert)
}

func (s *Server) alertRules(w http.ResponseWriter, r *http.Request) {
	allItems := s.alerts.Rules()
	pageNumber, pageLimit := page(r), pageSize(r)
	writeJSON(w, http.StatusOK, map[string]any{"items": pageItems(allItems, pageNumber, pageLimit), "total": len(allItems), "page": pageNumber, "page_size": pageLimit})
}

type alertRuleRequest struct {
	ID                    string   `json:"id"`
	Name                  string   `json:"name"`
	Enabled               *bool    `json:"enabled"`
	DomainThresholds      []int    `json:"domain_thresholds"`
	CertificateThresholds []int    `json:"certificate_thresholds"`
	StaleAfterHours       *int     `json:"stale_after_hours"`
	AssetTypes            []string `json:"asset_types"`
	Providers             []string `json:"providers"`
	Owners                []string `json:"owners"`
	Environments          []string `json:"environments"`
	Tags                  []string `json:"tags"`
}

func (s *Server) createAlertRule(w http.ResponseWriter, r *http.Request) {
	var request alertRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid alert rule request"})
		return
	}
	if request.ID == "" {
		request.ID = slug(request.Name)
	}
	enabled := true
	if request.Enabled != nil {
		enabled = *request.Enabled
	}
	staleAfter := 26
	if request.StaleAfterHours != nil {
		staleAfter = *request.StaleAfterHours
	}
	rule := alerting.Rule{ID: request.ID, Name: request.Name, Enabled: enabled, DomainThresholds: request.DomainThresholds, CertificateThresholds: request.CertificateThresholds, StaleAfterHours: staleAfter, AssetTypes: request.AssetTypes, Providers: request.Providers, Owners: request.Owners, Environments: request.Environments, Tags: request.Tags}
	if len(rule.DomainThresholds) == 0 {
		rule.DomainThresholds = []int{90, 30, 14, 7, 3}
	}
	if len(rule.CertificateThresholds) == 0 {
		rule.CertificateThresholds = []int{90, 30, 14, 7, 3}
	}
	if err := s.alerts.AddRule(rule); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := s.audit(r, "alert_rule.create", "alert_rule", rule.ID, "succeeded"); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "alert rule created but audit event could not be recorded"})
		return
	}
	created, _ := s.alerts.GetRule(rule.ID)
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) updateAlertRule(w http.ResponseWriter, r *http.Request) {
	current, ok := s.alerts.GetRule(r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "alert rule not found"})
		return
	}
	var request alertRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid alert rule request"})
		return
	}
	if request.Name != "" {
		current.Name = request.Name
	}
	if request.Enabled != nil {
		current.Enabled = *request.Enabled
	}
	if request.DomainThresholds != nil {
		current.DomainThresholds = request.DomainThresholds
	}
	if request.CertificateThresholds != nil {
		current.CertificateThresholds = request.CertificateThresholds
	}
	if request.StaleAfterHours != nil {
		current.StaleAfterHours = *request.StaleAfterHours
	}
	if request.AssetTypes != nil {
		current.AssetTypes = request.AssetTypes
	}
	if request.Providers != nil {
		current.Providers = request.Providers
	}
	if request.Owners != nil {
		current.Owners = request.Owners
	}
	if request.Environments != nil {
		current.Environments = request.Environments
	}
	if request.Tags != nil {
		current.Tags = request.Tags
	}
	updated, err := s.alerts.UpdateRule(current)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}
	if err := s.audit(r, "alert_rule.update", "alert_rule", updated.ID, "succeeded"); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "alert rule updated but audit event could not be recorded"})
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) deleteAlertRule(w http.ResponseWriter, r *http.Request) {
	if err := s.alerts.DeleteRule(r.PathValue("id")); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}
	if err := s.audit(r, "alert_rule.delete", "alert_rule", r.PathValue("id"), "succeeded"); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "alert rule deleted but audit event could not be recorded"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) alertEvents(w http.ResponseWriter, r *http.Request) {
	allItems := s.alerts.Events()
	pageNumber, pageLimit := page(r), pageSize(r)
	writeJSON(w, http.StatusOK, map[string]any{"items": pageItems(allItems, pageNumber, pageLimit), "total": len(allItems), "page": pageNumber, "page_size": pageLimit})
}

func (s *Server) evaluateAlerts(w http.ResponseWriter, r *http.Request) {
	items := s.alerts.Evaluate()
	s.dispatchAlerts(r, items)
	if err := s.audit(r, "alert.evaluate", "monitor", "default", "succeeded"); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "alert evaluation completed but audit event could not be recorded"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) acknowledgeAlert(w http.ResponseWriter, r *http.Request) {
	s.transitionAlert(w, r, alerting.StateAcknowledged)
}

func (s *Server) resolveAlert(w http.ResponseWriter, r *http.Request) {
	s.transitionAlert(w, r, alerting.StateResolved)
}

func (s *Server) suppressAlert(w http.ResponseWriter, r *http.Request) {
	s.transitionAlert(w, r, alerting.StateSuppressed)
}

func (s *Server) transitionAlert(w http.ResponseWriter, r *http.Request, state string) {
	request := struct {
		Actor string `json:"actor"`
		Note  string `json:"note"`
	}{}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&request)
	}
	if request.Actor == "" {
		request.Actor = "admin"
	}
	alert, err := s.alerts.Transition(r.PathValue("id"), state, request.Actor, request.Note)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}
	if err := s.audit(r, "alert."+state, "alert", alert.ID, "succeeded"); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "alert changed but audit event could not be recorded"})
		return
	}
	writeJSON(w, http.StatusOK, alert)
}

type notificationRequest struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Kind          string            `json:"kind"`
	Endpoint      string            `json:"endpoint"`
	Enabled       *bool             `json:"enabled"`
	SigningSecret string            `json:"signing_secret"`
	Credentials   map[string]string `json:"credentials"`
}

func (s *Server) notificationChannels(w http.ResponseWriter, r *http.Request) {
	allItems := s.notifications.Channels()
	pageNumber, pageLimit := page(r), pageSize(r)
	writeJSON(w, http.StatusOK, map[string]any{"items": pageItems(allItems, pageNumber, pageLimit), "total": len(allItems), "page": pageNumber, "page_size": pageLimit})
}

func (s *Server) createNotificationChannel(w http.ResponseWriter, r *http.Request) {
	var request notificationRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid notification channel request"})
		return
	}
	if request.ID == "" {
		request.ID = slug(request.Name)
	}
	enabled := true
	if request.Enabled != nil {
		enabled = *request.Enabled
	}
	channel := notifications.Channel{ID: request.ID, Name: request.Name, Kind: request.Kind, Endpoint: request.Endpoint, Enabled: enabled}
	if err := s.notifications.AddChannel(channel); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if request.SigningSecret != "" {
		if s.secrets == nil {
			_ = s.notifications.DeleteChannel(request.ID)
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "encryption key is required for signing secrets"})
			return
		}
		ciphertext, err := s.secrets.Encrypt([]byte(request.SigningSecret))
		if err != nil {
			_ = s.notifications.DeleteChannel(request.ID)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not encrypt signing secret"})
			return
		}
		if err := s.notifications.SetSigningSecret(request.ID, ciphertext); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save signing secret"})
			return
		}
	}
	if request.Credentials != nil {
		if s.secrets == nil {
			_ = s.notifications.DeleteChannel(request.ID)
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "encryption key is required for notification credentials"})
			return
		}
		ciphertext, err := s.secrets.EncryptMap(request.Credentials)
		if err != nil {
			_ = s.notifications.DeleteChannel(request.ID)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not encrypt notification credentials"})
			return
		}
		if err := s.notifications.SetCredentials(request.ID, ciphertext); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save notification credentials"})
			return
		}
	}
	for _, item := range s.notifications.Channels() {
		if item.ID == request.ID {
			if err := s.audit(r, "notification_channel.create", "notification_channel", request.ID, "succeeded"); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "channel created but audit event could not be recorded"})
				return
			}
			writeJSON(w, http.StatusCreated, item)
			return
		}
	}
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "channel was not created"})
}

func (s *Server) updateNotificationChannel(w http.ResponseWriter, r *http.Request) {
	var request notificationRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid notification channel request"})
		return
	}
	current := s.notifications.Channels()
	var existing notifications.Channel
	for _, item := range current {
		if item.ID == r.PathValue("id") {
			existing = item
			break
		}
	}
	if existing.ID == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "notification channel not found"})
		return
	}
	enabled := existing.Enabled
	if request.Enabled != nil {
		enabled = *request.Enabled
	}
	channel, err := s.notifications.UpdateChannel(existing.ID, request.Name, request.Endpoint, enabled)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if request.SigningSecret != "" {
		if s.secrets == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "encryption key is required for signing secrets"})
			return
		}
		ciphertext, encryptErr := s.secrets.Encrypt([]byte(request.SigningSecret))
		if encryptErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not encrypt signing secret"})
			return
		}
		if err := s.notifications.SetSigningSecret(existing.ID, ciphertext); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save signing secret"})
			return
		}
		channel, _ = findChannel(s.notifications.Channels(), existing.ID)
	}
	if request.Credentials != nil {
		if s.secrets == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "encryption key is required for notification credentials"})
			return
		}
		ciphertext, encryptErr := s.secrets.EncryptMap(request.Credentials)
		if encryptErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not encrypt notification credentials"})
			return
		}
		if err := s.notifications.SetCredentials(existing.ID, ciphertext); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save notification credentials"})
			return
		}
		channel, _ = findChannel(s.notifications.Channels(), existing.ID)
	}
	if err := s.audit(r, "notification_channel.update", "notification_channel", existing.ID, "succeeded"); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "channel updated but audit event could not be recorded"})
		return
	}
	writeJSON(w, http.StatusOK, channel)
}

func (s *Server) deleteNotificationChannel(w http.ResponseWriter, r *http.Request) {
	if err := s.notifications.DeleteChannel(r.PathValue("id")); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	if err := s.audit(r, "notification_channel.delete", "notification_channel", r.PathValue("id"), "succeeded"); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "channel deleted but audit event could not be recorded"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) testNotificationChannel(w http.ResponseWriter, r *http.Request) {
	delivery, err := s.notifications.Test(r.Context(), r.PathValue("id"))
	outcome := "succeeded"
	if err != nil {
		outcome = "failed"
	}
	var auditErr error
	if delivery.CorrelationID != "" {
		auditErr = s.auditWithCorrelation(r, "notification_channel.test", "notification_channel", r.PathValue("id"), outcome, delivery.CorrelationID)
	} else {
		auditErr = s.audit(r, "notification_channel.test", "notification_channel", r.PathValue("id"), outcome)
	}
	if auditErr != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "channel test completed but audit event could not be recorded"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err.Error(), "delivery": delivery})
		return
	}
	writeJSON(w, http.StatusOK, delivery)
}

func (s *Server) notificationDeliveries(w http.ResponseWriter, r *http.Request) {
	allItems := s.notifications.Deliveries()
	if alertID := strings.TrimSpace(r.URL.Query().Get("alert_id")); alertID != "" {
		filtered := make([]notifications.Delivery, 0, len(allItems))
		for _, item := range allItems {
			if item.AlertID == alertID {
				filtered = append(filtered, item)
			}
		}
		allItems = filtered
	}
	pageNumber, pageLimit := page(r), pageSize(r)
	writeJSON(w, http.StatusOK, map[string]any{"items": pageItems(allItems, pageNumber, pageLimit), "total": len(allItems), "page": pageNumber, "page_size": pageLimit})
}

func (s *Server) notifyAlert(w http.ResponseWriter, r *http.Request) {
	alert, ok := s.alerts.Get(r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "alert not found"})
		return
	}
	if err := s.notifications.Queue(alert); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "notification could not be queued"})
		return
	}
	deliveries := s.notifications.DeliverOutbox(r.Context())
	if err := s.auditDeliveries(r, deliveries); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "notification completed but audit event could not be recorded"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": deliveries})
}

func (s *Server) dispatchAlerts(r *http.Request, alerts []alerting.Alert) {
	for _, alert := range alerts {
		if alert.State == alerting.StateResolved || alert.State == alerting.StateSuppressed {
			continue
		}
		if err := s.notifications.Queue(alert); err != nil {
			s.logger.Error("notification_queue_failed", "alert_id", alert.ID, "error", err)
			continue
		}
		if err := s.auditDeliveries(r, s.notifications.DeliverOutbox(r.Context())); err != nil {
			s.logger.Error("notification_audit_failed", "error", err)
		}
	}
}

func (s *Server) auditDeliveries(r *http.Request, deliveries []notifications.Delivery) error {
	var firstErr error
	for _, delivery := range deliveries {
		s.metrics.Inc("notification_deliveries_total")
		if delivery.Status != "delivered" {
			s.metrics.Inc("notification_failures_total")
		}
		if err := s.auditWithCorrelation(r, "notification.delivery", "notification_delivery", delivery.ID, delivery.Status, delivery.CorrelationID); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (s *Server) audit(r *http.Request, action, objectType, objectID, outcome string) error {
	correlationID := strings.TrimSpace(r.Header.Get("X-Request-ID"))
	if correlationID == "" {
		correlationID = "req-" + time.Now().UTC().Format("20060102T150405.000000000Z")
	}
	return s.auditWithCorrelation(r, action, objectType, objectID, outcome, correlationID)
}

func (s *Server) auditSyncRun(r *http.Request, run catalog.SyncRun, outcome string) error {
	if run.CorrelationID != "" {
		return s.auditWithCorrelation(r, "sync.run", "provider_connection", run.ConnectionID, outcome, run.CorrelationID)
	}
	return s.audit(r, "sync.run", "provider_connection", r.PathValue("id"), outcome)
}

func (s *Server) auditWithCorrelation(r *http.Request, action, objectType, objectID, outcome, correlationID string) error {
	actor := "system"
	if requestRole, ok := s.authenticate(r); ok {
		actor = string(requestRole)
	}
	if strings.TrimSpace(correlationID) == "" {
		correlationID = "req-" + time.Now().UTC().Format("20060102T150405.000000000Z")
	}
	return s.store.AppendAudit(catalog.AuditEvent{
		Actor:         actor,
		Action:        action,
		ObjectType:    objectType,
		ObjectID:      objectID,
		Outcome:       outcome,
		CorrelationID: correlationID,
	})
}

func findChannel(items []notifications.Channel, id string) (notifications.Channel, bool) {
	for _, item := range items {
		if item.ID == id {
			return item, true
		}
	}
	return notifications.Channel{}, false
}

func findMember(items []catalog.Member, id string) (catalog.Member, bool) {
	for _, item := range items {
		if item.ID == id {
			return item, true
		}
	}
	return catalog.Member{}, false
}

func parseFilter(r *http.Request) catalog.Filter {
	filter := catalog.Filter{Search: r.URL.Query().Get("search"), Provider: r.URL.Query().Get("provider"), Owner: r.URL.Query().Get("owner"), Environment: r.URL.Query().Get("environment"), Status: r.URL.Query().Get("status"), ExpiryState: r.URL.Query().Get("expiry_state"), Tag: r.URL.Query().Get("tag"), Sort: r.URL.Query().Get("sort"), Page: page(r), PageSize: pageSize(r)}
	filter.SortDesc = strings.EqualFold(r.URL.Query().Get("order"), "desc")
	if value := r.URL.Query().Get("stale"); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			filter.Stale = &parsed
		}
	}
	if value := r.URL.Query().Get("expires_before"); value != "" {
		if parsed, err := time.Parse(time.RFC3339, value); err == nil {
			filter.ExpiresBefore = &parsed
		}
	}
	if value := r.URL.Query().Get("expires_after"); value != "" {
		if parsed, err := time.Parse(time.RFC3339, value); err == nil {
			filter.ExpiresAfter = &parsed
		}
	}
	return filter
}

func page(r *http.Request) int {
	parsed, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if parsed < 1 {
		return 1
	}
	return parsed
}

func pageSize(r *http.Request) int {
	parsed, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if parsed < 1 || parsed > 200 {
		return 50
	}
	return parsed
}

func pageItems[T any](items []T, pageNumber, pageLimit int) []T {
	start := (pageNumber - 1) * pageLimit
	if start >= len(items) {
		return []T{}
	}
	end := start + pageLimit
	if end > len(items) {
		end = len(items)
	}
	return items[start:end]
}

func (s *Server) web(w http.ResponseWriter, r *http.Request) {
	index := filepath.Join(s.config.WebDir, "index.html")
	if _, err := os.Stat(index); err != nil {
		http.NotFound(w, r)
		return
	}

	relativePath := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	requested := filepath.Join(s.config.WebDir, relativePath)
	if relative, err := filepath.Rel(s.config.WebDir, requested); err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		http.NotFound(w, r)
		return
	}
	if info, err := os.Stat(requested); err == nil && !info.IsDir() {
		http.ServeFile(w, r, requested)
		return
	}
	http.ServeFile(w, r, index)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
