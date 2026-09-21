package httpapi

import (
	"crypto/subtle"
	"encoding/csv"
	"encoding/json"
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
	"github.com/MamreTek/cert-harbor/internal/providers"
	"github.com/MamreTek/cert-harbor/internal/providers/registry"
	"github.com/MamreTek/cert-harbor/internal/security"
	"github.com/MamreTek/cert-harbor/internal/syncer"
)

type Server struct {
	config  config.Config
	store   *catalog.Store
	syncer  *syncer.Service
	alerts  *alerting.Engine
	secrets *security.SecretBox
	mux     *http.ServeMux
}

type Dependencies struct {
	Store   *catalog.Store
	Syncer  *syncer.Service
	Alerts  *alerting.Engine
	Secrets *security.SecretBox
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
	s := &Server{config: cfg, store: deps.Store, syncer: deps.Syncer, alerts: deps.Alerts, secrets: deps.Secrets, mux: http.NewServeMux()}
	s.mux.HandleFunc("GET /healthz", s.health)
	s.mux.HandleFunc("GET /readyz", s.ready)
	s.mux.HandleFunc("GET /api/v1/meta", s.meta)
	s.mux.HandleFunc("GET /api/v1/catalog/summary", s.summary)
	s.mux.HandleFunc("GET /api/v1/provider-connections", s.connections)
	s.mux.HandleFunc("POST /api/v1/provider-connections", s.createConnection)
	s.mux.HandleFunc("PATCH /api/v1/provider-connections/{id}", s.updateConnection)
	s.mux.HandleFunc("DELETE /api/v1/provider-connections/{id}", s.deleteConnection)
	s.mux.HandleFunc("POST /api/v1/provider-connections/{id}/test", s.testConnection)
	s.mux.HandleFunc("POST /api/v1/provider-connections/{id}/sync", s.syncConnection)
	s.mux.HandleFunc("GET /api/v1/domains", s.domains)
	s.mux.HandleFunc("GET /api/v1/certificates", s.certificates)
	s.mux.HandleFunc("GET /api/v1/export/domains.csv", s.exportDomains)
	s.mux.HandleFunc("GET /api/v1/export/certificates.csv", s.exportCertificates)
	s.mux.HandleFunc("GET /api/v1/sync-runs", s.syncRuns)
	s.mux.HandleFunc("GET /api/v1/alerts", s.alertList)
	s.mux.HandleFunc("GET /api/v1/alert-rules", s.alertRules)
	s.mux.HandleFunc("GET /api/v1/alert-events", s.alertEvents)
	s.mux.HandleFunc("POST /api/v1/monitor/evaluate", s.evaluateAlerts)
	s.mux.HandleFunc("POST /api/v1/alerts/{id}/acknowledge", s.acknowledgeAlert)
	s.mux.HandleFunc("POST /api/v1/alerts/{id}/resolve", s.resolveAlert)
	s.mux.HandleFunc("POST /api/v1/alerts/{id}/suppress", s.suppressAlert)
	s.mux.HandleFunc("/", s.web)
	return s
}

func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" || r.URL.Path == "/api/v1/meta" || !strings.HasPrefix(r.URL.Path, "/api/") {
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
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) meta(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"name":    "CertHarbor",
		"version": "0.2.0",
		"env":     s.config.Env,
	})
}

func (s *Server) summary(w http.ResponseWriter, _ *http.Request) {
	summary := s.store.Summary()
	openAlerts := 0
	for _, item := range s.alerts.Alerts() {
		if item.State != alerting.StateResolved {
			openAlerts++
		}
	}
	summary["open_alerts"] = openAlerts
	writeJSON(w, http.StatusOK, summary)
}

func (s *Server) connections(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": s.store.ListConnections()})
}

type connectionRequest struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Provider    string            `json:"provider"`
	Enabled     *bool             `json:"enabled"`
	Credentials map[string]string `json:"credentials"`
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
	connection := catalog.Connection{ID: request.ID, Name: request.Name, Provider: provider, Enabled: enabled, Source: "api", FixturePath: s.config.FixturePath, Capabilities: adapter.Capabilities()}
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
	connection, err := s.store.UpdateConnection(current.ID, request.Name, enabled)
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
	writeJSON(w, http.StatusOK, connection)
}

func (s *Server) deleteConnection(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteConnection(r.PathValue("id")); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
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
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) syncConnection(w http.ResponseWriter, r *http.Request) {
	run, err := s.syncer.Sync(r.Context(), r.PathValue("id"))
	if err != nil {
		status := http.StatusUnprocessableEntity
		if strings.Contains(err.Error(), "not found") {
			status = http.StatusNotFound
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	s.alerts.Evaluate()
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) domains(w http.ResponseWriter, r *http.Request) {
	items, total := s.store.ListDomains(parseFilter(r))
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total, "page": page(r), "page_size": pageSize(r)})
}

func (s *Server) certificates(w http.ResponseWriter, r *http.Request) {
	items, total := s.store.ListCertificates(parseFilter(r))
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total, "page": page(r), "page_size": pageSize(r)})
}

func (s *Server) exportDomains(w http.ResponseWriter, r *http.Request) {
	items, _ := s.store.ListDomains(catalog.Filter{Search: r.URL.Query().Get("search"), Provider: r.URL.Query().Get("provider"), Page: 1, PageSize: 200})
	rows := [][]string{{"id", "provider", "source_id", "name", "status", "owner", "environment", "expires_at", "last_seen_at", "stale", "source_url"}}
	for _, item := range items {
		expiresAt := ""
		if item.ExpiresAt != nil {
			expiresAt = item.ExpiresAt.UTC().Format(time.RFC3339)
		}
		rows = append(rows, []string{item.ID, item.Provider, item.SourceID, item.Name, item.Status, item.Owner, item.Environment, expiresAt, item.LastSeenAt.UTC().Format(time.RFC3339), strconv.FormatBool(item.Stale), item.SourceURL})
	}
	writeCSV(w, "domains.csv", rows)
}

func (s *Server) exportCertificates(w http.ResponseWriter, r *http.Request) {
	items, _ := s.store.ListCertificates(catalog.Filter{Search: r.URL.Query().Get("search"), Provider: r.URL.Query().Get("provider"), Page: 1, PageSize: 200})
	rows := [][]string{{"id", "provider", "source_id", "common_name", "issuer", "serial_number", "fingerprint", "valid_from", "valid_to", "owner", "environment", "last_seen_at", "stale", "source_url"}}
	for _, item := range items {
		rows = append(rows, []string{item.ID, item.Provider, item.SourceID, item.CommonName, item.Issuer, item.SerialNumber, item.Fingerprint, item.ValidFrom.UTC().Format(time.RFC3339), item.ValidTo.UTC().Format(time.RFC3339), item.Owner, item.Environment, item.LastSeenAt.UTC().Format(time.RFC3339), strconv.FormatBool(item.Stale), item.SourceURL})
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

func (s *Server) syncRuns(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": s.store.ListSyncRuns()})
}

func (s *Server) alertList(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": s.alerts.Alerts()})
}

func (s *Server) alertRules(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": s.alerts.Rules()})
}

func (s *Server) alertEvents(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": s.alerts.Events()})
}

func (s *Server) evaluateAlerts(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": s.alerts.Evaluate()})
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
	writeJSON(w, http.StatusOK, alert)
}

func parseFilter(r *http.Request) catalog.Filter {
	filter := catalog.Filter{Search: r.URL.Query().Get("search"), Provider: r.URL.Query().Get("provider"), Page: page(r), PageSize: pageSize(r)}
	if value := r.URL.Query().Get("stale"); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			filter.Stale = &parsed
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
