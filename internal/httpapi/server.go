package httpapi

import (
	"encoding/json"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/MamreTek/cert-harbor/internal/catalog"
	"github.com/MamreTek/cert-harbor/internal/config"
	"github.com/MamreTek/cert-harbor/internal/providers/registry"
	"github.com/MamreTek/cert-harbor/internal/syncer"
)

type Server struct {
	config config.Config
	store  *catalog.Store
	syncer *syncer.Service
	mux    *http.ServeMux
}

type Dependencies struct {
	Store  *catalog.Store
	Syncer *syncer.Service
}

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
	s := &Server{config: cfg, store: deps.Store, syncer: deps.Syncer, mux: http.NewServeMux()}
	s.mux.HandleFunc("GET /healthz", s.health)
	s.mux.HandleFunc("GET /readyz", s.ready)
	s.mux.HandleFunc("GET /api/v1/meta", s.meta)
	s.mux.HandleFunc("GET /api/v1/catalog/summary", s.summary)
	s.mux.HandleFunc("GET /api/v1/provider-connections", s.connections)
	s.mux.HandleFunc("POST /api/v1/provider-connections/{id}/test", s.testConnection)
	s.mux.HandleFunc("POST /api/v1/provider-connections/{id}/sync", s.syncConnection)
	s.mux.HandleFunc("GET /api/v1/domains", s.domains)
	s.mux.HandleFunc("GET /api/v1/certificates", s.certificates)
	s.mux.HandleFunc("GET /api/v1/sync-runs", s.syncRuns)
	s.mux.HandleFunc("/", s.web)
	return s
}

func (s *Server) Handler() http.Handler {
	return s.mux
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
	writeJSON(w, http.StatusOK, s.store.Summary())
}

func (s *Server) connections(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": s.store.ListConnections()})
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

func (s *Server) syncRuns(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": s.store.ListSyncRuns()})
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
