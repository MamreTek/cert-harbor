package catalog

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/MamreTek/cert-harbor/internal/domain"
	"github.com/MamreTek/cert-harbor/internal/providers"
)

type persistedConnection struct {
	ID                    string                 `json:"id"`
	Name                  string                 `json:"name"`
	Provider              providers.Provider     `json:"provider"`
	Enabled               bool                   `json:"enabled"`
	Source                string                 `json:"source"`
	FixturePath           string                 `json:"fixture_path,omitempty"`
	Capabilities          providers.Capabilities `json:"capabilities"`
	Status                string                 `json:"status"`
	LastSyncAt            *time.Time             `json:"last_sync_at,omitempty"`
	LastSyncError         string                 `json:"last_sync_error,omitempty"`
	CredentialsStored     bool                   `json:"credentials_stored"`
	CredentialsCiphertext string                 `json:"credentials_ciphertext,omitempty"`
}

// OpenStore opens an atomically persisted catalog. An absent file starts empty.
func OpenStore(path string) (*Store, error) {
	store := NewStore()
	store.filePath = path
	if path == "" {
		return store, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	var snapshot struct {
		Version      int                            `json:"version"`
		Domains      map[string]domain.Domain       `json:"domains"`
		Certificates map[string]domain.Certificate  `json:"certificates"`
		Connections  map[string]persistedConnection `json:"connections"`
		SyncRuns     []SyncRun                      `json:"sync_runs"`
		AuditEvents  []AuditEvent                   `json:"audit_events"`
		Workspace    Workspace                      `json:"workspace"`
		Members      map[string]Member              `json:"members"`
	}
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return nil, err
	}
	if snapshot.Domains != nil {
		store.domains = snapshot.Domains
	}
	if snapshot.Certificates != nil {
		store.certificates = snapshot.Certificates
	}
	for id, connection := range snapshot.Connections {
		store.connections[id] = Connection{
			ID: connection.ID, Name: connection.Name, Provider: connection.Provider, Enabled: connection.Enabled,
			Source: connection.Source, FixturePath: connection.FixturePath, Capabilities: connection.Capabilities,
			Status: connection.Status, LastSyncAt: connection.LastSyncAt, LastSyncError: connection.LastSyncError,
			CredentialsStored: connection.CredentialsStored, CredentialsCiphertext: connection.CredentialsCiphertext,
		}
	}
	store.syncRuns = snapshot.SyncRuns
	store.auditEvents = snapshot.AuditEvents
	if snapshot.Workspace.ID != "" {
		store.workspace = snapshot.Workspace
	}
	if snapshot.Members != nil {
		store.members = snapshot.Members
	}
	return store, nil
}

func (s *Store) persistLocked() error {
	if s.filePath == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.filePath), 0o700); err != nil {
		return err
	}
	snapshot := struct {
		Version      int                            `json:"version"`
		Domains      map[string]domain.Domain       `json:"domains"`
		Certificates map[string]domain.Certificate  `json:"certificates"`
		Connections  map[string]persistedConnection `json:"connections"`
		SyncRuns     []SyncRun                      `json:"sync_runs"`
		AuditEvents  []AuditEvent                   `json:"audit_events"`
		Workspace    Workspace                      `json:"workspace"`
		Members      map[string]Member              `json:"members"`
	}{Version: 1, Domains: s.domains, Certificates: s.certificates, Connections: make(map[string]persistedConnection, len(s.connections)), SyncRuns: s.syncRuns, AuditEvents: s.auditEvents, Workspace: s.workspace, Members: s.members}
	for id, connection := range s.connections {
		snapshot.Connections[id] = persistedConnection{
			ID: connection.ID, Name: connection.Name, Provider: connection.Provider, Enabled: connection.Enabled,
			Source: connection.Source, FixturePath: connection.FixturePath, Capabilities: connection.Capabilities,
			Status: connection.Status, LastSyncAt: connection.LastSyncAt, LastSyncError: connection.LastSyncError,
			CredentialsStored: connection.CredentialsStored, CredentialsCiphertext: connection.CredentialsCiphertext,
		}
	}
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	temporary := s.filePath + ".tmp"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(temporary, s.filePath); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}
