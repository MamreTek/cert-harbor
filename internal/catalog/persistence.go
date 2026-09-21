package catalog

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/MamreTek/cert-harbor/internal/domain"
	"github.com/MamreTek/cert-harbor/internal/providers"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type persistedConnection struct {
	ID                    string                 `json:"id"`
	Name                  string                 `json:"name"`
	Provider              providers.Provider     `json:"provider"`
	Enabled               bool                   `json:"enabled"`
	SyncInterval          string                 `json:"sync_interval"`
	NextSyncAt            *time.Time             `json:"next_sync_at,omitempty"`
	Source                string                 `json:"source"`
	FixturePath           string                 `json:"fixture_path,omitempty"`
	Capabilities          providers.Capabilities `json:"capabilities"`
	Status                string                 `json:"status"`
	LastSyncAt            *time.Time             `json:"last_sync_at,omitempty"`
	LastSyncError         string                 `json:"last_sync_error,omitempty"`
	CredentialsStored     bool                   `json:"credentials_stored"`
	CredentialsCiphertext string                 `json:"credentials_ciphertext,omitempty"`
}

//go:embed migrations/001_catalog_snapshot.sql
var catalogSchema []byte

// OpenStore opens an atomically persisted catalog. An absent file starts empty.
// When databaseURL is supplied, PostgreSQL is the source of truth and the
// file path is ignored. The variadic form preserves the lightweight local API
// used by tests and local development.
func OpenStore(path string, databaseURLs ...string) (*Store, error) {
	store := NewStore()
	store.filePath = path
	if len(databaseURLs) > 0 && databaseURLs[0] != "" {
		db, err := openPostgres(databaseURLs[0])
		if err != nil {
			return nil, err
		}
		store.database = db
		data, err := readPostgresSnapshot(db)
		if err != nil {
			_ = db.Close()
			return nil, err
		}
		if len(data) == 0 {
			if path != "" {
				legacyData, legacyErr := os.ReadFile(path)
				if legacyErr == nil && len(legacyData) > 0 {
					if err := store.restore(legacyData); err != nil {
						_ = db.Close()
						return nil, fmt.Errorf("migrate legacy catalog snapshot: %w", err)
					}
					if err := store.persistLocked(); err != nil {
						_ = db.Close()
						return nil, fmt.Errorf("persist migrated catalog snapshot: %w", err)
					}
				}
			}
			return store, nil
		}
		if err := store.restore(data); err != nil {
			_ = db.Close()
			return nil, err
		}
		return store, nil
	}
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
	if err := store.restore(data); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *Store) restore(data []byte) error {
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
		return err
	}
	if snapshot.Domains != nil {
		s.domains = snapshot.Domains
	}
	if snapshot.Certificates != nil {
		s.certificates = snapshot.Certificates
	}
	for id, connection := range snapshot.Connections {
		if connection.SyncInterval == "" {
			connection.SyncInterval = "24h"
		}
		s.connections[id] = Connection{
			ID: connection.ID, Name: connection.Name, Provider: connection.Provider, Enabled: connection.Enabled,
			SyncInterval: connection.SyncInterval, NextSyncAt: connection.NextSyncAt,
			Source: connection.Source, FixturePath: connection.FixturePath, Capabilities: connection.Capabilities,
			Status: connection.Status, LastSyncAt: connection.LastSyncAt, LastSyncError: connection.LastSyncError,
			CredentialsStored: connection.CredentialsStored, CredentialsCiphertext: connection.CredentialsCiphertext,
		}
	}
	s.syncRuns = snapshot.SyncRuns
	s.auditEvents = snapshot.AuditEvents
	if snapshot.Workspace.ID != "" {
		s.workspace = snapshot.Workspace
	}
	if snapshot.Members != nil {
		s.members = snapshot.Members
	}
	return nil
}

func (s *Store) persistLocked() error {
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
			SyncInterval: connection.SyncInterval, NextSyncAt: connection.NextSyncAt,
			Source: connection.Source, FixturePath: connection.FixturePath, Capabilities: connection.Capabilities,
			Status: connection.Status, LastSyncAt: connection.LastSyncAt, LastSyncError: connection.LastSyncError,
			CredentialsStored: connection.CredentialsStored, CredentialsCiphertext: connection.CredentialsCiphertext,
		}
	}
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	if s.database != nil {
		db, ok := s.database.(*postgresDatabase)
		if !ok {
			return errors.New("unsupported catalog persistence database")
		}
		return writePostgresSnapshot(db, data)
	}
	if s.filePath == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.filePath), 0o700); err != nil {
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

type postgresDatabase struct{ *sql.DB }

func openPostgres(databaseURL string) (*postgresDatabase, error) {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open postgres catalog: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("connect to postgres catalog: %w", err)
	}
	if _, err := db.ExecContext(ctx, string(catalogSchema)); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize postgres catalog schema: %w", err)
	}
	return &postgresDatabase{DB: db}, nil
}

func readPostgresSnapshot(db *postgresDatabase) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var payload []byte
	err := db.QueryRowContext(ctx, `SELECT payload FROM cert_harbor_catalog_snapshots WHERE snapshot_id = 1`).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read postgres catalog snapshot: %w", err)
	}
	return payload, nil
}

func writePostgresSnapshot(db *postgresDatabase, payload []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := db.ExecContext(ctx, `
INSERT INTO cert_harbor_catalog_snapshots (snapshot_id, payload, updated_at)
VALUES (1, $1::jsonb, $2)
ON CONFLICT (snapshot_id) DO UPDATE
SET payload = EXCLUDED.payload, updated_at = EXCLUDED.updated_at`, payload, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("write postgres catalog snapshot: %w", err)
	}
	return nil
}
