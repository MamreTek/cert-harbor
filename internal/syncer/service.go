package syncer

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/MamreTek/cert-harbor/internal/catalog"
	"github.com/MamreTek/cert-harbor/internal/domain"
	observability "github.com/MamreTek/cert-harbor/internal/metrics"
	"github.com/MamreTek/cert-harbor/internal/providers"
	"github.com/MamreTek/cert-harbor/internal/security"
)

type Service struct {
	store    *catalog.Store
	adapters map[providers.Provider]providers.Adapter
	secrets  *security.SecretBox
	metrics  *observability.Metrics
	now      func() time.Time
}

func New(store *catalog.Store, adapters map[providers.Provider]providers.Adapter, secrets ...*security.SecretBox) *Service {
	service := &Service{store: store, adapters: adapters, now: func() time.Time { return time.Now().UTC() }}
	if len(secrets) > 0 {
		service.secrets = secrets[0]
	}
	return service
}

// SetMetrics attaches the process metrics sink used by both manual and scheduled syncs.
func (s *Service) SetMetrics(metrics *observability.Metrics) {
	s.metrics = metrics
}

func (s *Service) Sync(ctx context.Context, connectionID string) (catalog.SyncRun, error) {
	startedAt := time.Now()
	defer func() {
		if s.metrics != nil {
			s.metrics.ObserveDuration("sync", time.Since(startedAt).Seconds())
		}
	}()
	connection, ok := s.store.GetConnection(connectionID)
	if !ok {
		return catalog.SyncRun{}, fmt.Errorf("connection %q not found", connectionID)
	}
	adapter, ok := s.adapters[connection.Provider]
	if !ok {
		return catalog.SyncRun{}, fmt.Errorf("provider adapter %q is not configured", connection.Provider)
	}
	started := s.now()
	run, err := s.store.BeginSync(connection.ID, connection.Provider, started)
	if err != nil {
		return catalog.SyncRun{}, err
	}

	domains, certificates, err := s.collect(ctx, adapter, connection)
	if err != nil {
		if s.metrics != nil {
			s.metrics.Inc("provider_errors_total")
		}
		failed, finishErr := s.store.FinishSync(run.ID, false, s.now(), 0, 0, err.Error())
		if finishErr != nil {
			return catalog.SyncRun{}, finishErr
		}
		return failed, err
	}
	for i := range domains {
		domains[i].ID = connection.ID + ":domain:" + domains[i].SourceID
		domains[i].ConnectionID = connection.ID
		domains[i].Provider = string(connection.Provider)
		domains[i].LastSeenAt = started
		domains[i].Stale = false
	}
	for i := range certificates {
		certificates[i].ID = connection.ID + ":certificate:" + certificates[i].SourceID
		certificates[i].ConnectionID = connection.ID
		certificates[i].Provider = string(connection.Provider)
		certificates[i].LastSeenAt = started
		certificates[i].Stale = false
	}
	if err := s.store.ReplaceAssets(connection.ID, started, domains, certificates); err != nil {
		if s.metrics != nil {
			s.metrics.Inc("provider_errors_total")
		}
		summary := fmt.Errorf("persist catalog: %w", err).Error()
		failed, finishErr := s.store.FinishSync(run.ID, false, s.now(), 0, 0, summary)
		if finishErr != nil {
			return catalog.SyncRun{}, finishErr
		}
		return failed, errors.New(summary)
	}
	return s.store.FinishSync(run.ID, true, s.now(), len(domains), len(certificates), "")
}

func (s *Service) Test(ctx context.Context, connectionID string) (providers.TestResult, error) {
	connection, ok := s.store.GetConnection(connectionID)
	if !ok {
		return providers.TestResult{}, fmt.Errorf("connection %q not found", connectionID)
	}
	adapter, ok := s.adapters[connection.Provider]
	if !ok {
		return providers.TestResult{}, fmt.Errorf("provider adapter %q is not configured", connection.Provider)
	}
	credentials, err := s.credentials(connection)
	if err != nil {
		return providers.TestResult{}, err
	}
	return adapter.Test(ctx, credentials)
}

func (s *Service) collect(ctx context.Context, adapter providers.Adapter, connection catalog.Connection) ([]domain.Domain, []domain.Certificate, error) {
	credentials, err := s.credentials(connection)
	if err != nil {
		return nil, nil, err
	}
	var domains []domain.Domain
	seenDomainCursors := make(map[string]struct{})
	for cursor := ""; ; {
		if cursor != "" {
			if _, seen := seenDomainCursors[cursor]; seen {
				return nil, nil, fmt.Errorf("provider returned a repeated domain page cursor %q", cursor)
			}
			seenDomainCursors[cursor] = struct{}{}
		}
		page, err := adapter.ListDomains(ctx, credentials, cursor)
		if err != nil {
			return nil, nil, fmt.Errorf("list domains: %w", err)
		}
		domains = append(domains, page.Items...)
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	var certificates []domain.Certificate
	seenCertificateCursors := make(map[string]struct{})
	for cursor := ""; ; {
		if cursor != "" {
			if _, seen := seenCertificateCursors[cursor]; seen {
				return nil, nil, fmt.Errorf("provider returned a repeated certificate page cursor %q", cursor)
			}
			seenCertificateCursors[cursor] = struct{}{}
		}
		page, err := adapter.ListCertificates(ctx, credentials, cursor)
		if err != nil {
			return nil, nil, fmt.Errorf("list certificates: %w", err)
		}
		certificates = append(certificates, page.Items...)
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	return domains, certificates, nil
}

func (s *Service) credentials(connection catalog.Connection) (providers.Credentials, error) {
	if connection.CredentialsCiphertext == "" {
		return providers.Credentials{}, nil
	}
	if s.secrets == nil {
		return providers.Credentials{}, fmt.Errorf("credentials for connection %q cannot be decrypted without an encryption key", connection.ID)
	}
	values, err := s.secrets.DecryptMap(connection.CredentialsCiphertext)
	if err != nil {
		return providers.Credentials{}, fmt.Errorf("decrypt credentials for connection %q: %w", connection.ID, err)
	}
	return providers.Credentials{Values: values}, nil
}
