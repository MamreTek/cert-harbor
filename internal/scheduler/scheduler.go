package scheduler

import (
	"context"
	"log"
	"time"

	"github.com/MamreTek/cert-harbor/internal/catalog"
	"github.com/MamreTek/cert-harbor/internal/syncer"
)

type Scheduler struct {
	store   *catalog.Store
	syncer  *syncer.Service
	logf    func(string, ...any)
	onCycle func(context.Context)
}

func New(store *catalog.Store, service *syncer.Service, onCycle ...func(context.Context)) *Scheduler {
	scheduler := &Scheduler{store: store, syncer: service, logf: log.Printf}
	if len(onCycle) > 0 {
		scheduler.onCycle = onCycle[0]
	}
	return scheduler
}

func (s *Scheduler) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	s.initializeNextRuns(time.Now().UTC())
	ticker := time.NewTicker(minimumTick(interval))
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.RunDue(ctx)
		}
	}
}

func minimumTick(interval time.Duration) time.Duration {
	if interval < time.Minute {
		return interval
	}
	return time.Minute
}

func (s *Scheduler) RunOnce(ctx context.Context) {
	for _, connection := range s.store.ListConnections() {
		if !connection.Enabled {
			continue
		}
		if _, err := s.syncConnection(ctx, connection); err != nil {
			s.logf("scheduled sync failed connection=%s provider=%s error=%v", connection.ID, connection.Provider, err)
		}
	}
	if s.onCycle != nil {
		s.onCycle(ctx)
	}
}

func (s *Scheduler) RunDue(ctx context.Context) {
	now := time.Now().UTC()
	for _, connection := range s.store.ListConnections() {
		if !connection.Enabled || (connection.NextSyncAt != nil && now.Before(*connection.NextSyncAt)) {
			continue
		}
		if _, err := s.syncConnection(ctx, connection); err != nil {
			s.logf("scheduled sync failed connection=%s provider=%s error=%v", connection.ID, connection.Provider, err)
		}
		s.scheduleNext(connection, now)
	}
	if s.onCycle != nil {
		s.onCycle(ctx)
	}
}

func (s *Scheduler) syncConnection(ctx context.Context, connection catalog.Connection) (catalog.SyncRun, error) {
	run, err := s.syncer.Sync(ctx, connection.ID)
	outcome := "succeeded"
	if err != nil {
		outcome = "failed"
	}
	correlationID := run.CorrelationID
	if correlationID == "" {
		correlationID = "scheduled-" + connection.ID + "-" + time.Now().UTC().Format("20060102T150405.000000000Z")
	}
	objectID := connection.ID
	if run.ConnectionID != "" {
		objectID = run.ConnectionID
	}
	if auditErr := s.store.AppendAudit(catalog.AuditEvent{
		Actor:         "system",
		Action:        "sync.run",
		ObjectType:    "provider_connection",
		ObjectID:      objectID,
		Outcome:       outcome,
		CorrelationID: correlationID,
		CreatedAt:     time.Now().UTC(),
	}); auditErr != nil {
		s.logf("scheduled sync audit failed connection=%s error=%v", connection.ID, auditErr)
	}
	return run, err
}

func (s *Scheduler) initializeNextRuns(now time.Time) {
	for _, connection := range s.store.ListConnections() {
		if connection.Enabled && connection.NextSyncAt == nil {
			s.scheduleNext(connection, now)
		}
	}
}

func (s *Scheduler) scheduleNext(connection catalog.Connection, now time.Time) {
	interval, err := time.ParseDuration(connection.SyncInterval)
	if err != nil || interval <= 0 {
		interval = 24 * time.Hour
	}
	next := now.Add(interval)
	_ = s.store.SetNextSyncAt(connection.ID, next)
}
