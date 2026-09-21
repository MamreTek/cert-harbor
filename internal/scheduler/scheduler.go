package scheduler

import (
	"context"
	"log"
	"time"

	"github.com/MamreTek/cert-harbor/internal/catalog"
	"github.com/MamreTek/cert-harbor/internal/syncer"
)

type Scheduler struct {
	store  *catalog.Store
	syncer *syncer.Service
	logf   func(string, ...any)
}

func New(store *catalog.Store, service *syncer.Service) *Scheduler {
	return &Scheduler{store: store, syncer: service, logf: log.Printf}
}

func (s *Scheduler) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.RunOnce(ctx)
		}
	}
}

func (s *Scheduler) RunOnce(ctx context.Context) {
	for _, connection := range s.store.ListConnections() {
		if !connection.Enabled {
			continue
		}
		if _, err := s.syncer.Sync(ctx, connection.ID); err != nil {
			s.logf("scheduled sync failed connection=%s provider=%s error=%v", connection.ID, connection.Provider, err)
		}
	}
}
