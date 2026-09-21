package metrics

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

type Metrics struct {
	mu              sync.RWMutex
	counters        map[string]uint64
	durationSeconds map[string]float64
	durationCounts  map[string]uint64
}

func New() *Metrics {
	return &Metrics{counters: make(map[string]uint64), durationSeconds: make(map[string]float64), durationCounts: make(map[string]uint64)}
}

func (m *Metrics) Inc(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counters[name]++
}

// ObserveDuration records a duration in seconds for a named operation.
func (m *Metrics) ObserveDuration(name string, seconds float64) {
	if seconds < 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.durationSeconds[name] += seconds
	m.durationCounts[name]++
}

func (m *Metrics) Snapshot() map[string]uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	items := make(map[string]uint64, len(m.counters))
	for name, value := range m.counters {
		items[name] = value
	}
	return items
}

func (m *Metrics) Render(summary map[string]int, openAlerts, staleConnections int) string {
	counters := m.Snapshot()
	var builder strings.Builder
	builder.WriteString("# TYPE certharbor_sync_runs_total counter\n")
	builder.WriteString(fmt.Sprintf("certharbor_sync_runs_total %d\n", counters["sync_runs_total"]))
	builder.WriteString("# TYPE certharbor_sync_failures_total counter\n")
	builder.WriteString(fmt.Sprintf("certharbor_sync_failures_total %d\n", counters["sync_failures_total"]))
	builder.WriteString("# TYPE certharbor_provider_errors_total counter\n")
	builder.WriteString(fmt.Sprintf("certharbor_provider_errors_total %d\n", counters["provider_errors_total"]))
	builder.WriteString("# TYPE certharbor_sync_duration_seconds summary\n")
	builder.WriteString(fmt.Sprintf("certharbor_sync_duration_seconds_sum %f\n", m.durationSecondsFor("sync")))
	builder.WriteString(fmt.Sprintf("certharbor_sync_duration_seconds_count %d\n", m.durationCountFor("sync")))
	builder.WriteString("# TYPE certharbor_notification_deliveries_total counter\n")
	builder.WriteString(fmt.Sprintf("certharbor_notification_deliveries_total %d\n", counters["notification_deliveries_total"]))
	builder.WriteString("# TYPE certharbor_notification_failures_total counter\n")
	builder.WriteString(fmt.Sprintf("certharbor_notification_failures_total %d\n", counters["notification_failures_total"]))
	values := map[string]int{"domains": summary["domains"], "certificates": summary["certificates"], "connections": summary["connections"], "stale_assets": summary["stale_assets"], "open_alerts": openAlerts, "stale_connections": staleConnections}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	builder.WriteString("# TYPE certharbor_inventory gauge\n")
	for _, key := range keys {
		builder.WriteString(fmt.Sprintf("certharbor_inventory{kind=%q} %d\n", key, values[key]))
	}
	return builder.String()
}

func (m *Metrics) durationSecondsFor(name string) float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.durationSeconds[name]
}

func (m *Metrics) durationCountFor(name string) uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.durationCounts[name]
}
