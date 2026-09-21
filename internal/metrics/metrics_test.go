package metrics

import (
	"strings"
	"testing"
)

func TestRenderIncludesCountersAndInventoryGauges(t *testing.T) {
	metrics := New()
	metrics.Inc("sync_runs_total")
	metrics.Inc("notification_failures_total")
	metrics.Inc("provider_errors_total")
	metrics.ObserveDuration("sync", 1.25)
	output := metrics.Render(map[string]int{"domains": 2}, 3, 1)
	for _, expected := range []string{
		"certharbor_sync_runs_total 1",
		"certharbor_notification_failures_total 1",
		"certharbor_provider_errors_total 1",
		"certharbor_sync_duration_seconds_sum 1.250000",
		"certharbor_sync_duration_seconds_count 1",
		`certharbor_inventory{kind="domains"} 2`,
		`certharbor_inventory{kind="open_alerts"} 3`,
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("metrics output missing %q:\n%s", expected, output)
		}
	}
}
