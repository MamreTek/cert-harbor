package catalog

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestPostgresCatalogRoundTrip(t *testing.T) {
	databaseURL := os.Getenv("CERT_HARBOR_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set CERT_HARBOR_TEST_DATABASE_URL to run the PostgreSQL integration test")
	}
	first, err := OpenStore("", databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	testID := "postgres-test-" + time.Now().UTC().Format("20060102T150405.000000000")
	if err := first.AddMember(Member{ID: testID, Email: testID + "@example.com", Name: "Postgres test", Role: "viewer", Status: "active"}); err != nil {
		_ = first.Close()
		t.Fatal(err)
	}
	if err := first.AppendAudit(AuditEvent{Actor: "test", Action: "postgres.round_trip", ObjectType: "test", ObjectID: "round-trip", Outcome: "succeeded", CreatedAt: time.Now().UTC()}); err != nil {
		_ = first.Close()
		t.Fatal(err)
	}
	backend := first.StateBackend()
	if backend == nil {
		_ = first.Close()
		t.Fatal("postgres store did not expose a shared state backend")
	}
	if err := backend.SaveState("integration-test", []byte(`{"state":"durable"}`)); err != nil {
		_ = first.Close()
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	second, err := OpenStore("", databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()
	foundMember := false
	for _, member := range second.ListMembers() {
		if member.ID == testID {
			foundMember = true
		}
	}
	if !foundMember {
		t.Fatalf("restored members did not contain %q: %#v", testID, second.ListMembers())
	}
	if events := second.ListAuditEvents(); len(events) != 1 || events[0].Action != "postgres.round_trip" {
		t.Fatalf("restored audit events = %#v", events)
	}
	state, err := second.StateBackend().LoadState("integration-test")
	var decodedState struct {
		State string `json:"state"`
	}
	if err != nil || json.Unmarshal(state, &decodedState) != nil || decodedState.State != "durable" {
		t.Fatalf("restored shared state = %s err=%v", state, err)
	}
}
