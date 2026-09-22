package main

import (
	"testing"

	"github.com/MamreTek/cert-harbor/internal/catalog"
	"github.com/MamreTek/cert-harbor/internal/notifications"
)

func TestRecordNotificationDeliveriesUsesDeliveryCorrelationID(t *testing.T) {
	store := catalog.NewStore()
	recordNotificationDeliveries(store, []notifications.Delivery{{
		ID:            "delivery-1",
		CorrelationID: "corr-delivery-1",
		Status:        "delivered",
	}})

	events := store.ListAuditEvents()
	if len(events) != 1 {
		t.Fatalf("expected one notification audit event, got %d", len(events))
	}
	if events[0].CorrelationID != "corr-delivery-1" {
		t.Fatalf("expected delivery correlation ID to be preserved, got %q", events[0].CorrelationID)
	}
}
