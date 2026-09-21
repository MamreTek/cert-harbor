package domain

import "time"

type Domain struct {
	ID                string     `json:"id"`
	ConnectionID      string     `json:"connection_id"`
	Provider          string     `json:"provider"`
	SourceID          string     `json:"source_id"`
	Name              string     `json:"name"`
	RegistrableDomain string     `json:"registrable_domain,omitempty"`
	Zone              string     `json:"zone,omitempty"`
	Registrar         string     `json:"registrar,omitempty"`
	Status            string     `json:"status,omitempty"`
	Nameservers       []string   `json:"nameservers,omitempty"`
	ExpiresAt         *time.Time `json:"expires_at,omitempty"`
	ExpiryState       string     `json:"expiry_state,omitempty"`
	Owner             string     `json:"owner,omitempty"`
	Environment       string     `json:"environment,omitempty"`
	Tags              []string   `json:"tags,omitempty"`
	Notes             string     `json:"notes,omitempty"`
	LastSeenAt        time.Time  `json:"last_seen_at"`
	Stale             bool       `json:"stale"`
	SourceURL         string     `json:"source_url,omitempty"`
}

type Certificate struct {
	ID              string    `json:"id"`
	ConnectionID    string    `json:"connection_id"`
	Provider        string    `json:"provider"`
	SourceID        string    `json:"source_id"`
	CommonName      string    `json:"common_name"`
	SANs            []string  `json:"sans,omitempty"`
	Issuer          string    `json:"issuer,omitempty"`
	Status          string    `json:"status,omitempty"`
	SerialNumber    string    `json:"serial_number,omitempty"`
	Fingerprint     string    `json:"fingerprint,omitempty"`
	CertificateType string    `json:"certificate_type,omitempty"`
	LinkedDomains   []string  `json:"linked_domains,omitempty"`
	ValidFrom       time.Time `json:"valid_from"`
	ValidTo         time.Time `json:"valid_to"`
	ExpiryState     string    `json:"expiry_state,omitempty"`
	Region          string    `json:"region,omitempty"`
	Owner           string    `json:"owner,omitempty"`
	Environment     string    `json:"environment,omitempty"`
	Tags            []string  `json:"tags,omitempty"`
	Notes           string    `json:"notes,omitempty"`
	LastSeenAt      time.Time `json:"last_seen_at"`
	Stale           bool      `json:"stale"`
	SourceURL       string    `json:"source_url,omitempty"`
}
