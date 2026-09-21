package catalog

import (
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/MamreTek/cert-harbor/internal/domain"
	"github.com/MamreTek/cert-harbor/internal/providers"
)

type Connection struct {
	ID                    string                 `json:"id"`
	Name                  string                 `json:"name"`
	Provider              providers.Provider     `json:"provider"`
	Enabled               bool                   `json:"enabled"`
	Source                string                 `json:"source"`
	FixturePath           string                 `json:"-"`
	Capabilities          providers.Capabilities `json:"capabilities"`
	Status                string                 `json:"status"`
	LastSyncAt            *time.Time             `json:"last_sync_at,omitempty"`
	LastSyncError         string                 `json:"last_sync_error,omitempty"`
	CredentialsStored     bool                   `json:"credentials_stored"`
	CredentialsCiphertext string                 `json:"-"`
}

type SyncRun struct {
	ID            string    `json:"id"`
	ConnectionID  string    `json:"connection_id"`
	Provider      string    `json:"provider"`
	StartedAt     time.Time `json:"started_at"`
	FinishedAt    time.Time `json:"finished_at,omitempty"`
	Status        string    `json:"status"`
	Domains       int       `json:"domains"`
	Certificates  int       `json:"certificates"`
	ErrorSummary  string    `json:"error_summary,omitempty"`
	CorrelationID string    `json:"correlation_id"`
}

type AuditEvent struct {
	ID            string    `json:"id"`
	Actor         string    `json:"actor"`
	Action        string    `json:"action"`
	ObjectType    string    `json:"object_type"`
	ObjectID      string    `json:"object_id"`
	Outcome       string    `json:"outcome"`
	CorrelationID string    `json:"correlation_id"`
	CreatedAt     time.Time `json:"created_at"`
}

type Workspace struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

type Member struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Filter struct {
	Search        string
	Provider      string
	Owner         string
	Environment   string
	Status        string
	ExpiryState   string
	Tag           string
	Stale         *bool
	ExpiresBefore *time.Time
	ExpiresAfter  *time.Time
	Sort          string
	SortDesc      bool
	Page          int
	PageSize      int
}

type Store struct {
	mu           sync.RWMutex
	domains      map[string]domain.Domain
	certificates map[string]domain.Certificate
	connections  map[string]Connection
	syncRuns     []SyncRun
	auditEvents  []AuditEvent
	workspace    Workspace
	members      map[string]Member
	active       map[string]bool
	filePath     string
	database     database
}

type database interface {
	Close() error
}

func NewStore() *Store {
	now := time.Now().UTC()
	return &Store{
		domains:      make(map[string]domain.Domain),
		certificates: make(map[string]domain.Certificate),
		connections:  make(map[string]Connection),
		workspace:    Workspace{ID: "default", Name: "CertHarbor", CreatedAt: now},
		members:      map[string]Member{"local-admin": {ID: "local-admin", Email: "admin@localhost", Name: "Local administrator", Role: "administrator", Status: "active", CreatedAt: now, UpdatedAt: now}},
		active:       make(map[string]bool),
	}
}

// Close releases an optional external persistence connection.
func (s *Store) Close() error {
	if s.database == nil {
		return nil
	}
	return s.database.Close()
}

func (s *Store) Workspace() Workspace {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.workspace
}

func (s *Store) ListMembers() []Member {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]Member, 0, len(s.members))
	for _, member := range s.members {
		items = append(items, member)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Email < items[j].Email })
	return items
}

func (s *Store) AddMember(member Member) error {
	if member.ID == "" || member.Email == "" || member.Name == "" {
		return errors.New("member id, email, and name are required")
	}
	if member.Role != "administrator" && member.Role != "viewer" {
		return errors.New("member role must be administrator or viewer")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.members[member.ID]; exists {
		return errors.New("member already exists")
	}
	now := time.Now().UTC()
	if member.Status == "" {
		member.Status = "invited"
	}
	if member.CreatedAt.IsZero() {
		member.CreatedAt = now
	}
	member.UpdatedAt = now
	s.members[member.ID] = member
	return s.persistLocked()
}

func (s *Store) UpdateMember(id, name, role, status string) (Member, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	member, ok := s.members[id]
	if !ok {
		return Member{}, errors.New("member not found")
	}
	if name != "" {
		member.Name = name
	}
	if role != "" && role != "administrator" && role != "viewer" {
		return Member{}, errors.New("member role must be administrator or viewer")
	}
	if role != "" {
		if member.Role == "administrator" && role != "administrator" && s.adminCountLocked() == 1 {
			return Member{}, errors.New("workspace must retain an administrator")
		}
		member.Role = role
	}
	if status != "" {
		if status != "active" && status != "invited" && status != "suspended" {
			return Member{}, errors.New("member status must be active, invited, or suspended")
		}
		member.Status = status
	}
	member.UpdatedAt = time.Now().UTC()
	s.members[id] = member
	if err := s.persistLocked(); err != nil {
		return Member{}, err
	}
	return member, nil
}

func (s *Store) DeleteMember(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	member, ok := s.members[id]
	if !ok {
		return errors.New("member not found")
	}
	if member.Role == "administrator" && s.adminCountLocked() == 1 {
		return errors.New("workspace must retain an administrator")
	}
	delete(s.members, id)
	return s.persistLocked()
}

func (s *Store) adminCountLocked() int {
	count := 0
	for _, member := range s.members {
		if member.Role == "administrator" && member.Status != "suspended" {
			count++
		}
	}
	return count
}

func (s *Store) AddConnection(connection Connection) error {
	if connection.ID == "" || connection.Name == "" || connection.Provider == "" {
		return errors.New("connection id, name, and provider are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.connections[connection.ID]; exists {
		return errors.New("connection already exists")
	}
	if connection.Status == "" {
		connection.Status = "pending"
	}
	s.connections[connection.ID] = connection
	return s.persistLocked()
}

func (s *Store) GetConnection(id string) (Connection, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	connection, ok := s.connections[id]
	return connection, ok
}

func (s *Store) UpdateConnection(id, name string, enabled bool) (Connection, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	connection, ok := s.connections[id]
	if !ok {
		return Connection{}, errors.New("connection not found")
	}
	if name != "" {
		connection.Name = name
	}
	connection.Enabled = enabled
	s.connections[id] = connection
	if err := s.persistLocked(); err != nil {
		return Connection{}, err
	}
	return connection, nil
}

func (s *Store) DeleteConnection(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.connections[id]; !ok {
		return errors.New("connection not found")
	}
	delete(s.connections, id)
	for assetID, item := range s.domains {
		if item.ConnectionID == id {
			delete(s.domains, assetID)
		}
	}
	for assetID, item := range s.certificates {
		if item.ConnectionID == id {
			delete(s.certificates, assetID)
		}
	}
	return s.persistLocked()
}

func (s *Store) SetCredentials(id, ciphertext string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	connection, ok := s.connections[id]
	if !ok {
		return errors.New("connection not found")
	}
	connection.CredentialsCiphertext = ciphertext
	connection.CredentialsStored = ciphertext != ""
	s.connections[id] = connection
	return s.persistLocked()
}

func (s *Store) ListConnections() []Connection {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]Connection, 0, len(s.connections))
	for _, connection := range s.connections {
		items = append(items, connection)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	return items
}

func (s *Store) BeginSync(connectionID string, provider providers.Provider, now time.Time) (SyncRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	connection, ok := s.connections[connectionID]
	if !ok {
		return SyncRun{}, errors.New("connection not found")
	}
	if !connection.Enabled {
		return SyncRun{}, errors.New("connection is disabled")
	}
	if s.active[connectionID] {
		return SyncRun{}, errors.New("a sync is already running for this connection")
	}
	s.active[connectionID] = true
	connection.Status = "syncing"
	connection.LastSyncError = ""
	s.connections[connectionID] = connection
	run := SyncRun{
		ID:            "sync-" + now.Format("20060102T150405.000000000Z"),
		ConnectionID:  connectionID,
		Provider:      string(provider),
		StartedAt:     now,
		Status:        "running",
		CorrelationID: "corr-" + now.Format("20060102T150405.000000000Z"),
	}
	s.syncRuns = append(s.syncRuns, run)
	if err := s.persistLocked(); err != nil {
		s.active[connectionID] = false
		return SyncRun{}, err
	}
	return run, nil
}

func (s *Store) FinishSync(runID string, success bool, now time.Time, domains, certificates int, summary string) (SyncRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.syncRuns {
		if s.syncRuns[i].ID != runID {
			continue
		}
		run := &s.syncRuns[i]
		run.FinishedAt = now
		run.Domains = domains
		run.Certificates = certificates
		run.ErrorSummary = summary
		connection := s.connections[run.ConnectionID]
		if success {
			run.Status = "succeeded"
			connection.Status = "healthy"
			connection.LastSyncAt = &now
			connection.LastSyncError = ""
		} else {
			run.Status = "failed"
			connection.Status = "unhealthy"
			connection.LastSyncError = summary
		}
		s.connections[run.ConnectionID] = connection
		s.active[run.ConnectionID] = false
		if err := s.persistLocked(); err != nil {
			return SyncRun{}, err
		}
		return *run, nil
	}
	return SyncRun{}, errors.New("sync run not found")
}

func (s *Store) ReplaceAssets(connectionID string, syncedAt time.Time, domains []domain.Domain, certificates []domain.Certificate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	domainIDs := make(map[string]bool, len(domains))
	for _, item := range domains {
		domainIDs[item.ID] = true
		s.domains[item.ID] = item
	}
	certificateIDs := make(map[string]bool, len(certificates))
	for _, item := range certificates {
		certificateIDs[item.ID] = true
		s.certificates[item.ID] = item
	}
	for id, item := range s.domains {
		if item.ConnectionID == connectionID && !domainIDs[id] {
			item.Stale = true
			s.domains[id] = item
		}
	}
	for id, item := range s.certificates {
		if item.ConnectionID == connectionID && !certificateIDs[id] {
			item.Stale = true
			s.certificates[id] = item
		}
	}
	_ = syncedAt
	return s.persistLocked()
}

func (s *Store) ListDomains(filter Filter) ([]domain.Domain, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]domain.Domain, 0, len(s.domains))
	for _, item := range s.domains {
		if matchesDomain(filter, item) {
			items = append(items, item)
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if filter.Sort == "expires_at" {
			return beforeOrAfter(items[i].ExpiresAt, items[j].ExpiresAt, filter.SortDesc)
		}
		if filter.Sort == "last_seen_at" {
			return timeBeforeOrAfter(items[i].LastSeenAt, items[j].LastSeenAt, filter.SortDesc)
		}
		if filter.SortDesc {
			return items[i].Name > items[j].Name
		}
		return items[i].Name < items[j].Name
	})
	return paginate(items, filter)
}

// ListAllDomains returns every domain that is currently known to the catalog.
// Background monitoring uses this method so alert evaluation is not capped by
// the API's page-size limit.
func (s *Store) ListAllDomains() []domain.Domain {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]domain.Domain, 0, len(s.domains))
	for _, item := range s.domains {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	return items
}

func (s *Store) GetDomain(id string) (domain.Domain, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, ok := s.domains[id]
	return item, ok
}

func (s *Store) ListCertificates(filter Filter) ([]domain.Certificate, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]domain.Certificate, 0, len(s.certificates))
	for _, item := range s.certificates {
		if matchesCertificate(filter, item) {
			items = append(items, item)
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if filter.Sort == "expires_at" {
			return timeBeforeOrAfter(items[i].ValidTo, items[j].ValidTo, filter.SortDesc)
		}
		if filter.Sort == "last_seen_at" {
			return timeBeforeOrAfter(items[i].LastSeenAt, items[j].LastSeenAt, filter.SortDesc)
		}
		if filter.SortDesc {
			return items[i].CommonName > items[j].CommonName
		}
		return items[i].CommonName < items[j].CommonName
	})
	return paginate(items, filter)
}

// ListAllCertificates returns every certificate that is currently known to the
// catalog. Background monitoring uses this method so alert evaluation is not
// capped by the API's page-size limit.
func (s *Store) ListAllCertificates() []domain.Certificate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]domain.Certificate, 0, len(s.certificates))
	for _, item := range s.certificates {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].CommonName < items[j].CommonName })
	return items
}

func (s *Store) GetCertificate(id string) (domain.Certificate, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, ok := s.certificates[id]
	return item, ok
}

func (s *Store) ListSyncRuns() []SyncRun {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := append([]SyncRun(nil), s.syncRuns...)
	sort.Slice(items, func(i, j int) bool { return items[i].StartedAt.After(items[j].StartedAt) })
	return items
}

func (s *Store) AppendAudit(event AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if event.ID == "" {
		event.ID = "audit-" + time.Now().UTC().Format("20060102T150405.000000000Z")
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	s.auditEvents = append(s.auditEvents, event)
	return s.persistLocked()
}

func (s *Store) ListAuditEvents() []AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := append([]AuditEvent(nil), s.auditEvents...)
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.After(items[j].CreatedAt) })
	return items
}

func (s *Store) Summary() map[string]int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	openStale := 0
	for _, item := range s.domains {
		if item.Stale {
			openStale++
		}
	}
	for _, item := range s.certificates {
		if item.Stale {
			openStale++
		}
	}
	return map[string]int{
		"domains":      len(s.domains),
		"certificates": len(s.certificates),
		"connections":  len(s.connections),
		"stale_assets": openStale,
	}
}

func matches(filter Filter, provider, name, owner, environment string, stale bool, tags []string, expiresAt *time.Time) bool {
	if filter.Provider != "" && !strings.EqualFold(filter.Provider, provider) {
		return false
	}
	if filter.Owner != "" && !strings.EqualFold(filter.Owner, owner) {
		return false
	}
	if filter.Environment != "" && !strings.EqualFold(filter.Environment, environment) {
		return false
	}
	if filter.Stale != nil && *filter.Stale != stale {
		return false
	}
	if filter.Tag != "" && !containsFold(tags, filter.Tag) {
		return false
	}
	if filter.ExpiresBefore != nil && (expiresAt == nil || expiresAt.After(*filter.ExpiresBefore)) {
		return false
	}
	if filter.ExpiresAfter != nil && (expiresAt == nil || expiresAt.Before(*filter.ExpiresAfter)) {
		return false
	}
	if filter.ExpiryState != "" && !strings.EqualFold(filter.ExpiryState, expiryState(expiresAt, stale)) {
		return false
	}
	return filter.Search == "" || strings.Contains(strings.ToLower(name), strings.ToLower(filter.Search))
}

func expiryState(expiresAt *time.Time, stale bool) string {
	if stale {
		return "stale"
	}
	if expiresAt == nil {
		return "unknown"
	}
	days := int(time.Until(*expiresAt) / (24 * time.Hour))
	if expiresAt.Before(time.Now().UTC()) {
		return "expired"
	}
	if days <= 90 {
		return "expiring"
	}
	return "healthy"
}

func matchesDomain(filter Filter, item domain.Domain) bool {
	return (filter.Status == "" || strings.EqualFold(filter.Status, item.Status)) && matches(filter, item.Provider, item.Name, item.Owner, item.Environment, item.Stale, item.Tags, item.ExpiresAt)
}

func matchesCertificate(filter Filter, item domain.Certificate) bool {
	return matches(filter, item.Provider, item.CommonName, item.Owner, item.Environment, item.Stale, item.Tags, &item.ValidTo)
}

func containsFold(values []string, wanted string) bool {
	for _, value := range values {
		if strings.EqualFold(value, wanted) {
			return true
		}
	}
	return false
}

func timeBeforeOrAfter(left, right time.Time, desc bool) bool {
	if desc {
		return left.After(right)
	}
	return left.Before(right)
}

func beforeOrAfter(left, right *time.Time, desc bool) bool {
	if left == nil {
		return false
	}
	if right == nil {
		return true
	}
	return timeBeforeOrAfter(*left, *right, desc)
}

func paginate[T any](items []T, filter Filter) ([]T, int) {
	total := len(items)
	page := filter.Page
	if page < 1 {
		page = 1
	}
	pageSize := filter.PageSize
	if pageSize < 1 || pageSize > 200 {
		pageSize = 50
	}
	start := (page - 1) * pageSize
	if start >= len(items) {
		return []T{}, total
	}
	end := start + pageSize
	if end > len(items) {
		end = len(items)
	}
	return items[start:end], total
}
