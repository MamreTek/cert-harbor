import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  BellOutlined,
  CloudServerOutlined,
  DashboardOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
  SettingOutlined,
} from '@ant-design/icons'
import { Alert, Button, Card, Col, Descriptions, Input, Layout, Menu, Modal, Row, Select, Space, Spin, Statistic, Table, Tag, Typography } from 'antd'

const { Header, Sider, Content } = Layout

const menuItems = [
  { key: 'overview', icon: <DashboardOutlined />, label: 'Overview' },
  { key: 'domains', icon: <CloudServerOutlined />, label: 'Domain inventory' },
  { key: 'certificates', icon: <SafetyCertificateOutlined />, label: 'Certificates' },
  { key: 'alerts', icon: <BellOutlined />, label: 'Alert center' },
  { key: 'settings', icon: <SettingOutlined />, label: 'Settings' },
]

const emptySummary = { domains: 0, certificates: 0, connections: 0, stale_assets: 0 }
const defaultFetcher = globalThis.fetch?.bind(globalThis)
const browserTimeZone = () => {
  try { return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC' } catch { return 'UTC' }
}
const timeZoneOptions = ['UTC', browserTimeZone(), 'Asia/Shanghai', 'Asia/Tokyo', 'Europe/London', 'America/New_York', 'America/Los_Angeles'].filter((value, index, values) => values.indexOf(value) === index).map((value) => ({ value, label: value }))
const formatTimestamp = (value, timeZone) => {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  try {
    return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short', timeZone }).format(date)
  } catch {
    return value
  }
}

export function App({ fetcher = defaultFetcher }) {
  const [summary, setSummary] = useState(emptySummary)
  const [connections, setConnections] = useState([])
  const [domains, setDomains] = useState([])
  const [certificates, setCertificates] = useState([])
  const [domainPage, setDomainPage] = useState(1)
  const [certificatePage, setCertificatePage] = useState(1)
  const [domainTotal, setDomainTotal] = useState(0)
  const [certificateTotal, setCertificateTotal] = useState(0)
  const [alerts, setAlerts] = useState([])
  const [alertPage, setAlertPage] = useState(1)
  const [alertTotal, setAlertTotal] = useState(0)
  const [alertFilters, setAlertFilters] = useState({ state: '', provider: '' })
  const [rules, setRules] = useState([])
  const [members, setMembers] = useState([])
  const [channels, setChannels] = useState([])
  const [syncRuns, setSyncRuns] = useState([])
  const [auditEvents, setAuditEvents] = useState([])
  const [notificationDeliveries, setNotificationDeliveries] = useState([])
  const [alertDeliveries, setAlertDeliveries] = useState([])
  const [deliveryPage, setDeliveryPage] = useState(1)
  const [deliveryTotal, setDeliveryTotal] = useState(0)
  const [alertDetail, setAlertDetail] = useState(null)
  const [deepLinkAlertID] = useState(() => {
    const match = globalThis.location?.pathname?.match(/^\/alerts\/([^/]+)$/)
    return match ? decodeURIComponent(match[1]) : ''
  })
  const [activePage, setActivePage] = useState('overview')
  const [loading, setLoading] = useState(Boolean(fetcher))
  const [syncing, setSyncing] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [inventoryFilters, setInventoryFilters] = useState({ search: '', provider: '', owner: '', environment: '', tag: '', expiry_state: '', stale: '', expires_before: '', expires_after: '', sort: '', order: '' })
  const [modalKind, setModalKind] = useState('')
  const [modalValues, setModalValues] = useState({})
  const [editingId, setEditingId] = useState('')
  const [detailItem, setDetailItem] = useState(null)
  const [detailKind, setDetailKind] = useState('')
  const [authToken, setAuthToken] = useState(() => {
    try { return globalThis.localStorage?.getItem('cert_harbor_token') || '' } catch { return '' }
  })
  const [tokenDraft, setTokenDraft] = useState(authToken)
  const [timeZone, setTimeZone] = useState(() => {
    try { return globalThis.localStorage?.getItem('cert_harbor_timezone') || browserTimeZone() } catch { return browserTimeZone() }
  })

  const requester = useCallback((url, options = {}) => {
    const headers = { ...(options.headers || {}) }
    if (authToken) headers['X-CertHarbor-Token'] = authToken
    return fetcher(url, { ...options, headers })
  }, [authToken, fetcher])

  const filterQuery = new URLSearchParams(Object.entries(inventoryFilters).filter(([, value]) => value !== '')).toString()
  const alertFilterQuery = new URLSearchParams(Object.entries(alertFilters).filter(([, value]) => value !== '')).toString()

  const loadInventory = useCallback(async () => {
    if (!fetcher) return
    setLoading(true)
    setError('')
    setNotice('')
    try {
      const responses = await Promise.all([
        requester('/api/v1/catalog/summary'),
        requester('/api/v1/provider-connections?page=1&page_size=50'),
        requester(`/api/v1/domains?page=${domainPage}&page_size=20${filterQuery ? `&${filterQuery}` : ''}`),
        requester(`/api/v1/certificates?page=${certificatePage}&page_size=20${filterQuery ? `&${filterQuery}` : ''}`),
        requester(`/api/v1/alerts?page=${alertPage}&page_size=20${alertFilterQuery ? `&${alertFilterQuery}` : ''}`),
        requester('/api/v1/alert-rules?page=1&page_size=50'),
        requester('/api/v1/members?page=1&page_size=50'),
        requester('/api/v1/notification-channels?page=1&page_size=50'),
        requester('/api/v1/sync-runs'),
        requester('/api/v1/audit-events?page=1&page_size=50'),
        requester(`/api/v1/notification-deliveries?page=${deliveryPage}&page_size=20`),
      ])
      if (responses.some((response) => !response.ok)) throw new Error('The inventory API returned an error.')
      const [nextSummary, nextConnections, nextDomains, nextCertificates, nextAlerts, nextRules, nextMembers, nextChannels, nextSyncRuns, nextAuditEvents, nextDeliveries] = await Promise.all(responses.map((response) => response.json()))
      setSummary({ ...emptySummary, ...nextSummary })
      setConnections(nextConnections.items ?? [])
      setDomains(nextDomains.items ?? [])
      setCertificates(nextCertificates.items ?? [])
      setDomainTotal(nextDomains.total ?? nextDomains.items?.length ?? 0)
      setCertificateTotal(nextCertificates.total ?? nextCertificates.items?.length ?? 0)
      setAlerts(nextAlerts.items ?? [])
      setAlertTotal(nextAlerts.total ?? nextAlerts.items?.length ?? 0)
      setRules(nextRules.items ?? [])
      setMembers(nextMembers.items ?? [])
      setChannels(nextChannels.items ?? [])
      setSyncRuns(nextSyncRuns.items ?? [])
      setAuditEvents(nextAuditEvents.items ?? [])
      setNotificationDeliveries(nextDeliveries.items ?? [])
      setDeliveryTotal(nextDeliveries.total ?? nextDeliveries.items?.length ?? 0)
    } catch (loadError) {
      setError(loadError.message || 'Unable to load inventory.')
    } finally {
      setLoading(false)
    }
  }, [alertFilterQuery, alertPage, certificatePage, deliveryPage, domainPage, fetcher, filterQuery, requester])

  useEffect(() => {
    setDomainPage(1)
    setCertificatePage(1)
  }, [filterQuery])

  useEffect(() => {
    setAlertPage(1)
  }, [alertFilterQuery])

  useEffect(() => {
    loadInventory()
  }, [loadInventory])

  useEffect(() => {
    if (!deepLinkAlertID || !fetcher) return
    setActivePage('alerts')
    requester(`/api/v1/alerts/${encodeURIComponent(deepLinkAlertID)}`)
      .then(async (response) => {
        if (!response.ok) throw new Error('Unable to load the linked alert.')
        const item = await response.json()
        if (item.id) setAlertDetail(item)
      })
      .catch((loadError) => setError(loadError.message || 'Unable to load the linked alert.'))
  }, [deepLinkAlertID, fetcher, requester])

  useEffect(() => {
    if (!alertDetail?.id || !fetcher) {
      setAlertDeliveries([])
      return
    }
    let cancelled = false
    requester(`/api/v1/notification-deliveries?alert_id=${encodeURIComponent(alertDetail.id)}&page=1&page_size=100`)
      .then(async (response) => {
        if (!response.ok) throw new Error('Unable to load alert delivery history.')
        const body = await response.json()
        if (!cancelled) setAlertDeliveries(body.items ?? [])
      })
      .catch((loadError) => {
        if (!cancelled) setError(loadError.message || 'Unable to load alert delivery history.')
      })
    return () => { cancelled = true }
  }, [alertDetail?.id, fetcher, requester])

  const syncConnection = async (connection) => {
    if (!fetcher || !connection) return
    setSyncing(true)
    setError('')
    setNotice('')
    try {
      const response = await requester(`/api/v1/provider-connections/${connection.id}/sync`, { method: 'POST' })
      const body = await response.json().catch(() => ({}))
      if (!response.ok) throw new Error(body.error || 'The provider sync failed.')
      await loadInventory()
      setNotice(`${connection.name || connection.provider} sync completed.`)
    } catch (syncError) {
      setError(syncError.message || 'Unable to synchronize the provider.')
    } finally {
      setSyncing(false)
    }
  }

  const syncNow = () => syncConnection(connections[0])

  const testConnection = async (item) => {
    setError('')
    setNotice('')
    try {
      const response = await requester(`/api/v1/provider-connections/${item.id}/test`, { method: 'POST' })
      const body = await response.json().catch(() => ({}))
      if (!response.ok) throw new Error(body.error || 'The provider connection test failed.')
      const guidance = body.capabilities?.credential_guidance
      setNotice(`Connection test passed${body.request_id ? ` (request ID: ${body.request_id})` : ''}.${guidance ? ` Required permissions: ${guidance}` : ''}`)
    } catch (testError) {
      setError(testError.message || 'The provider connection test failed.')
    }
  }

  const testNotificationChannel = async (item) => {
    setError('')
    setNotice('')
    try {
      const response = await requester(`/api/v1/notification-channels/${item.id}/test`, { method: 'POST' })
      const body = await response.json().catch(() => ({}))
      if (!response.ok) throw new Error(body.error || 'The notification channel test failed.')
      setNotice(`Notification channel test passed${body.id ? ` (delivery: ${body.id})` : ''}.`)
    } catch (testError) {
      setError(testError.message || 'The notification channel test failed.')
    }
  }

  const updateModalValue = (key, value) => setModalValues((current) => ({ ...current, [key]: value }))

  const openModal = (kind, item = {}) => {
    setModalKind(kind)
    setEditingId(item.id || '')
    setModalValues({
      enabled: item.enabled ?? true,
      role: item.role || 'viewer',
      status: item.status || 'active',
      kind: item.kind || 'webhook',
      name: item.name || '',
      provider: item.provider || '',
      endpoint: item.endpoint || '',
      sync_interval: item.sync_interval || '24h',
      domain_thresholds: (item.domain_thresholds || [90, 30, 14, 7, 3]).join(','),
      certificate_thresholds: (item.certificate_thresholds || [90, 30, 14, 7, 3]).join(','),
      stale_after_hours: String(item.stale_after_hours || 26),
      asset_types: (item.asset_types || []).join(','),
      tags: (item.tags || []).join(','),
    })
  }

  const closeModal = () => {
    setModalKind('')
    setModalValues({})
    setEditingId('')
  }

  const openDetail = (kind, item) => {
    setDetailKind(kind)
    setDetailItem(item)
  }

  const submitModal = async () => {
    if (!fetcher) return
    setError('')
    let url
    let payload
    try {
      if (modalKind === 'connection') {
        let credentials = {}
        if (modalValues.credentials) credentials = JSON.parse(modalValues.credentials)
        url = editingId ? `/api/v1/provider-connections/${editingId}` : '/api/v1/provider-connections'
        payload = { name: modalValues.name, sync_interval: modalValues.sync_interval, enabled: modalValues.enabled }
        if (!editingId) Object.assign(payload, { provider: modalValues.provider, credentials })
        else if (modalValues.credentials) payload.credentials = credentials
      } else if (modalKind === 'member') {
        url = editingId ? `/api/v1/members/${editingId}` : '/api/v1/members'
        payload = editingId ? { name: modalValues.name, role: modalValues.role, status: modalValues.status } : { email: modalValues.email, name: modalValues.name, role: modalValues.role }
      } else if (modalKind === 'channel') {
        let credentials = {}
        if (modalValues.credentials) credentials = JSON.parse(modalValues.credentials)
        url = editingId ? `/api/v1/notification-channels/${editingId}` : '/api/v1/notification-channels'
        payload = { name: modalValues.name, endpoint: modalValues.endpoint, enabled: modalValues.enabled }
        if (!editingId) Object.assign(payload, { kind: modalValues.kind, signing_secret: modalValues.signing_secret, credentials })
        else {
          if (modalValues.signing_secret) payload.signing_secret = modalValues.signing_secret
          if (modalValues.credentials) payload.credentials = credentials
        }
      } else if (modalKind === 'rule') {
        url = editingId ? `/api/v1/alert-rules/${editingId}` : '/api/v1/alert-rules'
        payload = { name: modalValues.name, domain_thresholds: String(modalValues.domain_thresholds).split(',').map(Number).filter(Number.isFinite), certificate_thresholds: String(modalValues.certificate_thresholds).split(',').map(Number).filter(Number.isFinite), stale_after_hours: Number(modalValues.stale_after_hours), asset_types: modalValues.asset_types ? String(modalValues.asset_types).split(',').map((value) => value.trim()).filter(Boolean) : [], tags: modalValues.tags ? String(modalValues.tags).split(',').map((value) => value.trim()).filter(Boolean) : [] }
      }
      const response = await requester(url, { method: editingId ? 'PATCH' : 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) })
      if (!response.ok) {
        const body = await response.json().catch(() => ({}))
        throw new Error(body.error || 'The requested change failed.')
      }
      closeModal()
      await loadInventory()
    } catch (mutationError) {
      setError(mutationError.message || 'The requested change failed.')
    }
  }

  const toggleConnection = async (item) => {
    const response = await requester(`/api/v1/provider-connections/${item.id}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled: !item.enabled }) })
    if (!response.ok) setError('Unable to update provider connection.')
    await loadInventory()
  }

  const deleteResource = async (url, message) => {
    if (!globalThis.confirm || globalThis.confirm(message)) {
      const response = await requester(url, { method: 'DELETE' })
      if (!response.ok) setError('Unable to delete the selected resource.')
      await loadInventory()
    }
  }

  const alertAction = async (id, action) => {
    const response = await requester(`/api/v1/alerts/${id}/${action}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ actor: 'administrator' }) })
    if (!response.ok) setError(`Unable to ${action} the alert.`)
    await loadInventory()
  }

  const rows = useMemo(() => [
    ...domains.map((item) => ({ key: item.id, asset: item.name, type: 'Domain', provider: item.provider, state: item.stale ? 'Stale' : 'Healthy', lastSync: item.last_seen_at })),
    ...certificates.map((item) => ({ key: item.id, asset: item.common_name, type: 'Certificate', provider: item.provider, state: item.stale ? 'Stale' : 'Healthy', lastSync: item.last_seen_at })),
  ], [certificates, domains])

  const overviewColumns = [
    { title: 'Asset', dataIndex: 'asset', key: 'asset' },
    { title: 'Type', dataIndex: 'type', key: 'type' },
    { title: 'Provider', dataIndex: 'provider', key: 'provider' },
    { title: 'State', dataIndex: 'state', key: 'state', render: (state) => <Tag color={state === 'Stale' ? 'orange' : 'green'}>{state}</Tag> },
    { title: 'Last sync', dataIndex: 'lastSync', key: 'lastSync', render: (value) => formatTimestamp(value, timeZone) },
  ]

  const renderInventoryFilters = () => <Space wrap className="inventory-filters">
    <Input.Search placeholder="Search inventory" allowClear onSearch={(value) => setInventoryFilters((current) => ({ ...current, search: value }))} onChange={(event) => { if (!event.target.value) setInventoryFilters((current) => ({ ...current, search: '' })) }} />
    <Select allowClear placeholder="Provider" style={{ minWidth: 150 }} value={inventoryFilters.provider || undefined} onChange={(value) => setInventoryFilters((current) => ({ ...current, provider: value || '' }))} options={connections.map((item) => ({ value: item.provider, label: item.provider }))} />
    <Input placeholder="Owner / team" allowClear value={inventoryFilters.owner} onChange={(event) => setInventoryFilters((current) => ({ ...current, owner: event.target.value }))} />
    <Input placeholder="Environment" allowClear value={inventoryFilters.environment} onChange={(event) => setInventoryFilters((current) => ({ ...current, environment: event.target.value }))} />
    <Input placeholder="Tag" allowClear value={inventoryFilters.tag} onChange={(event) => setInventoryFilters((current) => ({ ...current, tag: event.target.value }))} />
    <Select allowClear placeholder="Expiry state" style={{ minWidth: 150 }} value={inventoryFilters.expiry_state || undefined} onChange={(value) => setInventoryFilters((current) => ({ ...current, expiry_state: value || '' }))} options={['healthy', 'expiring', 'expired', 'revoked', 'invalid', 'stale', 'unknown'].map((value) => ({ value, label: value }))} />
    <Select allowClear placeholder="Freshness" style={{ minWidth: 130 }} value={inventoryFilters.stale || undefined} onChange={(value) => setInventoryFilters((current) => ({ ...current, stale: value || '' }))} options={[{ value: 'false', label: 'Current' }, { value: 'true', label: 'Stale' }]} />
    <Input placeholder="Expires before (UTC)" allowClear value={inventoryFilters.expires_before} onChange={(event) => setInventoryFilters((current) => ({ ...current, expires_before: event.target.value }))} />
    <Input placeholder="Expires after (UTC)" allowClear value={inventoryFilters.expires_after} onChange={(event) => setInventoryFilters((current) => ({ ...current, expires_after: event.target.value }))} />
    <Select allowClear placeholder="Sort by" style={{ minWidth: 145 }} value={inventoryFilters.sort || undefined} onChange={(value) => setInventoryFilters((current) => ({ ...current, sort: value || '' }))} options={[{ value: 'expires_at', label: 'Expiration' }, { value: 'last_seen_at', label: 'Freshness' }, { value: 'name', label: 'Name' }]} />
    <Select allowClear placeholder="Order" style={{ minWidth: 110 }} value={inventoryFilters.order || undefined} onChange={(value) => setInventoryFilters((current) => ({ ...current, order: value || '' }))} options={[{ value: 'asc', label: 'Ascending' }, { value: 'desc', label: 'Descending' }]} />
  </Space>

  const pageTitle = {
    overview: 'Overview',
    domains: 'Domain inventory',
    certificates: 'Certificates',
    alerts: 'Alert center',
    settings: 'Workspace settings',
  }[activePage]

  const renderOverview = () => <>
    <Row gutter={[16, 16]}>
      <Col xs={24} sm={12} lg={6}><Card><Statistic title="Domains" value={summary.domains} /></Card></Col>
      <Col xs={24} sm={12} lg={6}><Card><Statistic title="Certificates" value={summary.certificates} /></Card></Col>
      <Col xs={24} sm={12} lg={6}><Card><Statistic title="Stale assets" value={summary.stale_assets} /></Card></Col>
      <Col xs={24} sm={12} lg={6}><Card><Statistic title="Open alerts" value={summary.open_alerts ?? alerts.filter((item) => item.state === 'open' || item.state === 'acknowledged').length} /></Card></Col>
    </Row>
    <Card title="Inventory" className="inventory-card">
      <Table columns={overviewColumns} dataSource={rows.length ? rows : [{ key: 'empty', asset: 'No assets synchronized yet', type: '—', provider: '—', state: 'Ready', lastSync: 'Run your first sync' }]} pagination={false} />
    </Card>
  </>

  const renderDomains = () => <Card title="Domains" extra={renderInventoryFilters()}>
    <Table rowKey="id" dataSource={domains} pagination={{ current: domainPage, pageSize: 20, total: domainTotal, showSizeChanger: false, onChange: setDomainPage }} locale={{ emptyText: 'No domains synchronized yet' }} columns={[
      { title: 'Domain', dataIndex: 'name', key: 'name' },
      { title: 'Provider', dataIndex: 'provider', key: 'provider' },
      { title: 'Status', dataIndex: 'status', key: 'status', render: (value) => value || 'Unknown' },
      { title: 'Expiry state', dataIndex: 'expiry_state', key: 'expiry_state', render: (value) => value || 'Unknown' },
      { title: 'Nameservers', dataIndex: 'nameservers', key: 'nameservers', render: (value) => (value ?? []).join(', ') || 'Unknown' },
      { title: 'Last seen', dataIndex: 'last_seen_at', key: 'last_seen_at', render: (value) => formatTimestamp(value, timeZone) },
      { title: 'Freshness', dataIndex: 'stale', key: 'stale', render: (value) => <Tag color={value ? 'orange' : 'green'}>{value ? 'Stale' : 'Current'}</Tag> },
      { title: 'Details', render: (_, item) => <Button size="small" onClick={() => openDetail('Domain', item)}>View</Button> },
    ]} />
  </Card>

  const renderCertificates = () => <Card title="Certificates" extra={renderInventoryFilters()}>
    <Table rowKey="id" dataSource={certificates} pagination={{ current: certificatePage, pageSize: 20, total: certificateTotal, showSizeChanger: false, onChange: setCertificatePage }} locale={{ emptyText: 'No certificates synchronized yet' }} columns={[
      { title: 'Common name', dataIndex: 'common_name', key: 'common_name' },
      { title: 'Issuer', dataIndex: 'issuer', key: 'issuer', render: (value) => value || 'Unknown' },
      { title: 'Status', dataIndex: 'status', key: 'status', render: (value) => value || 'Unknown' },
      { title: 'Expiry state', dataIndex: 'expiry_state', key: 'expiry_state', render: (value) => value || 'Unknown' },
      { title: 'Valid to', dataIndex: 'valid_to', key: 'valid_to', render: (value) => formatTimestamp(value, timeZone) },
      { title: 'Region', dataIndex: 'region', key: 'region', render: (value) => value || '—' },
      { title: 'Provider', dataIndex: 'provider', key: 'provider' },
      { title: 'Freshness', dataIndex: 'stale', key: 'stale', render: (value) => <Tag color={value ? 'orange' : 'green'}>{value ? 'Stale' : 'Current'}</Tag> },
      { title: 'Details', render: (_, item) => <Button size="small" onClick={() => openDetail('Certificate', item)}>View</Button> },
    ]} />
  </Card>

  const renderAlerts = () => <Card title="Alerts" extra={<Space><Select allowClear placeholder="State" style={{ minWidth: 130 }} value={alertFilters.state || undefined} onChange={(value) => setAlertFilters((current) => ({ ...current, state: value || '' }))} options={['open', 'acknowledged', 'resolved', 'suppressed'].map((value) => ({ value, label: value }))} /><Select allowClear placeholder="Provider" style={{ minWidth: 150 }} value={alertFilters.provider || undefined} onChange={(value) => setAlertFilters((current) => ({ ...current, provider: value || '' }))} options={connections.map((item) => ({ value: item.provider, label: item.provider }))} /></Space>}>
    <Table rowKey="id" dataSource={alerts} pagination={{ current: alertPage, pageSize: 20, total: alertTotal, showSizeChanger: false, onChange: setAlertPage }} locale={{ emptyText: 'No alerts' }} columns={[
      { title: 'Asset', dataIndex: 'asset_name', key: 'asset_name' },
      { title: 'Type', dataIndex: 'asset_kind', key: 'asset_kind' },
      { title: 'State', dataIndex: 'state', key: 'state', render: (value) => <Tag color={value === 'open' ? 'red' : value === 'acknowledged' ? 'gold' : 'green'}>{value}</Tag> },
      { title: 'Severity', dataIndex: 'severity', key: 'severity' },
      { title: 'Days remaining', dataIndex: 'days_remaining', key: 'days_remaining', render: (value) => value ?? '—' },
      { title: 'Provider', dataIndex: 'provider', key: 'provider' },
      { title: 'Updated', dataIndex: 'updated_at', key: 'updated_at', render: (value) => formatTimestamp(value, timeZone) },
      { title: 'Source', render: (_, item) => item.source_url ? <a href={item.source_url} target="_blank" rel="noreferrer">Provider</a> : 'Unavailable' },
      { title: 'Details', render: (_, item) => <Button size="small" onClick={() => setAlertDetail(item)}>View</Button> },
      { title: 'Actions', render: (_, item) => <Space>
        {item.state === 'open' && <Button size="small" onClick={() => alertAction(item.id, 'acknowledge')}>Acknowledge</Button>}
        {item.state !== 'resolved' && <Button size="small" onClick={() => alertAction(item.id, 'resolve')}>Resolve</Button>}
        {(item.state === 'open' || item.state === 'acknowledged') && <Button size="small" onClick={() => alertAction(item.id, 'suppress')}>Suppress</Button>}
        {item.state !== 'resolved' && item.state !== 'suppressed' && <Button size="small" onClick={() => alertAction(item.id, 'notify')}>Notify</Button>}
      </Space> },
    ]} />
  </Card>

  const renderSettings = () => <>
    <Row gutter={[16, 16]}>
      <Col xs={24} lg={8}><Card title="Provider connections" extra={<Button size="small" onClick={() => openModal('connection')}>Add</Button>}><Table rowKey="id" size="small" pagination={false} dataSource={connections} columns={[{ title: 'Name', dataIndex: 'name' }, { title: 'Provider', dataIndex: 'provider' }, { title: 'Status', dataIndex: 'status' }, { title: 'Capabilities', dataIndex: 'capabilities', render: (value) => value?.supported_source_types?.join(', ') || 'Unknown' }, { title: 'Last sync', dataIndex: 'last_sync_at', render: (value) => value ? formatTimestamp(value, timeZone) : 'Never' }, { title: 'Schedule', dataIndex: 'sync_interval' }, { title: 'Next sync', dataIndex: 'next_sync_at', render: (value, item) => value ? formatTimestamp(value, timeZone) : item.last_sync_error || 'Waiting for scheduler' }, { title: 'Actions', render: (_, item) => <Space><Button size="small" onClick={() => syncConnection(item)} loading={syncing}>Sync</Button><Button size="small" onClick={() => testConnection(item)}>Test</Button><Button size="small" onClick={() => openModal('connection', item)}>Edit</Button><Button size="small" onClick={() => toggleConnection(item)}>{item.enabled ? 'Disable' : 'Enable'}</Button><Button size="small" danger onClick={() => deleteResource(`/api/v1/provider-connections/${item.id}`, 'Delete this provider connection?')}>Delete</Button></Space> }]} /></Card></Col>
      <Col xs={24} lg={8}><Card title="Members" extra={<Button size="small" onClick={() => openModal('member')}>Invite</Button>}><Table rowKey="id" size="small" pagination={false} dataSource={members} columns={[{ title: 'Email', dataIndex: 'email' }, { title: 'Role', dataIndex: 'role' }, { title: 'Status', dataIndex: 'status' }, { title: 'Actions', render: (_, item) => <Space><Button size="small" onClick={() => openModal('member', item)}>Edit</Button><Button size="small" danger onClick={() => deleteResource(`/api/v1/members/${item.id}`, 'Remove this member?')}>Remove</Button></Space> }]} /></Card></Col>
      <Col xs={24} lg={8}><Card title="Notification channels" extra={<Button size="small" onClick={() => openModal('channel')}>Add</Button>}><Table rowKey="id" size="small" pagination={false} dataSource={channels} columns={[{ title: 'Name', dataIndex: 'name' }, { title: 'Kind', dataIndex: 'kind' }, { title: 'Enabled', dataIndex: 'enabled', render: (value) => value ? 'Yes' : 'No' }, { title: 'Actions', render: (_, item) => <Space><Button size="small" onClick={() => testNotificationChannel(item)}>Test</Button><Button size="small" onClick={() => openModal('channel', item)}>Edit</Button><Button size="small" danger onClick={() => deleteResource(`/api/v1/notification-channels/${item.id}`, 'Delete this notification channel?')}>Delete</Button></Space> }]} /></Card></Col>
    </Row>
    <Card title="Alert rules" extra={<Button size="small" onClick={() => openModal('rule')}>Add</Button>} className="inventory-card"><Table rowKey="id" pagination={false} dataSource={rules} columns={[{ title: 'Name', dataIndex: 'name' }, { title: 'Asset types', dataIndex: 'asset_types', render: (value) => (value ?? []).join(', ') || 'All' }, { title: 'Domain thresholds', dataIndex: 'domain_thresholds', render: (value) => (value ?? []).join(', ') }, { title: 'Certificate thresholds', dataIndex: 'certificate_thresholds', render: (value) => (value ?? []).join(', ') }, { title: 'Stale after (hours)', dataIndex: 'stale_after_hours' }, { title: 'Actions', render: (_, item) => item.id === 'default' ? 'Protected' : <Space><Button size="small" onClick={() => openModal('rule', item)}>Edit</Button><Button size="small" danger onClick={() => deleteResource(`/api/v1/alert-rules/${item.id}`, 'Delete this alert rule?')}>Delete</Button></Space> }]} /></Card>
    <Row gutter={[16, 16]} className="inventory-card">
      <Col xs={24} lg={12}><Card title="Sync history"><Table rowKey="id" size="small" pagination={{ pageSize: 5 }} dataSource={syncRuns} columns={[{ title: 'Provider', dataIndex: 'provider' }, { title: 'Status', dataIndex: 'status' }, { title: 'Started', dataIndex: 'started_at', render: (value) => formatTimestamp(value, timeZone) }, { title: 'Error', dataIndex: 'error_summary', render: (value) => value || '—' }]} /></Card></Col>
      <Col xs={24} lg={12}><Card title="Audit history"><Table rowKey="id" size="small" pagination={{ pageSize: 5 }} dataSource={auditEvents} columns={[{ title: 'Action', dataIndex: 'action' }, { title: 'Object', dataIndex: 'object_type' }, { title: 'Outcome', dataIndex: 'outcome' }, { title: 'Created', dataIndex: 'created_at', render: (value) => formatTimestamp(value, timeZone) }]} /></Card></Col>
    </Row>
    <Card title="Notification delivery history" className="inventory-card"><Table rowKey="id" size="small" pagination={{ current: deliveryPage, pageSize: 20, total: deliveryTotal, showSizeChanger: false, onChange: setDeliveryPage }} dataSource={notificationDeliveries} locale={{ emptyText: 'No notification deliveries' }} columns={[{ title: 'Alert', dataIndex: 'alert_id' }, { title: 'Correlation', dataIndex: 'correlation_id' }, { title: 'Status', dataIndex: 'status', render: (value) => <Tag color={value === 'delivered' ? 'green' : 'red'}>{value}</Tag> }, { title: 'Attempts', dataIndex: 'attempts' }, { title: 'Created', dataIndex: 'created_at', render: (value) => formatTimestamp(value, timeZone) }, { title: 'Error', dataIndex: 'last_error', render: (value) => value || '—' }]} /></Card>
  </>

  const pageContent = { overview: renderOverview, domains: renderDomains, certificates: renderCertificates, alerts: renderAlerts, settings: renderSettings }[activePage]()

  const saveToken = () => {
    try {
      if (tokenDraft) globalThis.localStorage?.setItem('cert_harbor_token', tokenDraft)
      else globalThis.localStorage?.removeItem('cert_harbor_token')
    } catch { /* localStorage may be unavailable in embedded browsers */ }
    setAuthToken(tokenDraft)
  }

  const selectTimeZone = (value) => {
    setTimeZone(value)
    try { globalThis.localStorage?.setItem('cert_harbor_timezone', value) } catch { /* localStorage may be unavailable in embedded browsers */ }
  }

  return (
    <Layout className="app-shell">
      <Sider breakpoint="lg" collapsedWidth="0" className="app-sider">
        <div className="brand">CertHarbor</div>
        <Menu theme="dark" mode="inline" selectedKeys={[activePage]} onClick={({ key }) => setActivePage(key)} items={menuItems} />
      </Sider>
      <Layout>
        <Header className="app-header">
          <Space direction="vertical" size={0}>
            <Typography.Text type="secondary">Workspace</Typography.Text>
            <Typography.Title level={4}>{pageTitle}</Typography.Title>
          </Space>
          <Space>
            <Select aria-label="Timezone" size="small" value={timeZone} onChange={selectTimeZone} options={timeZoneOptions} style={{ width: 170 }} />
            <Input.Password aria-label="API token" placeholder="API token" value={tokenDraft} onChange={(event) => setTokenDraft(event.target.value)} onPressEnter={saveToken} style={{ width: 150 }} />
            <Button onClick={saveToken}>Use token</Button>
            {connections[0] && <Button type="primary" icon={<ReloadOutlined />} onClick={syncNow} loading={syncing}>Sync now</Button>}
            <Button icon={<ReloadOutlined />} onClick={loadInventory} loading={loading}>Refresh</Button>
          </Space>
        </Header>
        <Content className="app-content">
          <div className="page-heading">
            <Typography.Title level={2}>{activePage === 'overview' ? 'Certificate and domain inventory' : pageTitle}</Typography.Title>
            <Typography.Paragraph type="secondary">
              Connect your cloud providers to keep expiry and synchronization health in one place.
            </Typography.Paragraph>
          </div>
          {error && <Alert type="error" showIcon message={error} className="page-alert" />}
          {notice && <Alert type="success" showIcon message={notice} className="page-alert" />}
          {loading && rows.length === 0 ? <div className="loading-state"><Spin /></div> : <>
            {pageContent}
          </>}
        </Content>
      </Layout>
      <Modal open={Boolean(modalKind)} title={`${editingId ? 'Edit' : 'Add'} ${{ connection: 'provider connection', member: 'workspace member', channel: 'notification channel', rule: 'alert rule' }[modalKind] || ''}`} onCancel={closeModal} onOk={submitModal} okText="Save">
        {modalKind === 'connection' && <Space direction="vertical" style={{ width: '100%' }}><Input placeholder="Name" value={modalValues.name} onChange={(event) => updateModalValue('name', event.target.value)} /><Select placeholder="Provider" disabled={Boolean(editingId)} value={modalValues.provider || undefined} style={{ width: '100%' }} onChange={(value) => updateModalValue('provider', value)} options={['alibaba_cloud', 'tencent', 'aws', 'cloudflare'].map((value) => ({ value, label: value }))} /><Input placeholder="Sync interval, e.g. 24h" value={modalValues.sync_interval} onChange={(event) => updateModalValue('sync_interval', event.target.value)} /><Select placeholder="Enabled" value={modalValues.enabled} style={{ width: '100%' }} onChange={(value) => updateModalValue('enabled', value)} options={[{ value: true, label: 'Enabled' }, { value: false, label: 'Disabled' }]} /><Input.TextArea placeholder='Credentials JSON (optional; never returned when editing)' value={modalValues.credentials || ''} onChange={(event) => updateModalValue('credentials', event.target.value)} /></Space>}
        {modalKind === 'member' && <Space direction="vertical" style={{ width: '100%' }}><Input placeholder="Email" disabled={Boolean(editingId)} value={modalValues.email || ''} onChange={(event) => updateModalValue('email', event.target.value)} /><Input placeholder="Name" value={modalValues.name} onChange={(event) => updateModalValue('name', event.target.value)} /><Select placeholder="Role" value={modalValues.role} style={{ width: '100%' }} onChange={(value) => updateModalValue('role', value)} options={[{ value: 'viewer', label: 'Viewer' }, { value: 'administrator', label: 'Administrator' }]} /><Select placeholder="Status" value={modalValues.status} style={{ width: '100%' }} onChange={(value) => updateModalValue('status', value)} options={[{ value: 'active', label: 'Active' }, { value: 'invited', label: 'Invited' }, { value: 'suspended', label: 'Suspended' }]} /></Space>}
        {modalKind === 'channel' && <Space direction="vertical" style={{ width: '100%' }}><Input placeholder="Name" value={modalValues.name} onChange={(event) => updateModalValue('name', event.target.value)} /><Select placeholder="Kind" disabled={Boolean(editingId)} value={modalValues.kind} style={{ width: '100%' }} onChange={(value) => updateModalValue('kind', value)} options={[{ value: 'webhook', label: 'Webhook' }, { value: 'email', label: 'Email' }]} /><Input placeholder="Endpoint" value={modalValues.endpoint} onChange={(event) => updateModalValue('endpoint', event.target.value)} /><Select placeholder="Enabled" value={modalValues.enabled} style={{ width: '100%' }} onChange={(value) => updateModalValue('enabled', value)} options={[{ value: true, label: 'Enabled' }, { value: false, label: 'Disabled' }]} /><Input.Password placeholder="Signing secret (optional; never returned when editing)" value={modalValues.signing_secret || ''} onChange={(event) => updateModalValue('signing_secret', event.target.value)} /><Input.TextArea placeholder='Credentials JSON (email username/password/from/to)' value={modalValues.credentials || ''} onChange={(event) => updateModalValue('credentials', event.target.value)} /></Space>}
        {modalKind === 'rule' && <Space direction="vertical" style={{ width: '100%' }}><Input placeholder="Name" value={modalValues.name} onChange={(event) => updateModalValue('name', event.target.value)} /><Input placeholder="Asset types: domain,certificate,connection (optional)" value={modalValues.asset_types} onChange={(event) => updateModalValue('asset_types', event.target.value)} /><Input placeholder="Domain thresholds: 90,30,14,7,3" value={modalValues.domain_thresholds} onChange={(event) => updateModalValue('domain_thresholds', event.target.value)} /><Input placeholder="Certificate thresholds: 90,30,14,7,3" value={modalValues.certificate_thresholds} onChange={(event) => updateModalValue('certificate_thresholds', event.target.value)} /><Input placeholder="Stale after hours" value={modalValues.stale_after_hours} onChange={(event) => updateModalValue('stale_after_hours', event.target.value)} /><Input placeholder="Tags (comma-separated, optional)" value={modalValues.tags} onChange={(event) => updateModalValue('tags', event.target.value)} /></Space>}
      </Modal>
      <Modal open={Boolean(detailItem)} title={`${detailKind} details`} footer={null} onCancel={() => { setDetailItem(null); setDetailKind('') }}>
        {detailItem && <Descriptions bordered column={1} size="small">
          <Descriptions.Item label="Name">{detailItem.name || detailItem.common_name}</Descriptions.Item>
          <Descriptions.Item label="Provider">{detailItem.provider}</Descriptions.Item>
          <Descriptions.Item label="Source ID">{detailItem.source_id}</Descriptions.Item>
          <Descriptions.Item label="Owner / team">{detailItem.owner || 'Unknown'}</Descriptions.Item>
          <Descriptions.Item label="Environment">{detailItem.environment || 'Unknown'}</Descriptions.Item>
          <Descriptions.Item label="Tags">{(detailItem.tags || []).join(', ') || 'None'}</Descriptions.Item>
          <Descriptions.Item label="Notes">{detailItem.notes || 'None'}</Descriptions.Item>
          <Descriptions.Item label="Status">{detailItem.status || 'Unknown'}</Descriptions.Item>
          <Descriptions.Item label="Expiry state">{detailItem.expiry_state || 'Unknown'}</Descriptions.Item>
          {detailKind === 'Certificate' && <>
            <Descriptions.Item label="Issuer">{detailItem.issuer || 'Unknown'}</Descriptions.Item>
            <Descriptions.Item label="SANs">{(detailItem.sans || []).join(', ') || 'None'}</Descriptions.Item>
            <Descriptions.Item label="Linked domains">{(detailItem.linked_domains || []).join(', ') || 'Unknown'}</Descriptions.Item>
            <Descriptions.Item label="Certificate type">{detailItem.certificate_type || 'Unknown'}</Descriptions.Item>
            <Descriptions.Item label="Valid from">{formatTimestamp(detailItem.valid_from, timeZone)}</Descriptions.Item>
            <Descriptions.Item label="Valid to">{formatTimestamp(detailItem.valid_to, timeZone)}</Descriptions.Item>
            <Descriptions.Item label="Region">{detailItem.region || 'Unknown'}</Descriptions.Item>
          </>}
          <Descriptions.Item label="Last seen">{formatTimestamp(detailItem.last_seen_at, timeZone)}</Descriptions.Item>
          <Descriptions.Item label="Source">{detailItem.source_url ? <a href={detailItem.source_url} target="_blank" rel="noreferrer">Open provider source</a> : 'Unavailable'}</Descriptions.Item>
        </Descriptions>}
      </Modal>
      <Modal open={Boolean(alertDetail)} title="Alert details" footer={null} onCancel={() => setAlertDetail(null)}>
        {alertDetail && <Descriptions bordered column={1} size="small">
          <Descriptions.Item label="Asset">{alertDetail.asset_name}</Descriptions.Item>
          <Descriptions.Item label="Type">{alertDetail.asset_kind}</Descriptions.Item>
          <Descriptions.Item label="Provider">{alertDetail.provider}</Descriptions.Item>
          <Descriptions.Item label="State">{alertDetail.state}</Descriptions.Item>
          <Descriptions.Item label="Severity">{alertDetail.severity}</Descriptions.Item>
          <Descriptions.Item label="Days remaining">{alertDetail.days_remaining ?? 'Unknown'}</Descriptions.Item>
          <Descriptions.Item label="Expires at">{formatTimestamp(alertDetail.expires_at, timeZone)}</Descriptions.Item>
          <Descriptions.Item label="Freshness">{alertDetail.freshness || 'Unknown'}</Descriptions.Item>
          <Descriptions.Item label="Notifications">{alertDeliveries.map((delivery) => `${delivery.status} (${delivery.correlation_id})`).join(', ') || 'No recorded deliveries'}</Descriptions.Item>
          <Descriptions.Item label="Source">{alertDetail.source_url ? <a href={alertDetail.source_url} target="_blank" rel="noreferrer">Open provider source</a> : 'Unavailable'}</Descriptions.Item>
        </Descriptions>}
      </Modal>
    </Layout>
  )
}
