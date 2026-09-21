import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  BellOutlined,
  CloudServerOutlined,
  DashboardOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
  SettingOutlined,
} from '@ant-design/icons'
import { Alert, Button, Card, Col, Input, Layout, Menu, Row, Select, Space, Spin, Statistic, Table, Tag, Typography } from 'antd'

const { Header, Sider, Content } = Layout

const menuItems = [
  { key: 'overview', icon: <DashboardOutlined />, label: 'Overview' },
  { key: 'domains', icon: <CloudServerOutlined />, label: 'Domain inventory' },
  { key: 'certificates', icon: <SafetyCertificateOutlined />, label: 'Certificates' },
  { key: 'alerts', icon: <BellOutlined />, label: 'Alert center' },
  { key: 'settings', icon: <SettingOutlined />, label: 'Settings' },
]

const columns = [
  { title: 'Asset', dataIndex: 'asset', key: 'asset' },
  { title: 'Type', dataIndex: 'type', key: 'type' },
  { title: 'Provider', dataIndex: 'provider', key: 'provider' },
  { title: 'State', dataIndex: 'state', key: 'state', render: (state) => <Tag color={state === 'Stale' ? 'orange' : 'green'}>{state}</Tag> },
  { title: 'Last sync', dataIndex: 'lastSync', key: 'lastSync' },
]

const emptySummary = { domains: 0, certificates: 0, connections: 0, stale_assets: 0 }
const defaultFetcher = globalThis.fetch?.bind(globalThis)

export function App({ fetcher = defaultFetcher }) {
  const [summary, setSummary] = useState(emptySummary)
  const [connections, setConnections] = useState([])
  const [domains, setDomains] = useState([])
  const [certificates, setCertificates] = useState([])
  const [alerts, setAlerts] = useState([])
  const [rules, setRules] = useState([])
  const [members, setMembers] = useState([])
  const [channels, setChannels] = useState([])
  const [activePage, setActivePage] = useState('overview')
  const [loading, setLoading] = useState(Boolean(fetcher))
  const [syncing, setSyncing] = useState(false)
  const [error, setError] = useState('')
  const [inventoryFilters, setInventoryFilters] = useState({ search: '', provider: '', expiry_state: '', stale: '' })

  const filterQuery = new URLSearchParams(Object.entries(inventoryFilters).filter(([, value]) => value !== '')).toString()

  const loadInventory = useCallback(async () => {
    if (!fetcher) return
    setLoading(true)
    setError('')
    try {
      const responses = await Promise.all([
        fetcher('/api/v1/catalog/summary'),
        fetcher('/api/v1/provider-connections'),
        fetcher(`/api/v1/domains?page=1&page_size=50${filterQuery ? `&${filterQuery}` : ''}`),
        fetcher(`/api/v1/certificates?page=1&page_size=50${filterQuery ? `&${filterQuery}` : ''}`),
        fetcher('/api/v1/alerts'),
        fetcher('/api/v1/alert-rules'),
        fetcher('/api/v1/members'),
        fetcher('/api/v1/notification-channels'),
      ])
      if (responses.some((response) => !response.ok)) throw new Error('The inventory API returned an error.')
      const [nextSummary, nextConnections, nextDomains, nextCertificates, nextAlerts, nextRules, nextMembers, nextChannels] = await Promise.all(responses.map((response) => response.json()))
      setSummary({ ...emptySummary, ...nextSummary })
      setConnections(nextConnections.items ?? [])
      setDomains(nextDomains.items ?? [])
      setCertificates(nextCertificates.items ?? [])
      setAlerts(nextAlerts.items ?? [])
      setRules(nextRules.items ?? [])
      setMembers(nextMembers.items ?? [])
      setChannels(nextChannels.items ?? [])
    } catch (loadError) {
      setError(loadError.message || 'Unable to load inventory.')
    } finally {
      setLoading(false)
    }
  }, [fetcher, filterQuery])

  useEffect(() => {
    loadInventory()
  }, [loadInventory])

  const syncNow = async () => {
    const connection = connections[0]
    if (!fetcher || !connection) return
    setSyncing(true)
    setError('')
    try {
      const response = await fetcher(`/api/v1/provider-connections/${connection.id}/sync`, { method: 'POST' })
      if (!response.ok) throw new Error('The provider sync failed.')
      await loadInventory()
    } catch (syncError) {
      setError(syncError.message || 'Unable to synchronize the provider.')
    } finally {
      setSyncing(false)
    }
  }

  const rows = useMemo(() => [
    ...domains.map((item) => ({ key: item.id, asset: item.name, type: 'Domain', provider: item.provider, state: item.stale ? 'Stale' : 'Healthy', lastSync: item.last_seen_at })),
    ...certificates.map((item) => ({ key: item.id, asset: item.common_name, type: 'Certificate', provider: item.provider, state: item.stale ? 'Stale' : 'Healthy', lastSync: item.last_seen_at })),
  ], [certificates, domains])

  const renderInventoryFilters = () => <Space wrap className="inventory-filters">
    <Input.Search placeholder="Search inventory" allowClear onSearch={(value) => setInventoryFilters((current) => ({ ...current, search: value }))} onChange={(event) => { if (!event.target.value) setInventoryFilters((current) => ({ ...current, search: '' })) }} />
    <Select allowClear placeholder="Provider" style={{ minWidth: 150 }} value={inventoryFilters.provider || undefined} onChange={(value) => setInventoryFilters((current) => ({ ...current, provider: value || '' }))} options={connections.map((item) => ({ value: item.provider, label: item.provider }))} />
    <Select allowClear placeholder="Expiry state" style={{ minWidth: 150 }} value={inventoryFilters.expiry_state || undefined} onChange={(value) => setInventoryFilters((current) => ({ ...current, expiry_state: value || '' }))} options={['healthy', 'expiring', 'expired', 'stale', 'unknown'].map((value) => ({ value, label: value }))} />
    <Select allowClear placeholder="Freshness" style={{ minWidth: 130 }} value={inventoryFilters.stale || undefined} onChange={(value) => setInventoryFilters((current) => ({ ...current, stale: value || '' }))} options={[{ value: 'false', label: 'Current' }, { value: 'true', label: 'Stale' }]} />
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
      <Col xs={24} sm={12} lg={6}><Card><Statistic title="Open alerts" value={summary.open_alerts ?? alerts.filter((item) => item.state !== 'resolved').length} /></Card></Col>
    </Row>
    <Card title="Inventory" className="inventory-card">
      <Table columns={columns} dataSource={rows.length ? rows : [{ key: 'empty', asset: 'No assets synchronized yet', type: '—', provider: '—', state: 'Ready', lastSync: 'Run your first sync' }]} pagination={false} />
    </Card>
  </>

  const renderDomains = () => <Card title="Domains" extra={renderInventoryFilters()}>
    <Table rowKey="id" dataSource={domains} pagination={{ pageSize: 20 }} locale={{ emptyText: 'No domains synchronized yet' }} columns={[
      { title: 'Domain', dataIndex: 'name', key: 'name' },
      { title: 'Provider', dataIndex: 'provider', key: 'provider' },
      { title: 'Status', dataIndex: 'status', key: 'status', render: (value) => value || 'Unknown' },
      { title: 'Nameservers', dataIndex: 'nameservers', key: 'nameservers', render: (value) => (value ?? []).join(', ') || 'Unknown' },
      { title: 'Last seen', dataIndex: 'last_seen_at', key: 'last_seen_at' },
      { title: 'Freshness', dataIndex: 'stale', key: 'stale', render: (value) => <Tag color={value ? 'orange' : 'green'}>{value ? 'Stale' : 'Current'}</Tag> },
    ]} />
  </Card>

  const renderCertificates = () => <Card title="Certificates" extra={renderInventoryFilters()}>
    <Table rowKey="id" dataSource={certificates} pagination={{ pageSize: 20 }} locale={{ emptyText: 'No certificates synchronized yet' }} columns={[
      { title: 'Common name', dataIndex: 'common_name', key: 'common_name' },
      { title: 'Issuer', dataIndex: 'issuer', key: 'issuer', render: (value) => value || 'Unknown' },
      { title: 'Valid to', dataIndex: 'valid_to', key: 'valid_to' },
      { title: 'Region', dataIndex: 'region', key: 'region', render: (value) => value || '—' },
      { title: 'Provider', dataIndex: 'provider', key: 'provider' },
      { title: 'Freshness', dataIndex: 'stale', key: 'stale', render: (value) => <Tag color={value ? 'orange' : 'green'}>{value ? 'Stale' : 'Current'}</Tag> },
    ]} />
  </Card>

  const renderAlerts = () => <Card title="Alerts">
    <Table rowKey="id" dataSource={alerts} pagination={{ pageSize: 20 }} locale={{ emptyText: 'No alerts' }} columns={[
      { title: 'Asset', dataIndex: 'asset_name', key: 'asset_name' },
      { title: 'Type', dataIndex: 'asset_kind', key: 'asset_kind' },
      { title: 'State', dataIndex: 'state', key: 'state', render: (value) => <Tag color={value === 'open' ? 'red' : value === 'acknowledged' ? 'gold' : 'green'}>{value}</Tag> },
      { title: 'Severity', dataIndex: 'severity', key: 'severity' },
      { title: 'Days remaining', dataIndex: 'days_remaining', key: 'days_remaining', render: (value) => value ?? '—' },
      { title: 'Provider', dataIndex: 'provider', key: 'provider' },
      { title: 'Updated', dataIndex: 'updated_at', key: 'updated_at' },
    ]} />
  </Card>

  const renderSettings = () => <>
    <Row gutter={[16, 16]}>
      <Col xs={24} lg={8}><Card title="Provider connections"><Table rowKey="id" size="small" pagination={false} dataSource={connections} columns={[{ title: 'Name', dataIndex: 'name' }, { title: 'Provider', dataIndex: 'provider' }, { title: 'Status', dataIndex: 'status' }]} /></Card></Col>
      <Col xs={24} lg={8}><Card title="Members"><Table rowKey="id" size="small" pagination={false} dataSource={members} columns={[{ title: 'Email', dataIndex: 'email' }, { title: 'Role', dataIndex: 'role' }, { title: 'Status', dataIndex: 'status' }]} /></Card></Col>
      <Col xs={24} lg={8}><Card title="Notification channels"><Table rowKey="id" size="small" pagination={false} dataSource={channels} columns={[{ title: 'Name', dataIndex: 'name' }, { title: 'Kind', dataIndex: 'kind' }, { title: 'Enabled', dataIndex: 'enabled', render: (value) => value ? 'Yes' : 'No' }]} /></Card></Col>
    </Row>
    <Card title="Alert rules" className="inventory-card"><Table rowKey="id" pagination={false} dataSource={rules} columns={[{ title: 'Name', dataIndex: 'name' }, { title: 'Domain thresholds', dataIndex: 'domain_thresholds', render: (value) => (value ?? []).join(', ') }, { title: 'Certificate thresholds', dataIndex: 'certificate_thresholds', render: (value) => (value ?? []).join(', ') }, { title: 'Stale after (hours)', dataIndex: 'stale_after_hours' }]} /></Card>
  </>

  const pageContent = { overview: renderOverview, domains: renderDomains, certificates: renderCertificates, alerts: renderAlerts, settings: renderSettings }[activePage]()

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
          {loading && rows.length === 0 ? <div className="loading-state"><Spin /></div> : <>
            {pageContent}
          </>}
        </Content>
      </Layout>
    </Layout>
  )
}
