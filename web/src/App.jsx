import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  BellOutlined,
  CloudServerOutlined,
  DashboardOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
  SettingOutlined,
} from '@ant-design/icons'
import { Alert, Button, Card, Col, Layout, Menu, Row, Space, Spin, Statistic, Table, Tag, Typography } from 'antd'

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
  const [loading, setLoading] = useState(Boolean(fetcher))
  const [syncing, setSyncing] = useState(false)
  const [error, setError] = useState('')

  const loadInventory = useCallback(async () => {
    if (!fetcher) return
    setLoading(true)
    setError('')
    try {
      const responses = await Promise.all([
        fetcher('/api/v1/catalog/summary'),
        fetcher('/api/v1/provider-connections'),
        fetcher('/api/v1/domains?page=1&page_size=50'),
        fetcher('/api/v1/certificates?page=1&page_size=50'),
      ])
      if (responses.some((response) => !response.ok)) throw new Error('The inventory API returned an error.')
      const [nextSummary, nextConnections, nextDomains, nextCertificates] = await Promise.all(responses.map((response) => response.json()))
      setSummary({ ...emptySummary, ...nextSummary })
      setConnections(nextConnections.items ?? [])
      setDomains(nextDomains.items ?? [])
      setCertificates(nextCertificates.items ?? [])
    } catch (loadError) {
      setError(loadError.message || 'Unable to load inventory.')
    } finally {
      setLoading(false)
    }
  }, [fetcher])

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

  return (
    <Layout className="app-shell">
      <Sider breakpoint="lg" collapsedWidth="0" className="app-sider">
        <div className="brand">CertHarbor</div>
        <Menu theme="dark" mode="inline" defaultSelectedKeys={['overview']} items={menuItems} />
      </Sider>
      <Layout>
        <Header className="app-header">
          <Space direction="vertical" size={0}>
            <Typography.Text type="secondary">Workspace</Typography.Text>
            <Typography.Title level={4}>Overview</Typography.Title>
          </Space>
          <Space>
            {connections[0] && <Button type="primary" icon={<ReloadOutlined />} onClick={syncNow} loading={syncing}>Sync now</Button>}
            <Button icon={<ReloadOutlined />} onClick={loadInventory} loading={loading}>Refresh</Button>
          </Space>
        </Header>
        <Content className="app-content">
          <div className="page-heading">
            <Typography.Title level={2}>Certificate and domain inventory</Typography.Title>
            <Typography.Paragraph type="secondary">
              Connect your cloud providers to keep expiry and synchronization health in one place.
            </Typography.Paragraph>
          </div>
          {error && <Alert type="error" showIcon message={error} className="page-alert" />}
          {loading && rows.length === 0 ? <div className="loading-state"><Spin /></div> : <>
            <Row gutter={[16, 16]}>
              <Col xs={24} sm={12} lg={6}><Card><Statistic title="Domains" value={summary.domains} /></Card></Col>
              <Col xs={24} sm={12} lg={6}><Card><Statistic title="Certificates" value={summary.certificates} /></Card></Col>
              <Col xs={24} sm={12} lg={6}><Card><Statistic title="Stale assets" value={summary.stale_assets} /></Card></Col>
              <Col xs={24} sm={12} lg={6}><Card><Statistic title="Connections" value={summary.connections} /></Card></Col>
            </Row>
            <Card title="Inventory" className="inventory-card">
              <Table columns={columns} dataSource={rows.length ? rows : [{ key: 'empty', asset: 'No assets synchronized yet', type: '—', provider: '—', state: 'Ready', lastSync: 'Run your first sync' }]} pagination={false} />
            </Card>
          </>}
        </Content>
      </Layout>
    </Layout>
  )
}
