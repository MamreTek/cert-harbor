import {
  BellOutlined,
  CloudServerOutlined,
  DashboardOutlined,
  SafetyCertificateOutlined,
  SettingOutlined,
} from '@ant-design/icons'
import { Card, Col, Layout, Menu, Row, Space, Statistic, Table, Tag, Typography } from 'antd'

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
  { title: 'Provider', dataIndex: 'provider', key: 'provider' },
  { title: 'State', dataIndex: 'state', key: 'state', render: (state) => <Tag color="green">{state}</Tag> },
  { title: 'Last sync', dataIndex: 'lastSync', key: 'lastSync' },
]

const data = [
  { key: '1', asset: 'No assets synchronized yet', provider: '—', state: 'Ready', lastSync: 'Run your first sync' },
]

export function App() {
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
        </Header>
        <Content className="app-content">
          <div className="page-heading">
            <Typography.Title level={2}>Certificate and domain inventory</Typography.Title>
            <Typography.Paragraph type="secondary">
              Connect your cloud providers to keep expiry and synchronization health in one place.
            </Typography.Paragraph>
          </div>
          <Row gutter={[16, 16]}>
            <Col xs={24} sm={12} lg={6}><Card><Statistic title="Domains" value={0} /></Card></Col>
            <Col xs={24} sm={12} lg={6}><Card><Statistic title="Certificates" value={0} /></Card></Col>
            <Col xs={24} sm={12} lg={6}><Card><Statistic title="Open alerts" value={0} /></Card></Col>
            <Col xs={24} sm={12} lg={6}><Card><Statistic title="Providers" value={4} /></Card></Col>
          </Row>
          <Card title="Inventory" className="inventory-card">
            <Table columns={columns} dataSource={data} pagination={false} />
          </Card>
        </Content>
      </Layout>
    </Layout>
  )
}
