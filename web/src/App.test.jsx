import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { App } from './App'

describe('CertHarbor console', () => {
  it('renders the inventory foundation', async () => {
    const fetcher = async (url) => ({
      ok: true,
      json: async () => url.includes('summary')
        ? { domains: 0, certificates: 0, connections: 0, stale_assets: 0 }
        : { items: [] },
    })
    render(<App fetcher={fetcher} />)
    await waitFor(() => {
      expect(screen.getByText('Certificate and domain inventory')).toBeInTheDocument()
      expect(screen.getByText('Inventory')).toBeInTheDocument()
      expect(screen.getByText('No assets synchronized yet')).toBeInTheDocument()
      expect(screen.getByRole('combobox', { name: 'Timezone' })).toBeInTheDocument()
    })
    fireEvent.click(screen.getByText('Domain inventory'))
    expect(screen.getByText('Domains')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('Search inventory')).toBeInTheDocument()
  })

  it('acknowledges an open alert from the alert center', async () => {
    const calls = []
    const fetcher = async (url, options = {}) => {
      calls.push({ url, options })
      if (url.includes('summary')) return { ok: true, json: async () => ({ domains: 0, certificates: 0, connections: 0, stale_assets: 0 }) }
      if (url === '/api/v1/alerts?page=1&page_size=20') return { ok: true, json: async () => ({ items: [{ id: 'alert-1', asset_name: 'example.com', asset_kind: 'certificate', state: 'open', severity: 'high', provider: 'cloudflare', source_url: 'https://provider.example/certificate/1', updated_at: 'now' }], total: 1 }) }
      return { ok: true, json: async () => ({ items: [] }) }
    }
    render(<App fetcher={fetcher} />)
    await waitFor(() => expect(screen.getByText('Certificate and domain inventory')).toBeInTheDocument())
    fireEvent.change(screen.getByLabelText('API token'), { target: { value: 'viewer-secret' } })
    fireEvent.click(screen.getByText('Use token'))
    await waitFor(() => expect(calls.some(({ options }) => options.headers?.['X-CertHarbor-Token'] === 'viewer-secret')).toBe(true))
    fireEvent.click(screen.getByText('Alert center'))
    await waitFor(() => expect(screen.getByText('Acknowledge')).toBeInTheDocument())
    expect(screen.getByRole('link', { name: 'Provider' })).toHaveAttribute('href', 'https://provider.example/certificate/1')
    fireEvent.click(screen.getByText('Acknowledge'))
    await waitFor(() => expect(calls.some(({ url, options }) => url === '/api/v1/alerts/alert-1/acknowledge' && options.method === 'POST')).toBe(true))
  })

  it('tests a provider connection from settings', async () => {
    const calls = []
    const fetcher = async (url, options = {}) => {
      calls.push({ url, options })
      if (url.includes('summary')) return { ok: true, json: async () => ({ domains: 0, certificates: 0, connections: 1, stale_assets: 0 }) }
      if (url === '/api/v1/provider-connections?page=1&page_size=50') return { ok: true, json: async () => ({ items: [{ id: 'connection-1', name: 'Cloudflare', provider: 'cloudflare', status: 'healthy', enabled: true }] }) }
      if (url === '/api/v1/provider-connections/connection-1/test') return { ok: true, json: async () => ({ request_id: 'ray-1' }) }
      if (url === '/api/v1/provider-connections/connection-1/sync') return { ok: true, json: async () => ({ status: 'succeeded' }) }
      return { ok: true, json: async () => ({ items: [] }) }
    }
    render(<App fetcher={fetcher} />)
    await waitFor(() => expect(screen.getByText('Certificate and domain inventory')).toBeInTheDocument())
    fireEvent.click(screen.getByText('Settings'))
    await waitFor(() => expect(screen.getByText('Cloudflare')).toBeInTheDocument())
    fireEvent.click(screen.getByText('Test'))
    await waitFor(() => expect(calls.some(({ url, options }) => url === '/api/v1/provider-connections/connection-1/test' && options.method === 'POST')).toBe(true))
    expect(await screen.findByText(/Connection test passed/)).toBeInTheDocument()
    fireEvent.click(screen.getByText('Sync'))
    await waitFor(() => expect(calls.some(({ url, options }) => url === '/api/v1/provider-connections/connection-1/sync' && options.method === 'POST')).toBe(true))
    expect(screen.getByText('Cloudflare sync completed.')).toBeInTheDocument()
  }, 15000)

  it('opens inventory details from the domain table', async () => {
    const fetcher = async (url) => {
      if (url.includes('/domains?')) return { ok: true, json: async () => ({ items: [{ id: 'domain-1', name: 'example.com', provider: 'cloudflare', source_id: 'zone-1', status: 'active', last_seen_at: 'now', source_url: 'https://provider.example/domain/zone-1', tags: ['prod'] }], total: 1 }) }
      if (url.includes('summary')) return { ok: true, json: async () => ({ domains: 1, certificates: 0, connections: 0, stale_assets: 0 }) }
      return { ok: true, json: async () => ({ items: [] }) }
    }
    render(<App fetcher={fetcher} />)
    await waitFor(() => expect(screen.getByText('Certificate and domain inventory')).toBeInTheDocument())
    fireEvent.click(screen.getByText('Domain inventory'))
    await waitFor(() => expect(screen.getByText('example.com')).toBeInTheDocument())
    fireEvent.click(screen.getByText('View'))
    expect(screen.getByText('Domain details')).toBeInTheDocument()
    expect(screen.getByText('Open provider source')).toBeInTheDocument()
  })

  it('requests subsequent inventory pages from the API', async () => {
    const calls = []
    const fetcher = async (url) => {
      calls.push(url)
      if (url.includes('/domains?')) return { ok: true, json: async () => ({ items: [{ id: 'domain-1', name: 'example.com', provider: 'cloudflare', last_seen_at: 'now' }], total: 41, page: Number(new URL(url, 'http://localhost').searchParams.get('page')), page_size: 20 }) }
      if (url.includes('summary')) return { ok: true, json: async () => ({ domains: 41, certificates: 0, connections: 0, stale_assets: 0 }) }
      return { ok: true, json: async () => ({ items: [] }) }
    }
    render(<App fetcher={fetcher} />)
    await waitFor(() => expect(screen.getByText('Certificate and domain inventory')).toBeInTheDocument())
    fireEvent.click(screen.getByText('Domain inventory'))
    await waitFor(() => expect(screen.getByText('example.com')).toBeInTheDocument())
    fireEvent.click(screen.getByTitle('Next Page'))
    await waitFor(() => expect(calls.some((url) => url.includes('/domains?page=2&page_size=20'))).toBe(true))
  })

  it('exports the filtered domain inventory with the configured token', async () => {
    const calls = []
    const originalCreateObjectURL = globalThis.URL.createObjectURL
    const originalRevokeObjectURL = globalThis.URL.revokeObjectURL
    const originalAnchorClick = HTMLAnchorElement.prototype.click
    globalThis.URL.createObjectURL = () => 'blob:domains'
    globalThis.URL.revokeObjectURL = () => {}
    HTMLAnchorElement.prototype.click = () => {}
    const fetcher = async (url, options = {}) => {
      calls.push({ url, options })
      if (url.includes('summary')) return { ok: true, json: async () => ({ domains: 1, certificates: 0, connections: 0, stale_assets: 0 }) }
      if (url.includes('/domains?')) return { ok: true, json: async () => ({ items: [{ id: 'domain-1', name: 'example.com', provider: 'cloudflare', last_seen_at: 'now' }], total: 1 }) }
      if (url.startsWith('/api/v1/export/domains.csv')) return { ok: true, blob: async () => new Blob(['name\nexample.com\n'], { type: 'text/csv' }) }
      return { ok: true, json: async () => ({ items: [] }) }
    }
    try {
      render(<App fetcher={fetcher} />)
      await waitFor(() => expect(screen.getByText('Certificate and domain inventory')).toBeInTheDocument())
      fireEvent.change(screen.getByLabelText('API token'), { target: { value: 'viewer-secret' } })
      fireEvent.click(screen.getByText('Use token'))
      fireEvent.click(screen.getByText('Domain inventory'))
      await waitFor(() => expect(screen.getByText('Export CSV')).toBeInTheDocument())
      fireEvent.click(screen.getByText('Export CSV'))
      await waitFor(() => expect(calls.some(({ url, options }) => url.startsWith('/api/v1/export/domains.csv') && options.headers?.['X-CertHarbor-Token'] === 'viewer-secret')).toBe(true))
    } finally {
      globalThis.URL.createObjectURL = originalCreateObjectURL
      globalThis.URL.revokeObjectURL = originalRevokeObjectURL
      HTMLAnchorElement.prototype.click = originalAnchorClick
    }
  })

  it('opens a linked alert deep link', async () => {
    const originalPath = window.location.pathname
    window.history.pushState({}, '', '/alerts/alert-1')
    try {
      const fetcher = async (url) => {
        if (url === '/api/v1/alerts/alert-1') return { ok: true, json: async () => ({ id: 'alert-1', asset_name: 'example.com', asset_kind: 'certificate', provider: 'cloudflare', state: 'open', severity: 'high', days_remaining: 7, freshness: 'current', source_url: 'https://provider.example/certificate/1' }) }
        if (url === '/api/v1/notification-deliveries?alert_id=alert-1&page=1&page_size=100') return { ok: true, json: async () => ({ items: [{ id: 'delivery-1', alert_id: 'alert-1', correlation_id: 'corr-delivery-1', status: 'delivered', attempts: 1, created_at: 'now' }] }) }
        if (url === '/api/v1/alerts/alert-1/events') return { ok: true, json: async () => ({ items: [{ id: 'event-1', alert_id: 'alert-1', from_state: 'open', to_state: 'acknowledged', actor: 'administrator', note: 'tracking' }] }) }
        if (url === '/api/v1/alerts?page=1&page_size=20') return { ok: true, json: async () => ({ items: [], total: 0 }) }
        if (url === '/api/v1/notification-deliveries?page=1&page_size=20') return { ok: true, json: async () => ({ items: [{ id: 'delivery-1', alert_id: 'alert-1', correlation_id: 'corr-delivery-1', status: 'delivered', attempts: 1, created_at: 'now' }] }) }
        if (url.includes('summary')) return { ok: true, json: async () => ({ domains: 0, certificates: 0, connections: 0, stale_assets: 0 }) }
        return { ok: true, json: async () => ({ items: [] }) }
      }
      render(<App fetcher={fetcher} />)
      await waitFor(() => expect(screen.getByText('Alert details')).toBeInTheDocument())
      expect(screen.getByText('example.com')).toBeInTheDocument()
      expect(screen.getByText('Open provider source')).toBeInTheDocument()
      expect(screen.getByText('open → acknowledged by administrator (tracking)')).toBeInTheDocument()
      expect(screen.getByText('delivered (corr-delivery-1)')).toBeInTheDocument()
    } finally {
      window.history.pushState({}, '', originalPath)
    }
  })
})
