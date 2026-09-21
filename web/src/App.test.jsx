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
      if (url === '/api/v1/alerts') return { ok: true, json: async () => ({ items: [{ id: 'alert-1', asset_name: 'example.com', asset_kind: 'certificate', state: 'open', severity: 'high', provider: 'cloudflare', updated_at: 'now' }] }) }
      return { ok: true, json: async () => ({ items: [] }) }
    }
    render(<App fetcher={fetcher} />)
    await waitFor(() => expect(screen.getByText('Certificate and domain inventory')).toBeInTheDocument())
    fireEvent.change(screen.getByLabelText('API token'), { target: { value: 'viewer-secret' } })
    fireEvent.click(screen.getByText('Use token'))
    await waitFor(() => expect(calls.some(({ options }) => options.headers?.['X-CertHarbor-Token'] === 'viewer-secret')).toBe(true))
    fireEvent.click(screen.getByText('Alert center'))
    await waitFor(() => expect(screen.getByText('Acknowledge')).toBeInTheDocument())
    fireEvent.click(screen.getByText('Acknowledge'))
    await waitFor(() => expect(calls.some(({ url, options }) => url === '/api/v1/alerts/alert-1/acknowledge' && options.method === 'POST')).toBe(true))
  })
})
