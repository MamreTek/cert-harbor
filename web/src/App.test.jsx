import { render, screen, waitFor } from '@testing-library/react'
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
  })
})
