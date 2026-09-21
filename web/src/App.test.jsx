import { render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { App } from './App'

describe('CertHarbor console', () => {
  it('renders the inventory foundation', async () => {
    render(<App />)
    await waitFor(() => {
      expect(screen.getByText('Certificate and domain inventory')).toBeInTheDocument()
      expect(screen.getByText('Inventory')).toBeInTheDocument()
      expect(screen.getByText('No assets synchronized yet')).toBeInTheDocument()
    })
  })
})
