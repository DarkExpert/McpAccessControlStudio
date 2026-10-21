import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import App from './App'
import * as api from './api'
import * as mcp from './mcp'

vi.mock('./api', () => ({
  ApiError: class ApiError extends Error { constructor(readonly status: number) { super('Request failed') } },
  issueDemoToken: vi.fn(), fetchPolicy: vi.fn(), fetchOverview: vi.fn(), fetchAudit: vi.fn(),
  findTerminalEvent: vi.fn(), sessionValid: (session: { identity: string; expiresAtUtc: string } | null, identity: string) =>
    session?.identity === identity && Date.parse(session.expiresAtUtc) > Date.now() + 15_000,
}))
vi.mock('./mcp', () => ({ executeScenario: vi.fn(), executionError: () => 'MCP call failed.' }))

const future = '2099-01-01T00:00:00Z'
const policy = [{ name: 'crm.get_customer', allowedRoles: ['Viewer', 'Operator', 'Admin'], maximumAmount: null }]

beforeEach(() => {
  vi.mocked(api.issueDemoToken).mockImplementation(async identity => ({ identity, accessToken: `${identity}-token`, expiresAtUtc: future }))
  vi.mocked(api.fetchPolicy).mockResolvedValue(policy)
  vi.mocked(api.fetchOverview).mockResolvedValue({ persistedTerminalCount: 1, allowed: 0, denied: 1, forwarded: 0, blocked: 1, succeeded: 0, toolErrors: 0, unknown: 0 })
  vi.mocked(api.fetchAudit).mockResolvedValue({ items: [], nextCursor: null })
  vi.mocked(api.findTerminalEvent).mockResolvedValue(null)
  vi.mocked(mcp.executeScenario).mockResolvedValue({ isError: true, contentBlocks: 1, meta: {
    correlationId: 'a'.repeat(32), decision: 'Deny', reasonCode: 'RoleDenied', enforcement: 'Blocked', upstreamStatus: 'NotAttempted',
  } })
})
afterEach(() => { cleanup(); vi.clearAllMocks() })

it('runs a real client call with the selected role token and displays backend reason', async () => {
  render(<App />)
  fireEvent.click(screen.getByRole('button', { name: /delete customer/i }))
  fireEvent.click(screen.getByRole('button', { name: /run scenario/i }))
  await waitFor(() => expect(mcp.executeScenario).toHaveBeenCalled())
  expect(vi.mocked(mcp.executeScenario).mock.calls[0][0]).toBe('viewer-token')
  expect(vi.mocked(mcp.executeScenario).mock.calls[0][1].tool).toBe('crm.delete_customer')
  expect(await screen.findByText('RoleDenied')).toBeTruthy()
  expect(screen.getByText('a'.repeat(32))).toBeTruthy()
})

it('keeps an explicit Admin reporting token separate from Viewer MCP execution', async () => {
  render(<App />)
  fireEvent.click(screen.getByRole('button', { name: /security overview/i }))
  fireEvent.click(screen.getByRole('button', { name: /enable admin reporting/i }))
  await waitFor(() => expect(api.fetchOverview).toHaveBeenCalledWith('admin-token', expect.anything()))
  fireEvent.click(screen.getByRole('button', { name: /security playground/i }))
  fireEvent.click(screen.getByRole('button', { name: /run scenario/i }))
  await waitFor(() => expect(mcp.executeScenario).toHaveBeenCalled())
  expect(vi.mocked(mcp.executeScenario).mock.calls[0][0]).toBe('viewer-token')
})

it('clears results and Admin reporting on identity change', async () => {
  render(<App />)
  fireEvent.click(screen.getByRole('button', { name: /Security Overview/i }))
  fireEvent.click(screen.getByRole('button', { name: /Enable Admin reporting/i }))
  await waitFor(() => expect(api.fetchOverview).toHaveBeenCalled())
  fireEvent.click(screen.getByRole('button', { name: /Security Playground/i }))
  fireEvent.click(screen.getByRole('button', { name: /run scenario/i }))
  expect(await screen.findByText('RoleDenied')).toBeTruthy()
  fireEvent.click(screen.getByRole('button', { name: /operator/i }))
  expect(screen.queryByText('RoleDenied')).toBeNull()
  fireEvent.click(screen.getByRole('button', { name: /security overview/i }))
  expect(screen.getByText('Open an Admin reporting session')).toBeTruthy()
})

it('shows an error without inventing an authorization outcome when MCP fails', async () => {
  vi.mocked(mcp.executeScenario).mockRejectedValue(new Error('sensitive transport detail'))
  render(<App />)
  fireEvent.click(screen.getByRole('button', { name: /run scenario/i }))
  expect(await screen.findByRole('alert')).toHaveProperty('textContent', 'MCP call failed.')
  expect(screen.queryByText('Allowed by gateway')).toBeNull()
  expect(screen.queryByText('sensitive transport detail')).toBeNull()
})
