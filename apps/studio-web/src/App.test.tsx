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

const auditEntry = (id: number) => ({ id, correlationId: 'a'.repeat(32), kind: 'Terminal' as const,
  timestampUtc: '2026-10-21T00:00:00Z', subject: 'viewer', role: 'Viewer', toolName: 'crm.delete_customer',
  decision: 'Deny' as const, reasonCode: 'RoleDenied', enforcement: 'Blocked' as const,
  upstreamStatus: 'NotAttempted', errorCategory: null, durationMs: 2 })

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

it('keeps the requested audit page when a slower older page resolves last', async () => {
  let resolveSlow!: (value: { items: ReturnType<typeof auditEntry>[]; nextCursor: number | null }) => void
  vi.mocked(api.fetchAudit)
    .mockResolvedValueOnce({ items: [auditEntry(30)], nextCursor: 20 })
    .mockImplementationOnce(() => new Promise(resolve => { resolveSlow = resolve }))
    .mockResolvedValueOnce({ items: [auditEntry(30)], nextCursor: 20 })
  render(<App />)
  fireEvent.click(screen.getByRole('button', { name: /security overview/i }))
  fireEvent.click(screen.getByRole('button', { name: /enable admin reporting/i }))
  await waitFor(() => expect(api.fetchAudit).toHaveBeenCalledTimes(1))
  fireEvent.click(screen.getByRole('button', { name: /audit history/i }))
  await screen.findByText('Page 1 · newest first · up to 25 records')
  fireEvent.click(screen.getByRole('button', { name: /next page/i }))
  await screen.findByText('Loading audit history')
  fireEvent.click(screen.getByRole('button', { name: /previous page/i }))
  await waitFor(() => expect(api.fetchAudit).toHaveBeenCalledTimes(3))
  resolveSlow({ items: [auditEntry(19)], nextCursor: null })
  await screen.findByText('Page 1 · newest first · up to 25 records')
  expect(screen.queryByText('Page 2 · newest first · up to 25 records')).toBeNull()
  expect(vi.mocked(api.fetchAudit).mock.calls[1][2]?.aborted).toBe(true)
})

it('discards an old Admin audit response after the Playground identity changes', async () => {
  let resolveAudit!: (value: { items: ReturnType<typeof auditEntry>[]; nextCursor: number | null }) => void
  vi.mocked(api.fetchAudit).mockImplementationOnce(() => new Promise(resolve => { resolveAudit = resolve }))
  render(<App />)
  fireEvent.click(screen.getByRole('button', { name: /security overview/i }))
  fireEvent.click(screen.getByRole('button', { name: /enable admin reporting/i }))
  await waitFor(() => expect(api.fetchAudit).toHaveBeenCalledTimes(1))
  fireEvent.click(screen.getByRole('button', { name: /security playground/i }))
  fireEvent.click(screen.getByRole('button', { name: /operator/i }))
  resolveAudit({ items: [auditEntry(1)], nextCursor: null })
  fireEvent.click(screen.getByRole('button', { name: /audit history/i }))
  expect(await screen.findByText('Open an Admin reporting session')).toBeTruthy()
  expect(screen.queryByText('Recent decisions & outcomes')).toBeNull()
  expect(vi.mocked(api.fetchAudit).mock.calls[0][2]?.aborted).toBe(true)
})

it('shows safe audit empty and storage-error states', async () => {
  render(<App />)
  fireEvent.click(screen.getByRole('button', { name: /audit history/i }))
  fireEvent.click(screen.getByRole('button', { name: /enable admin reporting/i }))
  expect(await screen.findByText('No records on this page')).toBeTruthy()
  vi.mocked(api.fetchAudit).mockRejectedValueOnce(new api.ApiError(503))
  fireEvent.click(screen.getByRole('button', { name: /refresh/i }))
  expect(await screen.findByText('Audit history unavailable')).toBeTruthy()
  expect(screen.getByText('Audit storage is unavailable. Counts may be incomplete.')).toBeTruthy()
})
