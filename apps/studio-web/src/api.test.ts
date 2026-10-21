import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fetchAudit, findTerminalEvent, issueDemoToken, sessionValid } from './api'

const originalFetch = globalThis.fetch

beforeEach(() => { globalThis.fetch = vi.fn() })
afterEach(() => { globalThis.fetch = originalFetch; vi.restoreAllMocks() })

function respond(value: unknown) {
  return Promise.resolve({ ok: true, json: async () => value } as Response)
}

describe('demo session safety', () => {
  it('issues a role-specific token without credentials or token URL parameters', async () => {
    vi.mocked(fetch).mockReturnValue(respond({ accessToken: 'viewer-secret', expiresAtUtc: '2099-01-01T00:00:00Z' }))
    const session = await issueDemoToken('viewer')
    expect(session.identity).toBe('viewer')
    expect(sessionValid(session, 'viewer')).toBe(true)
    expect(sessionValid(session, 'admin')).toBe(false)
    const [url, init] = vi.mocked(fetch).mock.calls[0]
    expect(String(url)).toBe('http://127.0.0.1:5077/api/demo/token')
    expect(init?.credentials).toBe('omit')
    expect(init?.redirect).toBe('error')
    expect(init?.body).toBe(JSON.stringify({ identity: 'viewer' }))
  })

  it('rejects an expired in-memory token even for the matching identity', () => {
    expect(sessionValid({ identity: 'viewer', accessToken: 'expired', expiresAtUtc: '2020-01-01T00:00:00Z' }, 'viewer')).toBe(false)
  })
})

describe('audit cursor handling', () => {
  it('uses a bounded page size and never puts the Admin JWT in the URL', async () => {
    vi.mocked(fetch).mockReturnValue(respond({ items: [], nextCursor: null }))
    await fetchAudit('admin-secret', 42)
    const [url, init] = vi.mocked(fetch).mock.calls[0]
    expect(String(url)).toContain('limit=25&cursor=42')
    expect(String(url)).not.toContain('admin-secret')
    expect((init?.headers as Record<string, string>).Authorization).toBe('Bearer admin-secret')
  })

  it('looks up one Terminal event without pagination or token URL leakage', async () => {
    const id = 'a'.repeat(32)
    vi.mocked(fetch).mockReturnValue(respond({ correlationId: id, enforcement: 'Blocked' }))
    const found = await findTerminalEvent('admin-secret', id)
    expect(found?.enforcement).toBe('Blocked')
    expect(vi.mocked(fetch)).toHaveBeenCalledTimes(1)
    const [url, init] = vi.mocked(fetch).mock.calls[0]
    expect(String(url)).toBe(`http://127.0.0.1:5077/api/audit/terminal/${id}`)
    expect(String(url)).not.toContain('admin-secret')
    expect((init?.headers as Record<string, string>).Authorization).toBe('Bearer admin-secret')
  })

  it('returns no record on 404 and rejects malformed IDs before a request', async () => {
    vi.mocked(fetch).mockReturnValue(Promise.resolve({ ok: false, status: 404 } as Response))
    expect(await findTerminalEvent('admin-secret', 'a'.repeat(32))).toBeNull()
    expect(await findTerminalEvent('admin-secret', 'not-an-id')).toBeNull()
    expect(vi.mocked(fetch)).toHaveBeenCalledTimes(1)
  })
})
