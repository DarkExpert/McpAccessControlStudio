import type { Identity } from './scenarios'

export const API_ORIGIN = import.meta.env.VITE_API_ORIGIN || 'http://127.0.0.1:5077'

export interface TokenSession { identity: Identity; accessToken: string; expiresAtUtc: string }
export interface ToolPolicy { name: string; allowedRoles: string[]; maximumAmount: number | null }
export interface AuditEvent {
  id: number
  correlationId: string
  kind: 'Decision' | 'Terminal'
  timestampUtc: string
  subject: string
  role: string
  toolName: string
  decision: 'Allow' | 'Deny'
  reasonCode: string
  enforcement: 'Pending' | 'Blocked' | 'Forwarded'
  upstreamStatus: string
  errorCategory: string | null
  durationMs: number
}
export interface AuditPage { items: AuditEvent[]; nextCursor: number | null }
export interface SecurityOverview {
  persistedTerminalCount: number
  allowed: number
  denied: number
  forwarded: number
  blocked: number
  succeeded: number
  toolErrors: number
  unknown: number
}

export class ApiError extends Error {
  constructor(readonly status: number) { super(`Request failed with status ${status}`) }
}

function apiUrl(path: string): string { return new URL(path, API_ORIGIN).toString() }

async function request<T>(path: string, init: RequestInit, signal?: AbortSignal): Promise<T> {
  const response = await fetch(apiUrl(path), {
    ...init,
    signal,
    mode: 'cors',
    credentials: 'omit',
    redirect: 'error',
    cache: 'no-store',
  })
  if (!response.ok) throw new ApiError(response.status)
  return response.json() as Promise<T>
}

export function issueDemoToken(identity: Identity, signal?: AbortSignal): Promise<TokenSession> {
  return request<TokenSession>('/api/demo/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ identity }),
  }, signal).then(value => ({ ...value, identity }))
}

function authorized(token: string): RequestInit {
  return { headers: { Authorization: `Bearer ${token}` } }
}

export function fetchPolicy(token: string, signal?: AbortSignal): Promise<ToolPolicy[]> {
  return request('/api/security/policy', authorized(token), signal)
}

export function fetchOverview(token: string, signal?: AbortSignal): Promise<SecurityOverview> {
  return request('/api/security/overview', authorized(token), signal)
}

export function fetchAudit(token: string, cursor?: number, signal?: AbortSignal): Promise<AuditPage> {
  const query = new URLSearchParams({ limit: '25' })
  if (cursor !== undefined) query.set('cursor', String(cursor))
  return request(`/api/audit?${query}`, authorized(token), signal)
}

export async function findTerminalEvent(token: string, correlationId: string, signal?: AbortSignal): Promise<AuditEvent | null> {
  let cursor: number | undefined
  for (let page = 0; page < 3; page++) {
    const query = new URLSearchParams({ limit: '100' })
    if (cursor !== undefined) query.set('cursor', String(cursor))
    const result = await request<AuditPage>(`/api/audit?${query}`, authorized(token), signal)
    const found = result.items.find(entry => entry.kind === 'Terminal' && entry.correlationId === correlationId)
    if (found) return found
    if (result.nextCursor === null) return null
    cursor = result.nextCursor
  }
  return null
}

export function sessionValid(session: TokenSession | null, identity: Identity): session is TokenSession {
  return session?.identity === identity && Date.parse(session.expiresAtUtc) > Date.now() + 15_000
}
