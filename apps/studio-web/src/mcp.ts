import { API_ORIGIN } from './api'
import type { Scenario } from './scenarios'

export interface ExecutionMeta {
  correlationId: string
  decision: 'Allow' | 'Deny'
  reasonCode: string
  enforcement: 'Blocked' | 'Forwarded'
  upstreamStatus: string
}

export interface ToolExecution {
  isError: boolean
  contentBlocks: number
  meta: ExecutionMeta | null
}

function executionMeta(value: unknown): ExecutionMeta | null {
  if (!value || typeof value !== 'object') return null
  const meta = (value as Record<string, unknown>).accessControlStudio
  if (!meta || typeof meta !== 'object') return null
  const fields = meta as Record<string, unknown>
  if (typeof fields.correlationId !== 'string' ||
      !/^[a-f0-9]{32}$/.test(fields.correlationId) ||
      (fields.decision !== 'Allow' && fields.decision !== 'Deny') ||
      typeof fields.reasonCode !== 'string' ||
      (fields.enforcement !== 'Blocked' && fields.enforcement !== 'Forwarded') ||
      typeof fields.upstreamStatus !== 'string') return null
  return fields as unknown as ExecutionMeta
}

export async function executeScenario(token: string, scenario: Scenario, signal: AbortSignal): Promise<ToolExecution> {
  const [{ Client }, { StreamableHTTPClientTransport }] = await Promise.all([
    import('@modelcontextprotocol/sdk/client/index.js'),
    import('@modelcontextprotocol/sdk/client/streamableHttp.js'),
  ])
  const client = new Client({ name: 'access-control-studio-web', version: '0.3.0' })
  const transport = new StreamableHTTPClientTransport(new URL('/mcp', API_ORIGIN), {
    requestInit: {
      headers: { Authorization: `Bearer ${token}` },
      credentials: 'omit',
      redirect: 'error',
      cache: 'no-store',
    },
    fetch: (input, init) => fetch(input, {
      ...init,
      credentials: 'omit',
      redirect: 'error',
      signal: init?.signal && signal ? AbortSignal.any([init.signal, signal]) : signal,
    }),
  })
  try {
    await client.connect(transport)
    const result = await client.callTool({ name: scenario.tool, arguments: scenario.arguments }, undefined,
      { signal, timeout: 15_000 })
    return {
      isError: result.isError === true,
      contentBlocks: Array.isArray(result.content) ? result.content.length : 0,
      meta: executionMeta(result._meta),
    }
  } finally {
    try { await client.close() } catch { /* A closed or canceled transport needs no retry. */ }
  }
}

export function executionError(error: unknown): string {
  if (error && typeof error === 'object' && 'code' in error) {
    const code = (error as { code: unknown }).code
    if (code === 401) return 'The demo session expired or was rejected. Select the identity and try again.'
    if (code === 403) return 'This MCP request was rejected at the HTTP boundary.'
  }
  if (error instanceof DOMException && error.name === 'AbortError') return 'Request canceled.'
  return 'The MCP call could not be completed. The upstream outcome may be unknown.'
}
