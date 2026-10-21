import { useEffect, useRef, useState } from 'react'
import {
  Activity, ArrowDownRight, ArrowRight, ArrowUpRight, BookOpen, Check, ChevronLeft,
  ChevronRight, CircleAlert, Clock3, Database, Fingerprint, KeyRound, LayoutDashboard,
  LockKeyhole, Play, RefreshCw, Shield, ShieldCheck, ShieldX, Terminal, Users, Wrench,
} from 'lucide-react'
import {
  ApiError, fetchAudit, fetchOverview, fetchPolicy, findTerminalEvent, issueDemoToken,
  sessionValid,
} from './api'
import type { AuditEvent, AuditPage, SecurityOverview, TokenSession, ToolPolicy } from './api'
import { executeScenario, executionError } from './mcp'
import type { ToolExecution } from './mcp'
import { identities, scenarios, toolLabels } from './scenarios'
import type { Identity, Scenario } from './scenarios'

type View = 'overview' | 'roles' | 'permissions' | 'audit' | 'playground'
type RunRecord = {
  identity: Identity
  scenario: Scenario
  execution: ToolExecution
  terminal: AuditEvent | null
  auditState: 'not-enabled' | 'persisted' | 'missing' | 'unavailable'
}

const navigation = [
  { id: 'overview', label: 'Security Overview', icon: LayoutDashboard },
  { id: 'roles', label: 'Users & Roles', icon: Users },
  { id: 'permissions', label: 'Tool Permissions', icon: ShieldCheck },
  { id: 'audit', label: 'Audit History', icon: Database },
  { id: 'playground', label: 'Security Playground', icon: Terminal },
] as const

function requestMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 401) return 'Session expired or authentication failed. Reconnect the demo identity.'
    if (error.status === 403) return 'This identity cannot access global security reporting.'
    if (error.status === 503) return 'Audit storage is unavailable. Counts may be incomplete.'
  }
  return 'Unable to reach the local API. Start the .NET gateway and try again.'
}

function StatusPill({ value }: { value: string }) {
  const normalized = value.toLowerCase()
  const tone = ['allow', 'allowed', 'succeeded', 'forwarded'].includes(normalized) ? 'good'
    : ['deny', 'denied', 'blocked', 'toolerror', 'unknown'].includes(normalized) ? 'bad' : 'neutral'
  return <span className={`pill ${tone}`}>{value}</span>
}

function EmptyState({ icon: Icon, title, detail, action }: {
  icon: typeof Shield; title: string; detail: string; action?: React.ReactNode
}) {
  return <div className="empty-state"><div className="empty-icon"><Icon size={24} /></div>
    <h3>{title}</h3><p>{detail}</p>{action}</div>
}

function SectionHeading({ eyebrow, title, detail, side }: {
  eyebrow: string; title: string; detail: string; side?: React.ReactNode
}) {
  return <div className="section-heading"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1><p>{detail}</p></div>{side}</div>
}

function formatTime(value: string): string {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? '—' : new Intl.DateTimeFormat(undefined,
    { dateStyle: 'medium', timeStyle: 'medium' }).format(date)
}

function scheduleExpiry(expiresAtUtc: string, onExpire: () => void): () => void {
  let timer: number | undefined
  const schedule = () => {
    const remaining = Date.parse(expiresAtUtc) - Date.now()
    if (remaining <= 0) { onExpire(); return }
    timer = window.setTimeout(schedule, Math.min(remaining, 2_147_483_647))
  }
  schedule()
  return () => window.clearTimeout(timer)
}

function RoleMatrix({ policy }: { policy: ToolPolicy[] }) {
  return <div className="matrix-wrap"><table className="matrix-table"><thead><tr>
    <th>Tool</th>{identities.map(person => <th key={person.id}>{person.name}</th>)}<th>Condition</th>
  </tr></thead><tbody>{policy.map(tool => <tr key={tool.name}>
    <td><strong>{toolLabels[tool.name] || tool.name}</strong><span className="mono subline">{tool.name}</span></td>
    {identities.map(person => <td key={person.id}><span className={`matrix-mark ${tool.allowedRoles.includes(person.name) ? 'yes' : 'no'}`}>
      {tool.allowedRoles.includes(person.name) ? <Check size={15} /> : <LockKeyhole size={14} />}
      {tool.allowedRoles.includes(person.name) ? 'Allowed' : 'Denied'}
    </span></td>)}
    <td className="condition">{tool.maximumAmount === null ? 'No amount condition' : `Amount ≤ ${tool.maximumAmount.toLocaleString()}`}</td>
  </tr>)}</tbody></table></div>
}

function ReportingGate({ onEnable, busy, error }: { onEnable: () => void; busy: boolean; error: string | null }) {
  return <div className="report-gate"><div className="gate-symbol"><LockKeyhole size={25} /></div>
    <div className="eyebrow">RESTRICTED DATA</div><h2>Open an Admin reporting session</h2>
    <p>Global security records are only available with a validated Admin JWT. This session is separate from the identity used for Playground calls.</p>
    <button className="primary-button" disabled={busy} onClick={onEnable}>
      <KeyRound size={16} /> {busy ? 'Connecting…' : 'Enable Admin reporting'}
    </button>{error && <p className="inline-error" role="alert">{error}</p>}
    <div className="gate-note"><Shield size={15} /> Local Development demo only · token held in memory</div>
  </div>
}

function OverviewView({ data, loading, error, refresh }: {
  data: SecurityOverview | null; loading: boolean; error: string | null; refresh: () => void
}) {
  if (loading && !data) return <EmptyState icon={RefreshCw} title="Loading persisted activity" detail="Reading the Admin-only overview from SQLite." />
  if (error && !data) return <EmptyState icon={CircleAlert} title="Overview unavailable" detail={error} action={<button className="secondary-button" onClick={refresh}>Try again</button>} />
  if (!data || data.persistedTerminalCount === 0) return <EmptyState icon={Activity} title="No terminal records yet" detail="Run a Playground scenario, then refresh this view to see persisted outcomes." action={<button className="secondary-button" onClick={refresh}>Refresh overview</button>} />
  const total = data.persistedTerminalCount
  const rows = [
    { label: 'Allowed', count: data.allowed, className: 'bar-teal' },
    { label: 'Denied', count: data.denied, className: 'bar-red' },
    { label: 'Tool error', count: data.toolErrors, className: 'bar-amber' },
    { label: 'Unknown upstream', count: data.unknown, className: 'bar-slate' },
  ]
  return <><div className="metrics-grid">
    <div className="metric-card"><div className="metric-top"><span>Persisted terminal records</span><Database size={19} /></div><div className="metric-number">{total}</div><div className="metric-caption">Stored outcomes within retention</div></div>
    <div className="metric-card"><div className="metric-top"><span>Allowed decisions</span><ShieldCheck size={19} /></div><div className="metric-number mint">{data.allowed}</div><div className="metric-caption">From persisted terminal events</div></div>
    <div className="metric-card"><div className="metric-top"><span>Denied decisions</span><ShieldX size={19} /></div><div className="metric-number coral">{data.denied}</div><div className="metric-caption">Blocked by gateway policy</div></div>
    <div className="metric-card"><div className="metric-top"><span>Forwarded attempts</span><ArrowUpRight size={19} /></div><div className="metric-number">{data.forwarded}</div><div className="metric-caption">Not a physical invocation count</div></div>
  </div>
  <div className="two-column"><section className="surface-card"><div className="card-heading"><div><div className="eyebrow">DECISION MIX</div><h2>How the gateway responded</h2></div><button className="icon-button" aria-label="Refresh overview" onClick={refresh}><RefreshCw size={18} /></button></div>
    <div className="bar-list">{rows.map(row => <div className="bar-row" key={row.label}><div className="bar-label"><span>{row.label}</span><strong>{row.count}</strong></div><div className="bar-track"><div className={row.className} style={{ width: `${total ? Math.max(2, row.count / total * 100) : 0}%` }} /></div></div>)}</div>
  </section><section className="surface-card outcome-card"><div className="eyebrow">ENFORCEMENT OUTCOMES</div><h2>Execution boundary</h2>
    <div className="outcome-line"><span className="outcome-icon good"><ArrowUpRight size={18} /></span><div><strong>{data.forwarded} forwarded</strong><small>Allowed requests submitted to MCP upstream</small></div></div>
    <div className="outcome-line"><span className="outcome-icon bad"><ArrowDownRight size={18} /></span><div><strong>{data.blocked} blocked</strong><small>Denied before upstream invocation</small></div></div>
    <div className="outcome-line"><span className="outcome-icon neutral"><CircleAlert size={18} /></span><div><strong>{data.unknown} unknown</strong><small>Timeout or cancellation after forwarding</small></div></div>
    <p className="fine-print">All figures count persisted Terminal records only. Best-effort audit storage can miss events.</p>
  </section></div></>
}

function AuditView({ page, loading, error, cursorDepth, onNext, onBack, onRefresh }: {
  page: AuditPage | null; loading: boolean; error: string | null; cursorDepth: number
  onNext: () => void; onBack: () => void; onRefresh: () => void
}) {
  if (loading && !page) return <EmptyState icon={RefreshCw} title="Loading audit history" detail="Fetching the newest persisted records." />
  if (error && !page) return <EmptyState icon={CircleAlert} title="Audit history unavailable" detail={error} action={<button className="secondary-button" onClick={onRefresh}>Try again</button>} />
  if (!page?.items.length) return <EmptyState icon={Database} title="No records on this page" detail="Run a Playground scenario or return to the previous page." action={<button className="secondary-button" onClick={onRefresh}>Refresh</button>} />
  return <section className="surface-card table-card"><div className="card-heading"><div><div className="eyebrow">PERSISTED SQLITE EVENTS</div><h2>Recent decisions & outcomes</h2></div><button className="secondary-button small" onClick={onRefresh}><RefreshCw size={15} /> Refresh</button></div>
    {error && <p className="inline-error" role="alert">{error}</p>}
    <div className="audit-table-wrap"><table className="audit-table"><thead><tr><th>Timestamp</th><th>Identity</th><th>Tool</th><th>Event</th><th>Decision / reason</th><th>Enforcement</th><th>Upstream</th><th>Correlation ID</th></tr></thead>
      <tbody>{page.items.map(event => <tr key={event.id} className={event.kind === 'Terminal' ? 'terminal-row' : 'decision-row'}>
        <td className="timestamp">{formatTime(event.timestampUtc)}</td><td><strong>{event.subject}</strong><span className="subline">{event.role}</span></td>
        <td className="mono">{event.toolName}</td><td><span className={`event-kind ${event.kind.toLowerCase()}`}>{event.kind}</span></td>
        <td><StatusPill value={event.decision} /><span className="subline mono">{event.reasonCode}</span></td>
        <td><StatusPill value={event.enforcement} /></td><td>{event.upstreamStatus}<span className="subline">{event.errorCategory || '—'}</span></td>
        <td className="mono correlation-cell" title={event.correlationId}>{event.correlationId}</td>
      </tr>)}</tbody></table></div>
    <div className="table-footer"><span>Page {cursorDepth} · newest first · up to 25 records</span><div className="pager"><button disabled={cursorDepth === 1 || loading} onClick={onBack} aria-label="Previous page"><ChevronLeft size={18} /></button><button disabled={page.nextCursor === null || loading} onClick={onNext} aria-label="Next page"><ChevronRight size={18} /></button></div></div>
  </section>
}

function PlaygroundResult({ run }: { run: RunRecord }) {
  const meta = run.execution.meta
  const allowed = meta?.decision === 'Allow'
  return <section className={`result-card ${allowed ? 'result-allowed' : 'result-denied'}`} aria-live="polite">
    <div className="result-header"><span className={`result-icon ${allowed ? 'good' : 'bad'}`}>{allowed ? <ShieldCheck size={25} /> : <ShieldX size={25} />}</span><div>
      <div className="eyebrow">LIVE MCP RESULT · {run.identity.toUpperCase()}</div>
      <h2>{meta ? (allowed ? 'Allowed by gateway' : 'Denied by gateway') : 'MCP result received'}</h2>
      <p>{run.scenario.title} · {run.scenario.tool}</p></div><StatusPill value={run.execution.isError ? 'isError: true' : 'isError: false'} /></div>
    <div className="result-grid">
      <div><span>Authorization</span><strong>{meta?.decision || 'Unavailable'}</strong></div>
      <div><span>Reason code</span><strong className="mono">{meta?.reasonCode || 'Unavailable'}</strong></div>
      <div><span>Gateway enforcement</span><strong>{meta?.enforcement || 'Unavailable'}</strong></div>
      <div><span>Upstream status</span><strong>{meta?.upstreamStatus || 'Unavailable'}</strong></div>
      <div><span>MCP tool result</span><strong>{run.execution.isError ? 'Tool-level error' : 'Completed'}</strong></div>
      <div><span>Content blocks</span><strong>{run.execution.contentBlocks}</strong></div>
    </div>
    <div className="correlation-strip"><Fingerprint size={17} /><span>Correlation ID</span><code>{meta?.correlationId || 'Unavailable'}</code></div>
    <div className="audit-verification"><Database size={17} />
      {run.auditState === 'persisted' && run.terminal ? <span>Persisted Terminal audit: <strong>{run.terminal.enforcement}</strong> · {run.terminal.upstreamStatus} · {run.terminal.durationMs} ms</span>
        : run.auditState === 'not-enabled' ? <span>Enable the separate Admin reporting session to verify the persisted Terminal event.</span>
          : run.auditState === 'missing' ? <span>Terminal event was not found in the bounded audit lookup. Audit writes are best effort.</span>
            : <span>Persisted audit lookup is unavailable.</span>}
    </div>
    <p className="fine-print">CRM response payload is hidden in this dashboard. “Forwarded” does not establish an exact physical upstream invocation count.</p>
  </section>
}

export default function App() {
  const [view, setView] = useState<View>('playground')
  const [identity, setIdentity] = useState<Identity>('viewer')
  const [session, setSession] = useState<TokenSession | null>(null)
  const [reportingSession, setReportingSession] = useState<TokenSession | null>(null)
  const [policy, setPolicy] = useState<ToolPolicy[] | null>(null)
  const [policyError, setPolicyError] = useState<string | null>(null)
  const [overview, setOverview] = useState<SecurityOverview | null>(null)
  const [overviewError, setOverviewError] = useState<string | null>(null)
  const [overviewLoading, setOverviewLoading] = useState(false)
  const [audit, setAudit] = useState<AuditPage | null>(null)
  const [auditError, setAuditError] = useState<string | null>(null)
  const [auditLoading, setAuditLoading] = useState(false)
  const [auditCursors, setAuditCursors] = useState<(number | undefined)[]>([undefined])
  const [reportingBusy, setReportingBusy] = useState(false)
  const [reportingError, setReportingError] = useState<string | null>(null)
  const [scenarioId, setScenarioId] = useState('customer')
  const [running, setRunning] = useState(false)
  const [runError, setRunError] = useState<string | null>(null)
  const [run, setRun] = useState<RunRecord | null>(null)
  const active = useRef<AbortController | null>(null)
  const generation = useRef(0)
  const selectedScenario = scenarios.find(item => item.id === scenarioId) || scenarios[0]
  const reportingReady = sessionValid(reportingSession, 'admin')

  useEffect(() => {
    if (!session) return
    return scheduleExpiry(session.expiresAtUtc,
      () => setSession(current => current === session ? null : current))
  }, [session])

  useEffect(() => {
    if (!reportingSession) return
    return scheduleExpiry(reportingSession.expiresAtUtc, () => {
      setReportingSession(current => current === reportingSession ? null : current)
      setOverview(null); setAudit(null)
    })
  }, [reportingSession])

  useEffect(() => {
    const controller = new AbortController()
    let current = true
    setPolicy(null)
    setPolicyError(null)
    issueDemoToken(identity, controller.signal)
      .then(async issued => {
        if (!current) return
        setSession(issued)
        const descriptors = await fetchPolicy(issued.accessToken, controller.signal)
        if (current) setPolicy(descriptors)
      })
      .catch(error => { if (current && !controller.signal.aborted) setPolicyError(requestMessage(error)) })
    return () => { current = false; controller.abort() }
  }, [identity])

  function chooseIdentity(next: Identity) {
    if (next === identity) return
    generation.current++
    active.current?.abort()
    setIdentity(next)
    setSession(null)
    setReportingSession(null)
    setOverview(null)
    setAudit(null)
    setAuditCursors([undefined])
    setRun(null)
    setRunError(null)
    setReportingError(null)
    setRunning(false)
  }

  async function loadOverview(token: string, signal?: AbortSignal) {
    const current = generation.current
    setOverviewLoading(true); setOverviewError(null)
    try { const data = await fetchOverview(token, signal); if (current === generation.current && !signal?.aborted) setOverview(data) }
    catch (error) { if (current === generation.current && !signal?.aborted) {
      if (error instanceof ApiError && error.status === 401) { setReportingSession(null); setOverview(null); setAudit(null); setReportingError(requestMessage(error)) }
      else setOverviewError(requestMessage(error))
    } }
    finally { if (current === generation.current && !signal?.aborted) setOverviewLoading(false) }
  }

  async function loadAudit(token: string, cursor?: number, signal?: AbortSignal) {
    const current = generation.current
    setAuditLoading(true); setAuditError(null)
    try { const data = await fetchAudit(token, cursor, signal); if (current === generation.current && !signal?.aborted) setAudit(data) }
    catch (error) { if (current === generation.current && !signal?.aborted) {
      if (error instanceof ApiError && error.status === 401) { setReportingSession(null); setOverview(null); setAudit(null); setReportingError(requestMessage(error)) }
      else setAuditError(requestMessage(error))
    } }
    finally { if (current === generation.current && !signal?.aborted) setAuditLoading(false) }
  }

  async function enableReporting() {
    if (reportingBusy) return
    const current = generation.current
    const controller = new AbortController()
    active.current?.abort(); active.current = controller
    setReportingBusy(true); setReportingError(null)
    try {
      const issued = await issueDemoToken('admin', controller.signal)
      if (current !== generation.current || controller.signal.aborted) return
      setReportingSession(issued)
      await Promise.all([loadOverview(issued.accessToken, controller.signal), loadAudit(issued.accessToken, undefined, controller.signal)])
    } catch (error) {
      if (current === generation.current && !controller.signal.aborted) setReportingError(requestMessage(error))
    } finally { if (current === generation.current) setReportingBusy(false) }
  }

  async function runSelected() {
    if (running) return
    const current = generation.current
    const selectedIdentity = identity
    const scenario = selectedScenario
    const controller = new AbortController()
    active.current?.abort(); active.current = controller
    setRunning(true); setRun(null); setRunError(null)
    try {
      let token: string
      if (sessionValid(session, selectedIdentity)) token = session.accessToken
      else {
        const issued = await issueDemoToken(selectedIdentity, controller.signal)
        token = issued.accessToken
        if (current === generation.current) setSession(issued)
      }
      const execution = await executeScenario(token, scenario, controller.signal)
      if (controller.signal.aborted || current !== generation.current) return
      let terminal: AuditEvent | null = null
      let auditState: RunRecord['auditState'] = 'not-enabled'
      if (sessionValid(reportingSession, 'admin') && execution.meta?.correlationId) {
        try {
          terminal = await findTerminalEvent(reportingSession.accessToken, execution.meta.correlationId, controller.signal)
          auditState = terminal ? 'persisted' : 'missing'
        } catch { auditState = 'unavailable' }
      }
      if (controller.signal.aborted || current !== generation.current) return
      setRun({ identity: selectedIdentity, scenario, execution, terminal, auditState })
      if (sessionValid(reportingSession, 'admin')) void loadOverview(reportingSession.accessToken, controller.signal)
    } catch (error) {
      if (!controller.signal.aborted && current === generation.current) setRunError(executionError(error))
    } finally { if (current === generation.current) setRunning(false) }
  }

  const pageCursor = auditCursors[auditCursors.length - 1]
  function refreshOverview() { if (reportingReady) void loadOverview(reportingSession.accessToken) }
  function refreshAudit() { if (reportingReady) void loadAudit(reportingSession.accessToken, pageCursor) }
  function nextAuditPage() {
    if (!reportingReady || audit?.nextCursor === null || audit?.nextCursor === undefined) return
    const cursor = audit.nextCursor
    setAuditCursors(previous => [...previous, cursor]); void loadAudit(reportingSession.accessToken, cursor)
  }
  function previousAuditPage() {
    if (!reportingReady || auditCursors.length <= 1) return
    const previous = auditCursors.slice(0, -1)
    setAuditCursors(previous); void loadAudit(reportingSession.accessToken, previous[previous.length - 1])
  }

  return <div className="app-shell"><aside className="sidebar"><div className="brand"><div className="brand-mark"><Shield size={22} strokeWidth={2.4} /></div><div><strong>MCP Access</strong><span>CONTROL STUDIO</span></div></div>
    <div className="nav-label">WORKSPACE</div><nav aria-label="Main navigation">{navigation.map(item => {
      const Icon = item.icon
      return <button key={item.id} className={`nav-item ${view === item.id ? 'selected' : ''}`} onClick={() => setView(item.id)}><Icon size={18} /><span>{item.label}</span>{item.id === 'playground' && <span className="nav-new">LIVE</span>}</button>
    })}</nav>
    <div className="sidebar-bottom"><div className="sidebar-status"><span className="pulse-dot" /><div><strong>Local demo</strong><small>Real MCP · SQLite audit</small></div></div><div className="sidebar-foot">M3 SHOWCASE <span>·</span> .NET 10</div></div>
  </aside>
  <div className="main-shell"><header className="topbar"><div className="breadcrumb"><span>Studio</span><ChevronRight size={15} /><strong>{navigation.find(item => item.id === view)?.label}</strong></div><div className="topbar-right"><span className="environment"><span /> DEVELOPMENT</span><div className="avatar" title={`Selected Playground identity: ${identity}`}>{identity[0].toUpperCase()}</div></div></header>
    <main className="content">
      {view === 'playground' && <>
        <SectionHeading eyebrow="INTERACTIVE SECURITY LAB" title="Security Playground" detail="Choose a demo identity and run a real authenticated MCP tool call. The gateway decides the outcome." side={<div className="heading-chip"><Activity size={16} /> LIVE ENFORCEMENT</div>} />
        <div className="playground-layout"><div className="playground-main"><section className="surface-card selector-card"><div className="step-heading"><span>01</span><div><h2>Act as an identity</h2><p>Each role gets its own short-lived JWT. Changing identity clears all sessions and results.</p></div></div>
          <div className="identity-grid">{identities.map(person => <button key={person.id} className={`identity-option ${identity === person.id ? 'active' : ''}`} onClick={() => chooseIdentity(person.id)} aria-pressed={identity === person.id}><span className={`identity-avatar ${person.id}`}>{person.initials}</span><strong>{person.name}</strong><small>{person.summary}</small><span className="radio-dot" /></button>)}</div>
        </section><section className="surface-card selector-card"><div className="step-heading"><span>02</span><div><h2>Choose a scenario</h2><p>Safe, predefined inputs go through the actual MCP <code>tools/call</code> handler.</p></div></div>
          <div className="scenario-list">{scenarios.map(item => <button key={item.id} className={`scenario-option ${scenarioId === item.id ? 'active' : ''}`} onClick={() => { active.current?.abort(); setScenarioId(item.id); setRun(null); setRunError(null); setRunning(false) }} aria-pressed={scenarioId === item.id}><span className={`scenario-symbol ${item.category.toLowerCase()}`}>{item.category === 'Read' ? <BookOpen size={18} /> : item.category === 'Write' ? <Wrench size={18} /> : <LockKeyhole size={18} />}</span><span className="scenario-text"><strong>{item.title}</strong><small>{item.description}</small></span><span className="scenario-tag">{item.category}</span></button>)}</div>
        </section><div className="run-bar"><div><span className="eyebrow">READY TO EXECUTE</span><strong className="mono">{selectedScenario.tool}</strong></div><button className="primary-button run-button" disabled={running} onClick={() => void runSelected()}><Play size={17} fill="currentColor" />{running ? 'Running real MCP call…' : 'Run scenario'}<ArrowRight size={17} /></button></div>
        {runError && <div className="alert-error" role="alert"><CircleAlert size={19} />{runError}</div>}
        {run && <PlaygroundResult run={run} />}</div>
        <aside className="playground-aside"><section className="surface-card flow-card"><div className="eyebrow">THE SECURITY PATH</div><h2>What happens on Run</h2><div className="flow-list"><div><span>1</span><p><strong>Identity</strong><small>Short-lived role JWT</small></p></div><div><span>2</span><p><strong>Gateway</strong><small>JWT validation + policy</small></p></div><div><span>3</span><p><strong>Enforcement</strong><small>Block or forward via MCP</small></p></div><div><span>4</span><p><strong>Audit</strong><small>Decision + terminal record</small></p></div></div></section>
          <section className="surface-card insight-card"><div className="insight-icon"><ShieldCheck size={20} /></div><h3>Trust the execution path</h3><p>Results here come from the MCP handler. Policy evaluation alone never counts as a tool execution.</p><div className="insight-divider" /><p className="fine-print">Demo data is seeded. Successful forwarding is not an exactly-once guarantee.</p></section>
          {reportingReady && <div className="report-session-note"><KeyRound size={16} /> Admin reporting session active <span>· separate credential</span></div>}
        </aside></div>
      </>}
      {view === 'overview' && <><SectionHeading eyebrow="OBSERVABILITY" title="Security Overview" detail="A live summary of persisted terminal audit records. Storage is best effort, so counts are not a complete activity ledger." side={reportingReady ? <span className="admin-indicator"><KeyRound size={15} /> Admin reporting</span> : undefined} />
        {reportingReady ? <OverviewView data={overview} loading={overviewLoading} error={overviewError} refresh={refreshOverview} /> : <ReportingGate onEnable={() => void enableReporting()} busy={reportingBusy} error={reportingError} />}</>}
      {view === 'roles' && <><SectionHeading eyebrow="IDENTITY MODEL" title="Users & Roles" detail="Three seeded identities for a local demonstration. These are presentation definitions, not a user directory." />
        <div className="role-cards">{identities.map((person, index) => <div className="surface-card role-card" key={person.id}><div className="role-card-top"><span className={`identity-avatar ${person.id}`}>{person.initials}</span><span className="demo-tag">SEEDED DEMO</span></div><h2>{person.name}</h2><p>{person.summary}</p><div className="role-card-footer"><span>Role tier 0{index + 1}</span><span>{policy ? `${policy.filter(tool => tool.allowedRoles.includes(person.name)).length} / ${policy.length} tools` : 'Policy loading'}</span></div></div>)}</div>
        <section className="surface-card matrix-card"><div className="card-heading"><div><div className="eyebrow">BACKEND POLICY</div><h2>Role access matrix</h2></div><span className="source-badge">LIVE POLICY API</span></div>{policy ? <RoleMatrix policy={policy} /> : <EmptyState icon={CircleAlert} title="Policy data unavailable" detail={policyError || 'Loading policy descriptors from the authenticated API.'} />}</section></>}
      {view === 'permissions' && <><SectionHeading eyebrow="AUTHORIZATION POLICY" title="Tool Permissions" detail="Read-only descriptors are derived from the same backend policy that enforces real MCP calls." />
        <div className="info-banner"><Shield size={19} /><span>The matrix describes eligibility. Actual decisions also depend on tool arguments and validated identity.</span></div>
        <section className="surface-card matrix-card"><div className="card-heading"><div><div className="eyebrow">FIVE CRM TOOLS</div><h2>Permissions by role</h2></div><span className="source-badge">LIVE POLICY API</span></div>{policy ? <RoleMatrix policy={policy} /> : <EmptyState icon={CircleAlert} title="Policy data unavailable" detail={policyError || 'Loading policy descriptors from the authenticated API.'} />}</section>
        {policy?.some(tool => tool.maximumAmount !== null) && <section className="surface-card rule-callout"><div className="rule-icon"><Wrench size={19} /></div><div><div className="eyebrow">CONDITIONAL RULE</div><h3>Bounded order updates</h3><p>Allowed roles may update an order only when its JSON amount is a nonnegative number at or below the backend limit. The gateway rejects missing, malformed, duplicate, and excessive values before forwarding.</p></div></section>}</>}
      {view === 'audit' && <><SectionHeading eyebrow="FORENSIC TRAIL" title="Audit History" detail="Real SQLite records in descending ID order. Decision/Pending rows precede the actual Terminal enforcement outcome." side={reportingReady ? <span className="admin-indicator"><KeyRound size={15} /> Admin reporting</span> : undefined} />
        {reportingReady ? <AuditView page={audit} loading={auditLoading} error={auditError} cursorDepth={auditCursors.length} onNext={nextAuditPage} onBack={previousAuditPage} onRefresh={refreshAudit} /> : <ReportingGate onEnable={() => void enableReporting()} busy={reportingBusy} error={reportingError} />}</>}
      <footer className="content-footer"><span><Clock3 size={14} /> Local demonstration · audit storage is best effort</span><span>MCP Access Control Studio / M3</span></footer>
    </main></div></div>
}
