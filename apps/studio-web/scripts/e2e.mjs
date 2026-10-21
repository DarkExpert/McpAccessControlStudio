import assert from 'node:assert/strict'
import { chromium } from '@playwright/test'
import { startLocalRuntime } from './local-runtime.mjs'

let runtime
let browser
let stage = 'startup'
try {
  runtime = await startLocalRuntime()
  browser = await chromium.launch({ headless: true })
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } })
  const toolSubjects = []
  const lookupSubjects = []
  page.on('request', request => {
    const toolCall = request.url().endsWith('/mcp') && request.method() === 'POST' &&
      request.postData()?.includes('tools/call')
    const lookup = request.url().includes('/api/audit/terminal/') && request.method() === 'GET'
    if (!toolCall && !lookup) return
    const authorization = request.headers().authorization || ''
    const payload = authorization.split('.')[1]
    if (!payload) return
    const subject = JSON.parse(Buffer.from(payload, 'base64url').toString()).sub
    if (toolCall) toolSubjects.push(subject)
    if (lookup) lookupSubjects.push(subject)
  })
  await page.goto('http://127.0.0.1:5173/', { waitUntil: 'networkidle' })
  assert.match(await page.title(), /MCP Access Control Studio/)

  async function runScenario(label, decision, reason) {
    stage = `scenario ${label}`
    await page.getByRole('button', { name: new RegExp(label, 'i') }).click()
    await page.getByRole('button', { name: /Run scenario/i }).click()
    await page.getByText(reason, { exact: true }).waitFor({ timeout: 20_000 })
    assert.equal(await page.getByText(decision, { exact: true }).count() > 0, true)
    assert.match(await page.locator('.correlation-strip code').innerText(), /^[a-f0-9]{32}$/)
  }

  await runScenario('Delete customer', 'Deny', 'RoleDenied')
  await runScenario('Read customer', 'Allow', 'Allowed')
  await page.getByRole('button', { name: /Operator Reads and bounded updates/i }).click()
  await runScenario('Update within limit', 'Allow', 'Allowed')
  await runScenario('Update above limit', 'Deny', 'AmountLimitExceeded')
  await page.getByRole('button', { name: /Admin Privileged demo identity/i }).click()
  await runScenario('Export customers', 'Allow', 'Allowed')
  if (process.env.STUDIO_SCREENSHOT_PATH)
    await page.screenshot({ path: process.env.STUDIO_SCREENSHOT_PATH, fullPage: true })

  stage = 'first Admin reporting session'
  await page.getByRole('button', { name: /Security Overview/i }).click()
  await page.getByRole('button', { name: /Enable Admin reporting/i }).click()
  await page.getByText('Persisted terminal records', { exact: true }).waitFor()
  const persisted = Number(await page.locator('.metric-card .metric-number').first().innerText())
  assert.ok(persisted >= 5)
  stage = 'Audit History'
  await page.getByRole('button', { name: /Audit History/i }).click()
  await page.getByText('Recent decisions & outcomes').waitFor()
  assert.ok(await page.locator('.event-kind.terminal').count() >= 5)

  await page.getByRole('button', { name: /Security Playground/i }).click()
  await runScenario('List orders', 'Allow', 'Allowed')
  await page.getByText('Persisted Terminal audit:', { exact: false }).waitFor()

  stage = 'Viewer identity reset'
  await page.getByRole('button', { name: /Viewer Read-only demo identity/i }).click()
  await page.getByRole('button', { name: /Security Overview/i }).click()
  await page.getByText('Open an Admin reporting session').waitFor()
  stage = 'second Admin reporting session'
  await page.getByRole('button', { name: /Enable Admin reporting/i }).click()
  await page.getByText('Persisted terminal records', { exact: true }).waitFor()
  await page.getByRole('button', { name: /Security Playground/i }).click()
  await runScenario('List orders', 'Allow', 'Allowed')
  await page.getByText('Persisted Terminal audit:', { exact: false }).waitFor()
  assert.deepEqual(toolSubjects, ['viewer', 'viewer', 'operator', 'operator', 'admin', 'admin', 'viewer'])
  assert.ok(lookupSubjects.length >= 2)
  assert.ok(lookupSubjects.every(subject => subject === 'admin'))
  stage = 'keyboard and narrow-screen navigation'
  await page.getByRole('button', { name: 'Security Overview' }).focus()
  await page.keyboard.press('Enter')
  await page.getByText('Persisted terminal records', { exact: true }).waitFor()
  await page.setViewportSize({ width: 390, height: 844 })
  await page.getByRole('button', { name: 'Audit History' }).click()
  await page.getByText('Recent decisions & outcomes').waitFor()
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1))
  console.log(`Real browser Playground passed: 7 MCP calls, ${persisted} initial persisted terminal records, direct correlated audit lookup, role isolation and Admin reporting verified.`)
} catch (error) {
  console.error(`Real browser Playground failed at ${stage} (${error?.name || 'Error'}).`)
  process.exitCode = 1
} finally {
  if (browser) await browser.close()
  if (runtime) await runtime.close()
}
