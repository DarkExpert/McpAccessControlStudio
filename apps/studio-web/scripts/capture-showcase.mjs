import assert from 'node:assert/strict'
import { copyFile, mkdir, unlink } from 'node:fs/promises'
import { resolve } from 'node:path'
import { chromium } from '@playwright/test'
import { startLocalRuntime } from './local-runtime.mjs'

const assets = resolve(import.meta.dirname, '..', '..', '..', 'docs', 'assets')
const hold = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds))
let runtime
let browser
let context
try {
  await mkdir(assets, { recursive: true })
  runtime = await startLocalRuntime()
  browser = await chromium.launch({ headless: true })
  context = await browser.newContext({
    viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1,
    recordVideo: { dir: assets, size: { width: 1440, height: 900 } },
  })
  const page = await context.newPage()
  await page.goto('http://127.0.0.1:5173/', { waitUntil: 'networkidle' })
  assert.match(await page.title(), /MCP Access Control Studio/)
  await hold(5000)

  async function runScenario(name, decision, reason) {
    await page.getByRole('button', { name: new RegExp(name, 'i') }).click()
    await page.getByRole('button', { name: /Run scenario/i }).click()
    await page.getByText(reason, { exact: true }).waitFor({ timeout: 20_000 })
    assert.ok(await page.getByText(decision, { exact: true }).count())
    assert.match(await page.locator('.correlation-strip code').innerText(), /^[a-f0-9]{32}$/)
  }

  async function screenshot(name, height = 1560) {
    // Match each view's content height so the sticky navigation and result stay in frame.
    await page.setViewportSize({ width: 1440, height })
    await page.mouse.move(1420, height - 20)
    await hold(400)
    await page.screenshot({ path: resolve(assets, name) })
    await page.setViewportSize({ width: 1440, height: 900 })
  }

  await runScenario('Delete customer', 'Deny', 'RoleDenied')
  await screenshot('playground-viewer-denied.png')
  await hold(11000)

  await page.getByRole('button', { name: /Admin Privileged demo identity/i }).click()
  await runScenario('Export customers', 'Allow', 'Allowed')
  await screenshot('playground-admin-allowed.png')
  await hold(11000)

  await page.getByRole('button', { name: /Security Overview/i }).click()
  await page.getByRole('button', { name: /Enable Admin reporting/i }).click()
  await page.getByText('Persisted terminal records', { exact: true }).waitFor()
  const persisted = Number(await page.locator('.metric-card .metric-number').first().innerText())
  assert.ok(persisted >= 2)
  await screenshot('security-overview.png', 900)
  await hold(13000)

  await page.getByRole('button', { name: /Audit History/i }).click()
  await page.getByText('Recent decisions & outcomes').waitFor()
  assert.ok(await page.locator('.event-kind.terminal').count() >= 2)
  await screenshot('audit-history.png', 900)
  await hold(13000)

  await page.getByRole('button', { name: /Tool Permissions/i }).click()
  await page.getByText('Permissions by role').waitFor()
  assert.equal(await page.locator('.matrix-table tbody tr').count(), 5)
  await screenshot('tool-permissions.png', 1080)
  await hold(13000)

  await page.getByRole('button', { name: /Security Playground/i }).click()
  await page.getByText('Allowed by gateway').waitFor()
  await hold(10000)

  const video = page.video()
  await context.close()
  context = null
  const source = await video.path()
  await copyFile(source, resolve(assets, 'showcase-v0.1.0.webm'))
  await unlink(source)
  console.log(`Captured five real UI screenshots and a Playwright WebM recording with ${persisted} persisted Terminal records.`)
} catch (error) {
  console.error(`Showcase capture failed (${error?.name || 'Error'}).`)
  process.exitCode = 1
} finally {
  if (context) await context.close()
  if (browser) await browser.close()
  if (runtime) await runtime.close()
}
