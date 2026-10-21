import { spawn } from 'node:child_process'
import { randomBytes, randomUUID } from 'node:crypto'
import { mkdir, unlink } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

const webRoot = resolve(import.meta.dirname, '..')
const repoRoot = resolve(webRoot, '..', '..')
const apiDll = join(repoRoot, 'src', 'AccessControlStudio.Api', 'bin', 'Release', 'net10.0', 'AccessControlStudio.Api.dll')
const viteBin = join(webRoot, 'node_modules', 'vite', 'bin', 'vite.js')

async function ready(url, process, expected) {
  for (let attempt = 0; attempt < 150; attempt++) {
    if (process.exitCode !== null) throw new Error('A local service exited before readiness.')
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(1000), redirect: 'error' })
      if (response.status === expected) return
    } catch { /* The listener is starting. */ }
    await new Promise(resolve => setTimeout(resolve, 100))
  }
  throw new Error('A local service did not become ready.')
}

async function stop(child) {
  if (!child || child.exitCode !== null) return
  child.kill()
  await Promise.race([
    new Promise(resolve => child.once('exit', resolve)),
    new Promise(resolve => setTimeout(resolve, 3000)),
  ])
  if (child.exitCode === null) child.kill('SIGKILL')
}

export async function startLocalRuntime({ persistent = false } = {}) {
  const auditPath = persistent
    ? join(repoRoot, '.local-data', 'security-audit.db')
    : join(tmpdir(), 'AccessControlStudio.WebE2E', `${randomUUID()}.db`)
  await mkdir(resolve(auditPath, '..'), { recursive: true })
  const api = spawn('dotnet', [apiDll, '--urls', 'http://127.0.0.1:5077'], {
    cwd: repoRoot,
    env: {
      ...process.env,
      ASPNETCORE_ENVIRONMENT: 'Development',
      Jwt__SigningKey: randomBytes(64).toString('base64'),
      Audit__DatabasePath: auditPath,
    },
    stdio: 'ignore',
    windowsHide: true,
  })
  try {
    await ready('http://127.0.0.1:5077/api/security/policy', api, 401)
    const web = spawn(process.execPath, [viteBin, '--host', '127.0.0.1', '--port', '5173', '--strictPort'], {
      cwd: webRoot, stdio: 'ignore', windowsHide: true,
    })
    try {
      await ready('http://127.0.0.1:5173/', web, 200)
      return {
        async close() {
          await stop(web)
          await stop(api)
          if (!persistent) for (const suffix of ['', '-wal', '-shm']) {
            try { await unlink(auditPath + suffix) } catch { /* It may not exist. */ }
          }
        },
      }
    } catch (error) { await stop(web); throw error }
  } catch (error) { await stop(api); throw error }
}
