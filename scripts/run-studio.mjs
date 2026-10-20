import { spawnSync } from 'node:child_process'
import { resolve } from 'node:path'
import { startLocalRuntime } from '../apps/studio-web/scripts/local-runtime.mjs'

const repo = resolve(import.meta.dirname, '..')
const web = resolve(repo, 'apps', 'studio-web')
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm'

for (const [command, args, cwd] of [
  ['dotnet', ['restore'], repo],
  ['dotnet', ['build', '-c', 'Release', '--no-restore'], repo],
  [npm, ['ci'], web],
]) {
  const run = spawnSync(command, args, { cwd, stdio: 'inherit', shell: process.platform === 'win32' && command === npm })
  if (run.status !== 0) process.exit(run.status || 1)
}

let runtime
try {
  runtime = await startLocalRuntime({ persistent: true })
  console.log('Studio ready: http://127.0.0.1:5173/')
  console.log('Local Development only. Press Ctrl+C to stop both services.')
  await new Promise(resolve => {
    process.once('SIGINT', resolve)
    process.once('SIGTERM', resolve)
  })
} catch (error) {
  console.error(`Studio startup failed (${error?.name || 'Error'}).`)
  process.exitCode = 1
} finally {
  if (runtime) await runtime.close()
}
