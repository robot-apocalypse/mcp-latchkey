import crypto from 'node:crypto'
import fs from 'node:fs/promises'
import path from 'node:path'

// Serializes writes per destination and gives each write its own temp file.
// A single shared `${dest}.tmp` lets overlapping writers corrupt the temp file
// or make the second rename throw ENOENT (seen in gtasks-mcp as spurious 401s).
const chains = new Map<string, Promise<unknown>>()

async function writeOnce(dest: string, data: string): Promise<void> {
  await fs.mkdir(path.dirname(dest), { recursive: true })
  const tmp = `${dest}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`
  try {
    await fs.writeFile(tmp, data, { encoding: 'utf8', mode: 0o600 })
    await fs.rename(tmp, dest)
  } catch (e) {
    await fs.rm(tmp, { force: true }).catch(() => {})
    throw e
  }
}

/** `data` is captured at call time, so the bytes written reflect state when called. */
export function atomicWrite(dest: string, data: string): Promise<void> {
  const run = (chains.get(dest) ?? Promise.resolve()).then(
    () => writeOnce(dest, data),
    () => writeOnce(dest, data)
  )
  chains.set(dest, run.catch(() => {}))
  return run
}
