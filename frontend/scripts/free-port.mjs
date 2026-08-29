#!/usr/bin/env node
// Frees the given TCP port (default 5173) before `vite` starts, so a stale
// orphaned dev-server process (e.g. left behind when a terminal window was
// closed instead of Ctrl+C'd) never blocks the next `npm run dev`.
import { execSync } from 'node:child_process'

const port = process.argv[2] || '5173'

function killWindows(port) {
  let output
  try {
    // No `-p tcp` filter: Vite listens on IPv6 loopback ([::1]:port), which
    // Windows reports under protocol TCPV6 — a proto filter of "tcp" hides
    // those rows entirely and this fails to find anything to kill.
    output = execSync(`netstat -ano`, { encoding: 'utf8' })
  } catch {
    return
  }
  const pids = new Set()
  for (const line of output.split('\n')) {
    const match = line.match(/^\s*TCPV?6?\s+\S*:(\d+)\s+\S+\s+LISTENING\s+(\d+)/i)
    if (match && match[1] === String(port)) {
      pids.add(match[2])
    }
  }
  for (const pid of pids) {
    try {
      execSync(`taskkill /F /PID ${pid}`, { stdio: 'ignore' })
      console.log(`[free-port] Killed stale process ${pid} on port ${port}`)
    } catch {
      // process already gone — ignore
    }
  }
}

function killPosix(port) {
  let pids
  try {
    pids = execSync(`lsof -ti tcp:${port}`, { encoding: 'utf8' }).trim()
  } catch {
    return
  }
  for (const pid of pids.split('\n').filter(Boolean)) {
    try {
      execSync(`kill -9 ${pid}`, { stdio: 'ignore' })
      console.log(`[free-port] Killed stale process ${pid} on port ${port}`)
    } catch {
      // process already gone — ignore
    }
  }
}

try {
  if (process.platform === 'win32') {
    killWindows(port)
  } else {
    killPosix(port)
  }
} catch {
  // never block `npm run dev` because of a cleanup failure
}
