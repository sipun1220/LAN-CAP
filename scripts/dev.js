'use strict';
/* One-command dev startup: runs the Node API (server/) and the Vite
 * dev server (client/) together with prefixed, color-coded output.
 * Usage:  npm run dev        (from lan-cap/)
 * Stops both with Ctrl+C.
 *
 * Preflight: before spawning, any stale instance of this project still
 * holding the API/web ports is killed (Windows taskkill /T for the whole
 * tree). A foreign process on those ports is reported instead of killed.
 */
const { spawn, execFile } = require('child_process');
const fs = require('fs');
const net = require('net');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const IS_WIN = process.platform === 'win32';

const JOBS = [
  { name: 'api', cmd: 'npm start --prefix server', color: '\x1b[36m' },
  { name: 'web', cmd: 'npm run dev --prefix client', color: '\x1b[35m' },
];

const children = new Set();
let shuttingDown = false;

/* ---------- port helpers ---------- */

function readApiPort() {
  const env = path.join(ROOT, 'server', '.env');
  try {
    const m = fs.readFileSync(env, 'utf8').match(/^\s*PORT\s*=\s*(\d+)/m);
    if (m) return Number(m[1]);
  } catch { /* no .env */ }
  return 5174;
}

function readWebPort() {
  const cfg = path.join(ROOT, 'client', 'vite.config.js');
  try {
    const m = fs.readFileSync(cfg, 'utf8').match(/port\s*:\s*(\d+)/);
    if (m) return Number(m[1]);
  } catch { /* no vite config */ }
  return 5173;
}

function run(cmd, args) {
  return new Promise((resolve) => {
    const p = spawn(cmd, args, { windowsHide: true, stdio: 'ignore' });
    p.on('exit', (code) => resolve(code === null ? -1 : code));
    p.on('error', () => resolve(-1));
  });
}

/* PIDs listening on a TCP port. */
async function listenersOn(port) {
  if (IS_WIN) {
    const out = await new Promise((resolve) => {
      execFile('netstat', ['-ano', '-p', 'TCP'], { windowsHide: true, maxBuffer: 8 << 20 }, (_e, so) => resolve(so || ''));
    });
    const pids = new Set();
    for (const line of out.split(/\r?\n/)) {
      if (!/LISTENING/i.test(line)) continue;
      const m = line.trim().match(/:(\d+)\s+\S+\s+LISTENING\s+(\d+)/i);
      if (m && Number(m[1]) === port) pids.add(Number(m[2]));
    }
    return [...pids];
  }
  const out = await new Promise((resolve) => {
    execFile('sh', ['-c', `lsof -nP -iTCP:${port} -sTCP:LISTEN -t 2>/dev/null`], (e, so) => resolve(so || ''));
  });
  return out.split(/\s+/).map(Number).filter(Boolean);
}

/* Command line of a PID, for identifying who owns the port. */
async function describePid(pid) {
  if (IS_WIN) {
    const out = await new Promise((resolve) => {
      execFile('powershell', ['-NoProfile', '-Command',
        `(Get-CimInstance Win32_Process -Filter "ProcessId=${pid}" -ErrorAction SilentlyContinue).CommandLine`],
        { windowsHide: true, maxBuffer: 1 << 20 }, (_e, so) => resolve(so || ''));
    });
    return out.trim();
  }
  const out = await new Promise((resolve) => {
    execFile('sh', ['-c', `ps -p ${pid} -o command= 2>/dev/null`], (_e, so) => resolve(so || ''));
  });
  return out.trim();
}

/* True when the PID belongs to this project's dev stack. */
function isProjectProcess(cmdline) {
  if (!cmdline) return false;
  const c = cmdline.toLowerCase();
  return c.includes('server.js') || c.includes('vite') || c.includes('scripts\\dev.js')
    || c.includes('scripts/dev.js') || c.includes('lan-cap');
}

/* Kill a PID and every descendant. Windows needs taskkill /T; POSIX walks
 * the tree with ps. `child.kill()` alone is not enough on either platform. */
async function killTree(pid) {
  if (!pid) return;
  if (IS_WIN) {
    await run('taskkill', ['/pid', String(pid), '/T', '/F']);
    return;
  }
  const out = await new Promise((resolve) => {
    execFile('sh', ['-c', `pgrep -P ${pid} 2>/dev/null`], (_e, so) => resolve(so || ''));
  });
  for (const childPid of out.split(/\s+/).map(Number).filter(Boolean)) {
    await killTree(childPid);
  }
  try { process.kill(pid, 'SIGKILL'); } catch { /* already gone */ }
}

function portFree(port) {
  return new Promise((resolve) => {
    const sock = net.connect({ port, host: '127.0.0.1' });
    sock.setTimeout(600);
    sock.on('connect', () => { sock.destroy(); resolve(false); });
    sock.on('timeout', () => { sock.destroy(); resolve(true); });
    sock.on('error', () => resolve(true));
  });
}

async function waitForPort(port, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await portFree(port)) return true;
    await new Promise((r) => setTimeout(r, 200));
  }
  return false;
}

/* ---------- preflight ---------- */

async function preflight() {
  const ports = [
    { label: 'API', port: readApiPort() },
    { label: 'web', port: readWebPort() },
  ];
  for (const { label, port } of ports) {
    const pids = await listenersOn(port);
    if (!pids.length) continue;
    for (const pid of pids) {
      const cmdline = await describePid(pid);
      if (isProjectProcess(cmdline)) {
        console.log(`Port ${port} (${label}) held by a stale LAN-CAP process (PID ${pid}) — stopping it.`);
        await killTree(pid);
      } else {
        console.error(`Port ${port} (${label}) is in use by PID ${pid}, which is not part of this project.`);
        console.error(`  ${cmdline || '(command line unavailable)'}`);
        console.error(`  Free the port, or change it in client/vite.config.js / server/.env, then retry.`);
        process.exit(1);
      }
    }
    if (!(await waitForPort(port))) {
      console.error(`Port ${port} (${label}) is still in use after cleanup.`);
      process.exit(1);
    }
  }
}

/* ---------- run ---------- */

function log(job, chunk) {
  const lines = String(chunk).split(/\r?\n/);
  for (const line of lines) {
    if (!line.trim()) continue;
    process.stdout.write(`${job.color}[${job.name}]\x1b[0m ${line}\n`);
  }
}

function startJob(job) {
  // String command + shell:true: avoids Node DEP0190 (args array + shell)
  // and lets Windows resolve npm.cmd correctly.
  const child = spawn(job.cmd, {
    cwd: ROOT,
    shell: true,
    windowsHide: true,
  });
  child.jobName = job.name;
  children.add(child);
  child.stdout.on('data', (d) => log(job, d));
  child.stderr.on('data', (d) => log(job, d));
  child.on('exit', (code, signal) => {
    children.delete(child);
    if (shuttingDown) return;
    const reason = signal ? `signal ${signal}` : `code ${code}`;
    console.log(`[${job.name}] exited (${reason}) — stopping the other process.`);
    shutdown(code === 0 ? 0 : 1);
  });
  child.on('error', (err) => {
    console.error(`[${job.name}] failed to start: ${err.message}`);
    shutdown(1);
  });
}

function shutdown(code) {
  if (shuttingDown) return;
  shuttingDown = true;
  for (const child of children) {
    // Kill the tree: on Windows the direct child is a cmd.exe wrapper whose
    // kill does NOT propagate to npm/node grandchildren (they get orphaned
    // and keep holding ports). taskkill /T handles that.
    if (IS_WIN) {
      try { spawn('taskkill', ['/pid', String(child.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' }); } catch { /* gone */ }
    } else {
      killTree(child.pid);
    }
  }
  // Give children a moment to exit, then force out.
  setTimeout(() => process.exit(code), 800).unref();
}

process.on('SIGINT', () => shutdown(0));
process.on('SIGTERM', () => shutdown(0));

preflight()
  .then(() => {
    console.log('Starting LAN-CAP — API (server/) + Web (client/). Ctrl+C stops both.');
    for (const job of JOBS) startJob(job);
  })
  .catch((err) => {
    console.error(`Preflight failed: ${err.message}`);
    process.exit(1);
  });
