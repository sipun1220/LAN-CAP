'use strict';

const { execFile } = require('child_process');
const dns = require('dns').promises;
const net = require('net');
const { Resolver } = dns;

const PUBLIC_RESOLVERS = [
  ['1.1.1.1', 'Cloudflare'],
  ['1.0.0.1', 'Cloudflare'],
  ['8.8.8.8', 'Google'],
  ['8.8.4.4', 'Google'],
  ['9.9.9.9', 'Quad9'],
  ['208.67.222.222', 'OpenDNS'],
];

const CAMERA_VENDOR = /hikvision|dahua|axis|reolink|amcrest|foscam|wyze|tapo|kasa|ring|arlo|unifi|ubiquiti|hanwha|vivotek|bosch|swann|lorex|annke|ezviz|imou|aqara|eufy/i;
const CAMERA_WORD = /(^|[-_. ])(cam|ipcam|ip-cam|nvr|dvr|doorbell|webcam|camera)([-_. ]|$)|camera|webcam|doorbell/i;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function safeTarget(input) {
  let host = String(input || '').trim();
  if (!host) throw new Error('host is required');
  host = host.replace(/\.$/, '').toLowerCase();
  if (host.length > 253) throw new Error('host is too long');
  if (!/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(host)) {
    throw new Error('host must be a hostname or IPv4 address');
  }
  if (host.includes('..')) throw new Error('host contains an empty label');
  for (const label of host.split('.')) {
    if (!label || label.length > 63) throw new Error('invalid hostname label');
    if (!/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)) throw new Error('invalid hostname label');
  }
  return host;
}

function parsePingOutput(text) {
  const match = String(text || '').match(/\btime\s*([=<])\s*([\d.]+)\s*ms/i);
  if (match) return match[1] === '<' ? 0.5 : Number(match[2]);
  const compact = String(text || '').match(/([=<])\s*([\d.]+)\s*ms/i);
  if (!compact) return null;
  return compact[1] === '<' ? 0.5 : Number(compact[2]);
}

function pingArguments(host, timeoutMs) {
  if (process.platform === 'win32') return ['-n', '1', '-w', String(timeoutMs), host];
  if (process.platform === 'darwin') return ['-c', '1', '-W', String(timeoutMs), host];
  return ['-c', '1', '-W', String(Math.max(1, Math.ceil(timeoutMs / 1000))), host];
}

function pingOnce(host, timeoutMs) {
  return new Promise((resolve) => {
    const started = Date.now();
    execFile('ping', pingArguments(host, timeoutMs), {
      timeout: timeoutMs + 3000,
      windowsHide: true,
      maxBuffer: 256 * 1024,
    }, (error, stdout) => {
      const ms = parsePingOutput(stdout);
      const alive = !error && ms !== null;
      resolve({
        alive,
        ms,
        wallMs: Date.now() - started,
        error: error && error.code === 'ENOENT' ? 'ping command not found' : null,
      });
    });
  });
}

async function pingTool({ host, count = 4, timeoutMs = 1200 } = {}) {
  const target = safeTarget(host);
  const attempts = Math.max(1, Math.min(10, Number(count) || 4));
  const timeout = Math.max(250, Math.min(5000, Number(timeoutMs) || 1200));
  const samples = [];
  const sent = [];
  for (let i = 0; i < attempts; i += 1) {
    const result = await pingOnce(target, timeout);
    if (result.error) throw new Error(result.error);
    sent.push({ n: i + 1, alive: result.alive, ms: result.ms });
    if (result.alive && result.ms !== null) samples.push(result.ms);
    if (i < attempts - 1) await sleep(100);
  }
  const min = samples.length ? Math.min(...samples) : null;
  const max = samples.length ? Math.max(...samples) : null;
  const avg = samples.length ? samples.reduce((sum, value) => sum + value, 0) / samples.length : null;
  let jitter = null;
  if (samples.length > 1) {
    const deltas = samples.slice(1).map((value, i) => Math.abs(value - samples[i]));
    jitter = deltas.reduce((sum, value) => sum + value, 0) / deltas.length;
  }
  return {
    host: target,
    sent: attempts,
    received: samples.length,
    lossPct: Math.round(((attempts - samples.length) / attempts) * 100),
    min: min === null ? null : Number(min.toFixed(1)),
    avg: avg === null ? null : Number(avg.toFixed(1)),
    max: max === null ? null : Number(max.toFixed(1)),
    jitter: jitter === null ? null : Number(jitter.toFixed(1)),
    samples: sent,
  };
}

function parseTraceroute(text) {
  const hops = [];
  for (const line of String(text || '').split(/\r?\n/)) {
    const match = line.match(/^\s*(\d+)\s+(.+)$/);
    if (!match) continue;
    const rest = match[2];
    const ips = rest.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
    const ip = ips.find((value) => value !== '0.0.0.0') || '';
    const ms = [...rest.matchAll(/(?:<\s*)?([\d.]+)\s*ms/gi)].map((m) => Number(m[1]));
    if (!ip && !/\*/.test(rest)) continue;
    hops.push({
      hop: Number(match[1]),
      ip,
      ms,
      timeout: !ip && /\*/.test(rest),
    });
  }
  return hops;
}

function runExec(command, args, options) {
  return new Promise((resolve) => {
    execFile(command, args, options, (error, stdout, stderr) => {
      resolve({ error, stdout: stdout || '', stderr: stderr || '' });
    });
  });
}

async function tracerouteTool({ host, maxHops = 20, timeoutMs = 1200 } = {}) {
  const target = safeTarget(host);
  const hopsLimit = Math.max(1, Math.min(30, Number(maxHops) || 20));
  const wait = Math.max(250, Math.min(5000, Number(timeoutMs) || 1200));
  const isWindows = process.platform === 'win32';
  let command = isWindows ? 'tracert' : 'traceroute';
  let args = isWindows
    ? ['-d', '-h', String(hopsLimit), '-w', String(wait), target]
    : ['-n', '-m', String(hopsLimit), '-w', String(Math.max(1, Math.ceil(wait / 1000))), target];
  let result = await runExec(command, args, {
    timeout: (hopsLimit * (wait + 1200)) + 8000,
    windowsHide: true,
    maxBuffer: 1024 * 1024,
  });
  if (result.error && result.error.code === 'ENOENT' && !isWindows) {
    command = 'tracepath';
    args = ['-n', '-m', String(hopsLimit), target];
    result = await runExec(command, args, {
      timeout: (hopsLimit * (wait + 1200)) + 8000,
      windowsHide: true,
      maxBuffer: 1024 * 1024,
    });
  }
  if (result.error && result.error.code === 'ENOENT') {
    throw new Error(`${command} is not installed on this system`);
  }
  const output = result.stdout || result.stderr;
  const hops = parseTraceroute(output);
  return {
    host: target,
    command,
    maxHops: hopsLimit,
    hops,
    reached: Boolean(hops.length && hops[hops.length - 1].ip),
    output: output.slice(0, 24000),
    truncated: output.length > 24000,
    error: result.error && !hops.length ? (result.error.message || 'traceroute failed') : null,
  };
}

function withTimeout(promise, ms) {
  let timer;
  const timeout = new Promise((resolve) => {
    timer = setTimeout(() => resolve({ ok: false, error: 'timeout' }), ms);
  });
  const wrapped = Promise.resolve(promise)
    .then((value) => ({ ok: true, value }))
    .catch((error) => ({ ok: false, error: error.code || error.message || 'query failed' }));
  return Promise.race([wrapped, timeout]).finally(() => clearTimeout(timer));
}

function resolverLabel(server) {
  const known = PUBLIC_RESOLVERS.find(([ip]) => ip === server);
  return known ? known[1] : server;
}

async function queryServer(server, domain, timeoutMs) {
  const resolver = new Resolver();
  resolver.setServers([server]);
  const started = Date.now();
  const result = await withTimeout(resolver.resolve4(domain), timeoutMs);
  if (result.error === 'timeout') resolver.cancel();
  return {
    domain,
    ok: result.ok,
    ms: Date.now() - started,
    addresses: result.ok ? result.value : [],
    error: result.ok ? null : result.error,
  };
}

async function dnsBenchmark({ domain = 'example.com', timeoutMs = 1200 } = {}) {
  const target = safeTarget(domain);
  if (net.isIP(target)) throw new Error('domain name required');
  const wait = Math.max(200, Math.min(3000, Number(timeoutMs) || 1200));
  const system = dns.getServers().filter((server) => net.isIP(server));
  const servers = [];
  const seen = new Set();
  const add = (server) => {
    if (!server || seen.has(server) || !net.isIP(server)) return;
    seen.add(server);
    servers.push(server);
  };
  for (const server of system) add(server);
  for (const [server] of PUBLIC_RESOLVERS) add(server);
  const domains = [target, 'wikipedia.org', 'github.com'].filter((value, index, all) => all.indexOf(value) === index);
  const rows = await Promise.all(servers.map(async (server) => {
    const results = await Promise.all(domains.map((name) => queryServer(server, name, wait)));
    const ok = results.filter((result) => result.ok);
    const times = ok.map((result) => result.ms);
    const avg = times.length ? times.reduce((sum, value) => sum + value, 0) / times.length : null;
    return {
      server,
      label: resolverLabel(server),
      ok: ok.length > 0,
      avg: avg === null ? null : Math.round(avg),
      min: times.length ? Math.min(...times) : null,
      max: times.length ? Math.max(...times) : null,
      failures: results.filter((result) => !result.ok).length,
      results,
    };
  }));
  rows.sort((a, b) => {
    if (a.ok !== b.ok) return a.ok ? -1 : 1;
    return (a.avg ?? 99999) - (b.avg ?? 99999);
  });
  return { domain: target, domains, servers: rows, best: rows.find((row) => row.ok) || null, at: new Date().toISOString() };
}

async function dnsLookup({ host, timeoutMs = 3000 } = {}) {
  const target = safeTarget(host);
  const wait = Math.max(300, Math.min(8000, Number(timeoutMs) || 3000));
  if (net.isIP(target)) {
    const reverse = await withTimeout(dns.reverse(target), wait);
    return {
      host: target,
      isIp: true,
      servers: dns.getServers(),
      names: reverse.ok ? reverse.value : [],
      error: reverse.ok ? null : reverse.error,
      at: new Date().toISOString(),
    };
  }
  const queries = {
    a: () => dns.resolve4(target),
    aaaa: () => dns.resolve6(target),
    cname: () => dns.resolveCname(target),
    mx: () => dns.resolveMx(target),
    txt: () => dns.resolveTxt(target),
    ns: () => dns.resolveNs(target),
    soa: () => dns.resolveSoa(target),
  };
  const entries = await Promise.all(Object.entries(queries).map(async ([type, query]) => {
    const result = await withTimeout(query(), wait);
    let value = result.ok ? result.value : [];
    if (type === 'txt' && value) value = value.map((chunks) => chunks.join(''));
    return [type, { ok: result.ok, records: value, error: result.ok ? null : result.error }];
  }));
  const records = Object.fromEntries(entries);
  const found = Object.values(records).some((record) => record.ok && record.records && (
    Array.isArray(record.records) ? record.records.length > 0 : Object.keys(record.records).length > 0
  ));
  return {
    host: target,
    isIp: false,
    servers: dns.getServers(),
    records,
    ok: found,
    at: new Date().toISOString(),
  };
}

function parseNetshWifi(text) {
  const networks = [];
  let base = null;
  let current = null;
  const push = () => {
    if (current && current.bssid) networks.push(current);
    current = null;
  };
  for (const line of String(text || '').split(/\r?\n/)) {
    const ssid = line.match(/^\s*SSID\s+\d+\s*:\s*(.*)$/i);
    if (ssid) {
      push();
      base = { ssid: ssid[1].trim(), auth: '', encryption: '' };
      continue;
    }
    if (!base) continue;
    const auth = line.match(/^\s*Authentication\s*:\s*(.*)$/i);
    if (auth) { base.auth = auth[1].trim(); continue; }
    const encryption = line.match(/^\s*Encryption\s*:\s*(.*)$/i);
    if (encryption) { base.encryption = encryption[1].trim(); continue; }
    const bssid = line.match(/^\s*BSSID\s+\d+\s*:\s*(.*)$/i);
    if (bssid) {
      push();
      current = { ...base, bssid: bssid[1].trim(), signalPct: null, band: '', channel: null, radio: '' };
      continue;
    }
    if (!current) continue;
    const signal = line.match(/^\s*Signal\s*:\s*(\d+)%/i);
    if (signal) { current.signalPct = Number(signal[1]); continue; }
    const radio = line.match(/^\s*Radio type\s*:\s*(.*)$/i);
    if (radio) { current.radio = radio[1].trim(); continue; }
    const band = line.match(/^\s*Band\s*:\s*(.*)$/i);
    if (band) { current.band = band[1].trim(); continue; }
    const channel = line.match(/^\s*Channel\s*:\s*(\d+)/i);
    if (channel) { current.channel = Number(channel[1]); }
  }
  push();
  return networks;
}

function parseNmcliWifi(text) {
  const split = (line) => {
    const fields = [];
    let value = '';
    for (let i = 0; i < line.length; i += 1) {
      if (line[i] === '\\' && i + 1 < line.length) { value += line[i + 1]; i += 1; continue; }
      if (line[i] === ':') { fields.push(value); value = ''; continue; }
      value += line[i];
    }
    fields.push(value);
    return fields;
  };
  return String(text || '').split(/\r?\n/).filter(Boolean).map((line) => {
    const fields = split(line);
    const signal = Number(fields[3]);
    return {
      ssid: fields[0] || '',
      bssid: (fields[1] || '').toUpperCase(),
      channel: fields[2] ? Number(fields[2].split(',')[0]) : null,
      signalPct: Number.isFinite(signal) ? Math.max(0, Math.min(100, signal)) : null,
      auth: fields[4] || '',
      encryption: '',
      band: '',
      radio: '',
    };
  }).filter((network) => network.bssid);
}

function parseAirportWifi(text) {
  const networks = [];
  for (const line of String(text || '').split(/\r?\n/)) {
    const match = line.match(/^(.+?)\s+([0-9a-f]{2}(?::[0-9a-f]{2}){5})\s+(-?\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)$/i);
    if (!match) continue;
    const rssi = Number(match[3]);
    networks.push({
      ssid: match[1].trim(),
      bssid: match[2].toUpperCase(),
      signalPct: Math.max(0, Math.min(100, Math.round(2 * (rssi + 100)))),
      channel: Number(match[4].split(',')[0]) || null,
      radio: match[5],
      band: '',
      auth: match[7].trim(),
      encryption: '',
      rssi,
    });
  }
  return networks;
}

async function wifiScan(core) {
  let networks = [];
  let error = null;
  if (process.platform === 'win32') {
    const result = await runExec('netsh', ['wlan', 'show', 'networks', 'mode=bssid'], {
      timeout: 15000, windowsHide: true, maxBuffer: 1024 * 1024,
    });
    if (result.error) error = result.stderr.trim() || result.error.message;
    networks = parseNetshWifi(result.stdout);
  } else if (process.platform === 'darwin') {
    const airport = '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport';
    const result = await runExec(airport, ['-s'], { timeout: 20000, windowsHide: true, maxBuffer: 1024 * 1024 });
    if (result.error) error = result.stderr.trim() || result.error.message;
    networks = parseAirportWifi(result.stdout);
  } else {
    const result = await runExec('nmcli', ['-t', '-f', 'SSID,BSSID,CHAN,SIGNAL,SECURITY', 'dev', 'wifi', 'list', '--rescan', 'yes'], {
      timeout: 30000, windowsHide: true, maxBuffer: 1024 * 1024,
    });
    if (result.error) error = result.stderr.trim() || result.error.message;
    networks = parseNmcliWifi(result.stdout);
  }
  networks.sort((a, b) => (b.signalPct ?? -1) - (a.signalPct ?? -1));
  const connected = core && core.getWifiInfo ? core.getWifiInfo() : [];
  return { networks, connected, count: networks.length, error, platform: process.platform, at: new Date().toISOString() };
}

function arrayOf(value) {
  if (value === null || value === undefined) return [];
  return Array.isArray(value) ? value : [value];
}

async function windowsDhcp() {
  const script = [
    'Get-CimInstance Win32_NetworkAdapterConfiguration |',
    'Where-Object { $_.IPEnabled } |',
    'ForEach-Object { [pscustomobject]@{',
    'name=$_.Description; dhcpEnabled=[bool]$_.DHCPEnabled; dhcpServer=$_.DHCPServer;',
    'ips=@($_.IPAddress); gateways=@($_.DefaultIPGateway);',
    "leaseObtained=$(if ($_.DHCPLeaseObtained) { $_.DHCPLeaseObtained.ToString('o') } else { $null });",
    "leaseExpires=$(if ($_.DHCPLeaseExpires) { $_.DHCPLeaseExpires.ToString('o') } else { $null })",
    '} } | ConvertTo-Json -Depth 4 -Compress',
  ].join(' ');
  const result = await runExec('powershell', ['-NoProfile', '-NonInteractive', '-Command', script], {
    timeout: 15000, windowsHide: true, maxBuffer: 1024 * 1024,
  });
  if (result.error || !result.stdout.trim()) return [];
  try {
    return arrayOf(JSON.parse(result.stdout.trim()));
  } catch {
    return [];
  }
}

async function darwinDhcp(name) {
  if (!name) return null;
  const result = await runExec('ipconfig', ['getpacket', name], {
    timeout: 8000, windowsHide: true, maxBuffer: 256 * 1024,
  });
  if (result.error) return null;
  const fields = {};
  for (const line of result.stdout.split(/\r?\n/)) {
    const match = line.match(/^\s*([a-z_]+)\s*\([^)]*\)\s*:\s*(.*)$/i);
    if (match) fields[match[1]] = match[2].trim();
  }
  return fields;
}

async function dhcpInfo(core) {
  const interfaces = core && core.getInterfaces ? core.getInterfaces() : [];
  const parseCidr = core && core.parseCidr;
  const adapters = interfaces.map((iface) => {
    let gateway = null;
    try {
      gateway = parseCidr(iface.cidr).hosts[0] || null;
    } catch {
      gateway = null;
    }
    return {
      name: iface.name,
      ip: iface.ip,
      cidr: iface.cidr,
      gateway,
      dhcpEnabled: null,
      dhcpServer: null,
      leaseObtained: null,
      leaseExpires: null,
      leaseSeconds: null,
    };
  });
  if (process.platform === 'win32') {
    const rows = await windowsDhcp();
    for (const row of rows) {
      const rowIps = arrayOf(row.ips);
      const adapter = adapters.find((item) => rowIps.includes(item.ip));
      if (!adapter) continue;
      adapter.dhcpEnabled = row.dhcpEnabled;
      adapter.dhcpServer = row.dhcpServer || null;
      adapter.leaseObtained = row.leaseObtained || null;
      adapter.leaseExpires = row.leaseExpires || null;
      const gateways = arrayOf(row.gateways);
      if (!adapter.gateway && gateways.length) adapter.gateway = gateways[0];
    }
  } else if (process.platform === 'darwin') {
    for (const adapter of adapters) {
      const fields = await darwinDhcp(adapter.name);
      if (!fields) continue;
      adapter.dhcpEnabled = true;
      adapter.dhcpServer = fields.server_identifier || null;
      adapter.gateway = fields.router || adapter.gateway;
      const seconds = Number(fields.lease_time);
      if (Number.isFinite(seconds)) {
        adapter.leaseSeconds = seconds;
        adapter.leaseObtained = new Date().toISOString();
        adapter.leaseExpires = new Date(Date.now() + seconds * 1000).toISOString();
      }
    }
  }
  const primary = adapters.find((adapter) => adapter.dhcpEnabled) || adapters[0] || null;
  const iface = primary && primary.name ? primary.name : 'Wi-Fi';
  const recovery = process.platform === 'win32'
    ? [
      { title: 'Release the current lease', command: 'ipconfig /release' },
      { title: 'Request a fresh lease', command: 'ipconfig /renew' },
      { title: 'Clear the DNS cache', command: 'ipconfig /flushdns' },
      { title: 'Reconnect the adapter if it stalls', command: `Disable-NetAdapter -Name "${iface}" -Confirm:$false; Enable-NetAdapter -Name "${iface}"` },
    ]
    : process.platform === 'darwin'
      ? [
        { title: 'Request a fresh lease', command: `sudo ipconfig set "${iface}" DHCP` },
        { title: 'Flush the DNS cache', command: 'sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder' },
      ]
      : [
        { title: 'Release the current lease', command: `sudo dhclient -r ${iface}` },
        { title: 'Request a fresh lease', command: `sudo dhclient ${iface}` },
        { title: 'Flush the resolver cache', command: 'sudo resolvectl flush-caches' },
        { title: 'Restart NetworkManager', command: 'sudo systemctl restart NetworkManager' },
      ];
  return {
    platform: process.platform,
    adapters,
    gateway: primary ? primary.gateway : null,
    dhcpServer: primary ? primary.dhcpServer : null,
    leaseObtained: primary ? primary.leaseObtained : null,
    leaseExpires: primary ? primary.leaseExpires : null,
    recovery,
    note: 'Read-only diagnostics. These commands are shown for manual recovery after you confirm the gateway and lease details.',
    at: new Date().toISOString(),
  };
}

function cameraCandidates(devices, notes = {}) {
  const items = Object.values(devices || {}).map((device) => {
    const note = notes[device.ip] || {};
    const ports = new Set((device.ports || []).map((port) => Number(port.port ?? port)).filter(Boolean));
    const text = [device.hostname, device.name, device.vendor, device.fp && device.fp.model, note.name]
      .filter(Boolean).join(' ');
    const reasons = [];
    let score = 0;
    if (note.type === 'camera') { score += 10; reasons.push('labelled as a camera in notes'); }
    if (device.type === 'camera') { score += 6; reasons.push('classified as a camera during scanning'); }
    if (ports.has(554) || ports.has(8554)) { score += 6; reasons.push('RTSP video port is open'); }
    if (CAMERA_VENDOR.test(text)) { score += 5; reasons.push('known camera or NVR vendor'); }
    if (CAMERA_WORD.test(text)) { score += 4; reasons.push('camera-related hostname or model'); }
    if (ports.has(80) || ports.has(443) || ports.has(8080) || ports.has(8443)) { score += 1; reasons.push('web interface available'); }
    if (device.type === 'unknown' && (ports.has(554) || ports.has(8554))) { score += 2; reasons.push('unknown device exposing video'); }
    return {
      ip: device.ip,
      mac: device.mac || '',
      name: note.name || device.name || device.hostname || device.vendor || device.ip,
      vendor: device.vendor || 'Unknown',
      type: device.type || 'unknown',
      online: Boolean(device.online),
      lastSeen: device.lastSeen || null,
      score,
      confidence: score >= 10 ? 'likely' : score >= 5 ? 'possible' : 'low',
      reasons: [...new Set(reasons)],
      ports: [...ports],
    };
  }).filter((item) => item.online && item.score >= 4)
    .sort((a, b) => b.score - a.score);
  return {
    candidates: items,
    likely: items.filter((item) => item.confidence === 'likely').length,
    possible: items.filter((item) => item.confidence === 'possible').length,
    note: 'Camera discovery is inventory-based. Confirm physical ownership before disabling or blocking a device.',
    at: new Date().toISOString(),
  };
}

async function healthCheck(core) {
  const started = Date.now();
  const checks = [];
  const timed = async (id, label, fn) => {
    const t0 = Date.now();
    try {
      const value = await fn();
      checks.push({ id, label, status: value.status || 'pass', detail: value.detail, ms: Date.now() - t0 });
    } catch (error) {
      checks.push({ id, label, status: 'fail', detail: error.message || 'check failed', ms: Date.now() - t0 });
    }
  };
  const interfaces = core && core.getInterfaces ? core.getInterfaces() : [];
  checks.push({
    id: 'api',
    label: 'API service',
    status: 'pass',
    detail: `Node ${process.version} on ${process.platform}`,
    ms: 0,
  });
  checks.push({
    id: 'interface',
    label: 'LAN interface',
    status: interfaces.length ? 'pass' : 'warn',
    detail: interfaces.length ? `${interfaces[0].name} - ${interfaces[0].ip}` : 'no active LAN interface found',
    ms: 0,
  });
  let gateway = null;
  try {
    gateway = interfaces.length ? core.parseCidr(interfaces[0].cidr).hosts[0] : null;
  } catch {
    gateway = null;
  }
  if (gateway) {
    await timed('gateway', 'Gateway reachability', async () => {
      const result = await pingTool({ host: gateway, count: 1, timeoutMs: 1200 });
      return result.received
        ? { status: 'pass', detail: `${gateway} replied in ${result.avg} ms` }
        : { status: 'warn', detail: `${gateway} did not answer ICMP` };
    });
  } else {
    checks.push({ id: 'gateway', label: 'Gateway reachability', status: 'warn', detail: 'gateway could not be determined', ms: 0 });
  }
  await timed('dns', 'DNS resolution', async () => {
    const result = await withTimeout(dns.resolve4('example.com'), 2500);
    return result.ok
      ? { status: 'pass', detail: `example.com resolved ${result.value.length} address${result.value.length === 1 ? '' : 'es'}` }
      : { status: 'warn', detail: `resolver did not answer (${result.error})` };
  });
  await timed('storage', 'Local storage', async () => {
    const stats = await core.storageStats();
    return { status: 'pass', detail: `${stats.devices} devices, ${stats.scanHistory} scans, ${stats.retentionDays} day retention` };
  });
  if (core.getArpTable) {
    await timed('arp', 'ARP visibility', async () => {
      const table = await core.getArpTable();
      const count = Object.keys(table || {}).length;
      return { status: count ? 'pass' : 'warn', detail: `${count} address${count === 1 ? '' : 'es'} in the ARP table` };
    });
  }
  const counts = checks.reduce((acc, item) => {
    acc[item.status] = (acc[item.status] || 0) + 1;
    return acc;
  }, {});
  return {
    ok: !counts.fail,
    gateway,
    checks,
    counts,
    elapsedMs: Date.now() - started,
    at: new Date().toISOString(),
  };
}

function createTools(core) {
  return {
    health: () => healthCheck(core),
    ping: pingTool,
    traceroute: tracerouteTool,
    dnsBenchmark,
    dnsLookup,
    wifi: () => wifiScan(core),
    dhcp: () => dhcpInfo(core),
    hiddenCameras: (devices, notes) => cameraCandidates(devices, notes),
    safeTarget,
  };
}

module.exports = {
  createTools,
  safeTarget,
  parsePingOutput,
  parseTraceroute,
  parseNetshWifi,
  parseNmcliWifi,
  parseAirportWifi,
  cameraCandidates,
};
