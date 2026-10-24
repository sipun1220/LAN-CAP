/* Router security — LAN-side checks for the default gateway.
 *
 * Nothing here changes router configuration and nothing is sent to the
 * internet. We only look at what the gateway exposes to the local network:
 *   - default-gateway discovery (OS route table, subnet fallback)
 *   - open TCP services (management, Telnet/FTP/SMB, TR-069, Winbox)
 *   - UPnP IGD (SSDP + device description + unauthenticated SOAP probe)
 *   - NAT-PMP / PCP (UDP 5351 public-address / announce probes)
 *   - fingerprint (MAC vendor, HTTP, TLS certificate, UPnP model)
 *   - known CVE / advisory patterns matched against the fingerprint
 *
 * External/WAN reachability is deliberately out of scope: that belongs to
 * the user's public IP and must only be tested on networks they own.
 */
'use strict';

const { execFile } = require('child_process');
const dgram = require('dgram');
const { promisify } = require('util');

const execFileAsync = promisify(execFile);

const SEVERITY_WEIGHT = { critical: 50, high: 25, medium: 12, low: 4, info: 0 };
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/* Ports that matter on a home/office router. Keep the list small: each entry
 * costs one TCP connect and the UI only needs management-plane exposure. */
const ROUTER_PORTS = [
  { port: 21, label: 'FTP' },
  { port: 22, label: 'SSH' },
  { port: 23, label: 'Telnet' },
  { port: 53, label: 'DNS' },
  { port: 80, label: 'HTTP' },
  { port: 443, label: 'HTTPS' },
  { port: 445, label: 'SMB' },
  { port: 7547, label: 'TR-069' },
  { port: 8080, label: 'HTTP-alt' },
  { port: 8291, label: 'Winbox' },
  { port: 8443, label: 'HTTPS-alt' },
];

const PORT_RULES = {
  21: {
    severity: 'high',
    title: 'FTP server is exposed',
    detail: 'FTP sends credentials and files in clear text. Routers rarely need an FTP server enabled.',
    action: 'Disable the router FTP server (or restrict it to trusted devices).',
  },
  22: {
    severity: 'info',
    title: 'SSH is enabled',
    detail: 'SSH is encrypted and can be legitimate for advanced users, but every exposed management service adds attack surface.',
    action: 'Keep SSH firmware-patched and disable it if you do not use it.',
  },
  23: {
    severity: 'critical',
    title: 'Telnet management is open',
    detail: 'Telnet has no encryption. Anyone who can reach this port can capture the admin username and password.',
    action: 'Disable Telnet in the router settings and use HTTPS (or SSH) instead.',
  },
  445: {
    severity: 'critical',
    title: 'SMB file sharing is exposed by the router',
    detail: 'Routers should not expose SMB. This is normally a USB-storage feature and has a long history of worms and ransomware exploits.',
    action: 'Disable USB/SMB file sharing on the router unless you actively use it.',
  },
  7547: {
    severity: 'high',
    title: 'TR-069/CWMP management is reachable',
    detail: 'Port 7547 is the ISP remote-management protocol. Poorly secured CWMP endpoints have been mass-exploited (for example CVE-2016-10372 in the Eir D1000).',
    action: 'If your ISP does not require it, ask them to disable CWMP/TR-069. Keep router firmware updated.',
    cves: ['CVE-2016-10372'],
    confidence: 'possible',
  },
  8291: {
    severity: 'critical',
    title: 'MikroTik Winbox service is exposed',
    detail: 'Port 8291 is the MikroTik Winbox protocol. RouterOS before 6.42 is affected by CVE-2018-14847, which allows unauthenticated credential disclosure and file read.',
    action: 'Update RouterOS (6.42 is the minimum; use a current release) and block Winbox from untrusted networks.',
    cves: ['CVE-2018-14847'],
    confidence: 'possible',
  },
};

const NATPMP_ERRORS = {
  1: 'Unsupported version',
  2: 'Not authorized / refused',
  3: 'Network failure',
  4: 'Out of resources',
  5: 'Unsupported opcode',
};

function riskLevel(score) {
  if (score >= 70) return 'critical';
  if (score >= 40) return 'high';
  if (score >= 20) return 'medium';
  if (score > 0) return 'low';
  return 'safe';
}

/* Pure assessment: deterministic input (ports/upnp/natpmp/fingerprint) to
 * risk report. Kept side-effect free so it can be unit tested. */
function assessRouter(input = {}) {
  const gateway = input.gateway || {};
  const ports = Array.isArray(input.ports) ? input.ports : [];
  const upnp = input.upnp || {};
  const natpmp = input.natpmp || {};
  const fingerprint = input.fingerprint || {};
  const open = new Set(ports.filter((p) => p.open).map((p) => Number(p.port)));
  const findings = [];
  const seen = new Set();

  function add(finding) {
    if (!finding || !finding.id || seen.has(finding.id)) return;
    seen.add(finding.id);
    findings.push({ cves: [], confidence: 'confirmed', ...finding });
  }

  for (const [portKey, rule] of Object.entries(PORT_RULES)) {
    const port = Number(portKey);
    if (!open.has(port)) continue;
    add({
      id: `port-${port}`,
      port,
      severity: rule.severity,
      title: rule.title,
      detail: rule.detail,
      action: rule.action,
      cves: rule.cves || [],
      confidence: rule.confidence || 'confirmed',
    });
  }

  const httpsOpen = open.has(443) || open.has(8443);
  const httpOpen = open.has(80) || open.has(8080);
  const web = fingerprint.http || {};
  const httpsPorts = [443, 8443].filter((p) => open.has(p));
  const httpPorts = [80, 8080].filter((p) => open.has(p));
  const webResponses = Array.isArray(fingerprint.web) && fingerprint.web.length ? fingerprint.web : [web];
  const plainResponses = webResponses.filter((r) => r && r.scheme === 'http');
  const redirectsToHttps = plainResponses.length > 0 && plainResponses.every((r) => (
    [301, 302, 303, 307, 308].includes(Number(r.status))
    && /^https:/i.test(String(r.location || ''))
  ));

  if (httpOpen && !httpsOpen) {
    add({
      id: 'http-admin',
      severity: 'medium',
      title: 'Router admin page uses plain HTTP',
      detail: `The management interface answers on ${httpPorts.map((p) => `port ${p}`).join(', ')} without HTTPS. Admin credentials can be captured by anyone on the LAN.`,
      action: 'Enable HTTPS management in the router settings and disable HTTP access.',
    });
  } else if (httpOpen && httpsOpen && !redirectsToHttps) {
    add({
      id: 'http-admin',
      severity: 'low',
      title: 'HTTP management is still reachable',
      detail: 'HTTPS is available, but the router also serves the admin page over plain HTTP without redirecting to HTTPS.',
      action: 'Make HTTP redirect to HTTPS, or disable HTTP management entirely.',
    });
  }

  if ((open.has(8080) || open.has(8443)) && !open.has(80) && !open.has(443)) {
    add({
      id: 'alt-web',
      severity: 'low',
      title: 'Web management on an alternate port',
      detail: `The admin interface is reachable on ${[8080, 8443].filter((p) => open.has(p)).map((p) => `port ${p}`).join(', ')}. This is common, but confirm it is LAN-only and served over HTTPS.`,
      action: 'Keep the alternate admin port off the internet and use HTTPS.',
    });
  }

  if (upnp.igd) {
    const control = upnp.controlConfirmed
      ? ' We confirmed unauthenticated IGD control by requesting the external IP address.'
      : '';
    add({
      id: 'upnp-igd',
      severity: 'medium',
      title: 'UPnP IGD is enabled',
      detail: `The router advertises an Internet Gateway Device with a WAN port-mapping service. Any app on the LAN can request port forwards without a password.${control}`,
      action: 'Disable UPnP IGD unless you need automatic port forwarding (game consoles and some apps do).',
    });
  } else if (upnp.discovered) {
    add({
      id: 'upnp',
      severity: 'info',
      title: 'UPnP discovery is responding',
      detail: 'UPnP is enabled, but no internet-gateway port-mapping service was found in its description.',
      action: 'Keep UPnP disabled if you do not use it.',
    });
  }

  if (natpmp.supported) {
    add({
      id: 'natpmp',
      severity: 'medium',
      title: `${natpmp.protocol || 'NAT-PMP'} is enabled`,
      detail: `${natpmp.protocol || 'NAT-PMP'} lets LAN clients create port mappings without authentication. The router answered on UDP 5351.`,
      action: 'Disable NAT-PMP/PCP in the router settings if it is not required.',
    });
  }

  const fpText = [
    fingerprint.vendor,
    fingerprint.model,
    fingerprint.http?.server,
    fingerprint.http?.title,
    fingerprint.http?.realm,
    fingerprint.cert?.subject,
    fingerprint.cert?.issuer,
    fingerprint.upnp?.manufacturer,
    fingerprint.upnp?.model,
    fingerprint.upnp?.friendly,
  ].filter(Boolean).join(' ').toLowerCase();
  const hasWeb = httpOpen || httpsOpen;

  if (/rompager|allegro\s*software/.test(fpText)) {
    add({
      id: 'cve-misfortune-cookie',
      severity: 'critical',
      title: 'Possible Misfortune Cookie vulnerability',
      detail: 'The web server identifies as AllegroSoft RomPager — the component behind "Misfortune Cookie". RomPager 4.07 and earlier can allow authentication bypass on many routers.',
      action: 'Update router firmware to a build that ships RomPager 4.08+ (or newer), then re-scan.',
      cves: ['CVE-2014-9222'],
      confidence: 'possible',
    });
  }

  if (/goahead/.test(fpText) && hasWeb) {
    add({
      id: 'cve-goahead',
      severity: 'high',
      title: 'Possible GoAhead web-server vulnerability',
      detail: 'The management interface identifies as GoAhead. Certain GoAhead builds used in embedded routers are affected by CVE-2017-17562 (CGI environment injection); the exact version cannot be confirmed from outside.',
      action: 'Update router firmware and confirm the vendor has published a fix for your exact model.',
      cves: ['CVE-2017-17562'],
      confidence: 'possible',
    });
  }

  if (/netgear/.test(fpText) && hasWeb) {
    add({
      id: 'cve-netgear-password',
      severity: 'high',
      title: 'Possible Netgear password disclosure',
      detail: 'A Netgear management interface was detected. Many Netgear models are affected by CVE-2017-5521, where an unauthenticated request can expose admin credentials.',
      action: 'Update Netgear firmware to the latest release and disable remote management.',
      cves: ['CVE-2017-5521'],
      confidence: 'possible',
    });
  }

  if ((/zywall/.test(fpText) || /\busg\d|\batp\d/.test(fpText)) && hasWeb) {
    add({
      id: 'cve-zyxel',
      severity: 'critical',
      title: 'Possible Zyxel command injection',
      detail: 'A Zyxel ZyWALL/USG/ATP management interface was detected. CVE-2022-30525 allows unauthenticated OS command injection on affected firmware.',
      action: 'Patch Zyxel firmware immediately and disable WAN-side management.',
      cves: ['CVE-2022-30525'],
      confidence: 'possible',
    });
  }

  if (/cisco/.test(fpText) && /\brv\d{3}[a-z]*w?\b/.test(fpText) && hasWeb) {
    add({
      id: 'cve-cisco-rv',
      severity: 'high',
      title: 'Possible Cisco RV-series vulnerability',
      detail: 'A Cisco RV-series router was detected. CVE-2019-1663 affects several RV110W/RV130W/RV215W firmware releases and can allow remote code execution.',
      action: 'Update the Cisco RV firmware to the latest fixed release.',
      cves: ['CVE-2019-1663'],
      confidence: 'possible',
    });
  }

  if ((/d-link/.test(fpText) || /\bdir-\d+/.test(fpText)) && hasWeb) {
    add({
      id: 'advisory-dlink',
      severity: 'medium',
      title: 'D-Link model detected — verify firmware',
      detail: 'Many D-Link DIR-series routers have had command-injection and authentication-bypass flaws. The exact model/version could not be verified over the network.',
      action: 'Check D-Link security advisories for your exact model and update firmware.',
      confidence: 'possible',
    });
  }

  const checks = [];
  const openPorts = ports.filter((p) => p.open);
  const riskyPorts = findings.filter((f) => f.port && f.severity !== 'info');
  const criticalPort = riskyPorts.some((f) => f.severity === 'critical');
  const cveFindings = findings.filter((f) => f.cves.length > 0);

  checks.push({
    id: 'router',
    label: 'Router discovered',
    status: gateway.ip ? 'pass' : 'fail',
    detail: gateway.ip
      ? `${gateway.ip}${gateway.vendor && gateway.vendor !== 'Unknown' ? ` · ${gateway.vendor}` : ''}${gateway.mac ? ` · ${gateway.mac}` : ''}`
      : 'No IPv4 default gateway was found on this machine.',
  });

  checks.push({
    id: 'https',
    label: 'HTTPS management',
    status: httpsOpen ? 'pass' : httpOpen ? 'warn' : 'info',
    detail: httpsOpen
      ? `Encrypted admin interface on ${httpsPorts.map((p) => `port ${p}`).join(', ')}${httpOpen ? ` (HTTP also open on ${httpPorts.map((p) => p).join(', ')})` : ''}.`
      : httpOpen
        ? 'Admin interface is only reachable over plain HTTP.'
        : 'No web admin interface answered on the common ports.',
  });

  checks.push({
    id: 'ports',
    label: 'Exposed router services',
    status: criticalPort ? 'fail' : riskyPorts.length ? 'warn' : 'pass',
    detail: openPorts.length
      ? `Open: ${openPorts.map((p) => `${p.label}:${p.port}`).join(', ')}`
      : 'No ports answered in the router check set.',
  });

  checks.push({
    id: 'upnp',
    label: 'UPnP',
    status: upnp.igd ? 'warn' : upnp.discovered ? 'info' : 'pass',
    detail: upnp.igd
      ? `IGD port mapping is available${upnp.controlConfirmed ? `; unauthenticated control confirmed${upnp.externalIp ? ` (WAN IP ${upnp.externalIp})` : ''}` : ''}.`
      : upnp.discovered
        ? 'UPnP discovery responds, but no IGD port-mapping service was found.'
        : 'No UPnP response from the router.',
  });

  checks.push({
    id: 'natpmp',
    label: 'NAT-PMP / PCP',
    status: natpmp.supported ? 'warn' : 'pass',
    detail: natpmp.supported
      ? `${natpmp.protocol || 'NAT-PMP'} answered on UDP 5351${natpmp.externalIp ? ` (external IP ${natpmp.externalIp})` : ''}.`
      : 'No NAT-PMP/PCP response on UDP 5351.',
  });

  checks.push({
    id: 'fingerprint',
    label: 'Router fingerprint',
    status: (fingerprint.model || (fingerprint.vendor && fingerprint.vendor !== 'Unknown')) ? 'pass' : 'info',
    detail: fingerprint.model
      ? `${fingerprint.model}${fingerprint.vendor && fingerprint.vendor !== 'Unknown' ? ` · ${fingerprint.vendor}` : ''} (${fingerprint.confidence || 'low'} confidence)`
      : fingerprint.vendor && fingerprint.vendor !== 'Unknown'
        ? `${fingerprint.vendor} (model not identified)`
        : 'Could not identify the router model from LAN fingerprints.',
  });

  checks.push({
    id: 'cves',
    label: 'Known CVE patterns',
    status: cveFindings.some((f) => f.severity === 'critical' || f.severity === 'high') ? 'fail' : cveFindings.length ? 'warn' : 'pass',
    detail: cveFindings.length
      ? cveFindings.map((f) => `${f.cves.join('/')} (${f.confidence})`).join(', ')
      : 'No known vulnerable fingerprint pattern matched.',
  });

  checks.push({
    id: 'scope',
    label: 'Scan scope',
    status: 'info',
    detail: 'LAN-side checks only. External/WAN exposure and default admin credentials were not tested.',
  });

  const score = Math.min(100, findings.reduce((sum, f) => sum + (SEVERITY_WEIGHT[f.severity] || 0), 0));
  const level = riskLevel(score);
  const headline = {
    safe: 'No obvious router weaknesses',
    low: 'Mostly healthy',
    medium: 'Needs attention',
    high: 'Several risky settings',
    critical: 'Act now',
  }[level];
  const actionable = findings.filter((f) => f.severity !== 'info').length;
  const summary = actionable
    ? `${actionable} finding${actionable === 1 ? '' : 's'} need attention. Fix the highest-severity items first.`
    : 'The LAN-side checks did not match any known risk patterns.';

  const recommendations = [];
  const addRec = (text) => {
    if (!text) return;
    const key = String(text).toLowerCase();
    if (!recommendations.some((r) => r.toLowerCase() === key)) recommendations.push(text);
  };
  [...findings]
    .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9))
    .forEach((f) => addRec(f.action));
  addRec('Keep router firmware up to date — check the vendor support page for your exact model.');
  addRec('Change the router admin password if it is still the default.');
  addRec('Disable remote/WAN administration unless you specifically need it.');
  addRec('Use WPA2 or WPA3 for Wi-Fi and disable WPS.');

  return {
    checks,
    findings: [...findings].sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9)),
    risk: {
      score,
      level,
      headline,
      summary,
      counts: findings.reduce((acc, f) => {
        acc[f.severity] = (acc[f.severity] || 0) + 1;
        return acc;
      }, {}),
    },
    recommendations: recommendations.slice(0, 10),
  };
}

/* ---------- tiny network helpers (module-local) ---------- */

function isPrivateIp(ip) {
  const parts = String(ip).split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return false;
  return parts[0] === 10
    || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31)
    || (parts[0] === 192 && parts[1] === 168);
}

function inCidr(core, ip, cidr) {
  try {
    const [base, prefixText] = String(cidr).split('/');
    const prefix = Number(prefixText);
    if (!Number.isFinite(prefix)) return false;
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    return ((core.ipToInt(ip) & mask) >>> 0) === ((core.ipToInt(base) & mask) >>> 0);
  } catch {
    return false;
  }
}

function execText(file, args, timeout = 6000) {
  return execFileAsync(file, args, { timeout, windowsHide: true, encoding: 'utf8' })
    .then((r) => String(r.stdout || ''));
}

async function osDefaultGateway() {
  try {
    if (process.platform === 'win32') {
      try {
        const out = await execText('powershell', [
          '-NoProfile', '-NonInteractive', '-Command',
          "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty NextHop",
        ]);
        const ip = out.trim().split(/\s+/).find((v) => /^\d{1,3}(\.\d{1,3}){3}$/.test(v));
        if (ip && ip !== '0.0.0.0') return ip;
      } catch { /* fall back to route.exe */ }
      const out = await execText('route', ['print', '-4'], 5000);
      for (const line of out.split(/\r?\n/)) {
        const m = line.trim().match(/^0\.0\.0\.0\s+0\.0\.0\.0\s+(\d{1,3}(?:\.\d{1,3}){3})/);
        if (m && m[1] !== '0.0.0.0') return m[1];
      }
      return null;
    }
    if (process.platform === 'darwin') {
      const out = await execText('route', ['-n', 'get', 'default'], 5000);
      const m = out.match(/gateway:\s*(\d{1,3}(?:\.\d{1,3}){3})/);
      return m ? m[1] : null;
    }
    const out = await execText('ip', ['route', 'show', 'default'], 5000);
    const m = out.match(/default\s+via\s+(\d{1,3}(?:\.\d{1,3}){3})/);
    return m ? m[1] : null;
  } catch {
    return null;
  }
}

function localUrl(raw, target) {
  try {
    const u = new URL(String(raw));
    if (!/^https?:$/.test(u.protocol)) return false;
    return u.hostname === target || isPrivateIp(u.hostname);
  } catch {
    return false;
  }
}

function fetchDeviceDescription(url, timeoutMs = 2200) {
  return new Promise((resolve) => {
    const out = { location: url, manufacturer: '', model: '', friendly: '', deviceType: '', services: [] };
    if (!/^https?:\/\//i.test(url || '')) return resolve(out);
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };
    try {
      const lib = url.toLowerCase().startsWith('https') ? require('https') : require('http');
      const req = lib.get(url, { timeout: timeoutMs, rejectUnauthorized: false }, (res) => {
        let body = '';
        res.on('data', (c) => { if (body.length < 65536) body += c; });
        res.on('end', () => {
          const get = (tag) => {
            const m = body.match(new RegExp(`<${tag}[^>]*>([^<]{1,160})</${tag}>`, 'i'));
            return m ? m[1].trim() : '';
          };
          out.manufacturer = get('manufacturer');
          out.model = get('modelName') || get('modelNumber');
          out.friendly = get('friendlyName');
          out.deviceType = get('deviceType');
          out.services = [...body.matchAll(/<service>([\s\S]*?)<\/service>/gi)]
            .map((m) => ({
              type: (m[1].match(/<serviceType>([^<]+)<\/serviceType>/i) || [])[1] || '',
              control: (m[1].match(/<controlURL>([^<]+)<\/controlURL>/i) || [])[1] || '',
            }))
            .filter((s) => s.type || s.control);
          finish(out);
        });
      });
      req.on('timeout', () => { req.destroy(); finish(out); });
      req.on('error', () => finish(out));
      setTimeout(() => finish(out), timeoutMs + 500).unref?.();
    } catch {
      finish(out);
    }
  });
}

function udpProbe(host, port, payload, timeoutMs = 700) {
  return new Promise((resolve) => {
    let sock;
    let done = false;
    const finish = (value) => {
      if (done) return;
      done = true;
      try { sock.close(); } catch { /* already closed */ }
      resolve(value);
    };
    try {
      sock = dgram.createSocket('udp4');
      sock.once('message', (msg) => finish(msg));
      sock.once('error', () => finish(null));
      sock.send(payload, 0, payload.length, port, host, (err) => { if (err) finish(null); });
      setTimeout(() => finish(null), timeoutMs).unref?.();
    } catch {
      finish(null);
    }
  });
}

function pcpAnnounce(clientIp) {
  const buf = Buffer.alloc(24);
  buf[0] = 2; // version 2 (PCP)
  buf[1] = 0; // R=0, opcode 0 (ANNOUNCE)
  buf.writeUInt32BE(0, 4); // requested lifetime 0
  const ip = String(clientIp).split('.').map(Number);
  buf[18] = 0xff;
  buf[19] = 0xff;
  buf[20] = ip[0] || 0;
  buf[21] = ip[1] || 0;
  buf[22] = ip[2] || 0;
  buf[23] = ip[3] || 0;
  return buf;
}

async function checkNatPmp(host, clientIp = host) {
  // NAT-PMP v0 public-address request: two zero bytes.
  const pmp = Buffer.from([0, 0]);
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const res = await udpProbe(host, 5351, pmp, 650);
    if (res && res.length >= 12 && res[0] === 0 && res[1] === 128) {
      const code = res.readUInt16BE(2);
      return {
        supported: code === 0,
        protocol: 'NAT-PMP',
        externalIp: code === 0 ? [...res.subarray(8, 12)].join('.') : '',
        epoch: res.readUInt32BE(4),
        resultCode: code,
        error: code === 0 ? '' : (NATPMP_ERRORS[code] || `Result code ${code}`),
      };
    }
    if (res && res[0] === 2 && res.length >= 24 && res[1] === 128) {
      const code = res[3];
      return { supported: true, protocol: 'PCP', externalIp: '', resultCode: code, error: code === 0 ? '' : `PCP result ${code}` };
    }
  }
  // Some PCP servers ignore NAT-PMP entirely; ANNOUNCE is harmless.
  const res = await udpProbe(host, 5351, pcpAnnounce(clientIp), 800);
  if (res && res.length >= 24 && res[0] === 2 && res[1] === 128) {
    const code = res[3];
    return { supported: true, protocol: 'PCP', externalIp: '', resultCode: code, error: code === 0 ? '' : `PCP result ${code}` };
  }
  return { supported: false, protocol: null, externalIp: '', resultCode: null, error: '' };
}

function createRouterSecurity(core) {
  const jobs = new Map();
  const JOB_TTL = 10 * 60 * 1000;
  let seq = 0;
  let latest = null;

  async function discoverGateway() {
    const ifaceInfo = await core.pickInterface().catch(() => ({ iface: null, arp: {} }));
    const iface = ifaceInfo.iface;
    const cachedArp = ifaceInfo.arp || {};
    const routeIp = await osDefaultGateway();

    let ip = null;
    let source = '';
    if (routeIp && isPrivateIp(routeIp) && (!iface || inCidr(core, routeIp, iface.cidr))) {
      ip = routeIp;
      source = 'default-route';
    }
    if (!ip && iface) {
      try {
        ip = core.parseCidr(iface.cidr).hosts[0] || null;
        source = 'subnet';
      } catch { ip = null; }
    }
    if (!ip && routeIp) {
      ip = routeIp;
      source = 'default-route';
    }
    if (!ip) return { ip: null, mac: '', vendor: '', source: 'none', interface: null };

    let mac = cachedArp[ip] || '';
    if (!mac) {
      try { await core.pingHost(ip, 1); } catch { /* gateway may not answer ping */ }
      try { mac = (await core.getArpTable())[ip] || ''; } catch { /* keep empty */ }
    }
    const vendor = mac ? core.lookupVendor(mac).vendor : 'Unknown';
    return {
      ip,
      mac,
      vendor,
      source,
      interface: iface ? { name: iface.name, ip: iface.ip, cidr: iface.cidr, ssid: iface.ssid || null } : null,
    };
  }

  async function resolveTarget(ip, gateway) {
    if (!ip) return gateway.ip;
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip) || !isPrivateIp(ip)) {
      throw new Error('Target must be a private IPv4 address on your LAN.');
    }
    if (gateway.ip && ip === gateway.ip) return ip;
    if (gateway.interface && inCidr(core, ip, gateway.interface.cidr)) return ip;
    throw new Error('Only your detected gateway or a host on your local subnet can be scanned.');
  }

  async function checkUpnp(target, ssdp) {
    const hits = (ssdp || []).filter((s) => s.ip === target);
    const locations = [...new Set(hits.map((s) => s.location).filter((url) => localUrl(url, target)))].slice(0, 4);
    const descriptions = await Promise.all(locations.map((url) => fetchDeviceDescription(url)));
    const services = descriptions.flatMap((d) => d.services.map((s) => ({ ...s, base: d.location })));

    const igd = hits.some((h) => /InternetGatewayDevice|WANIPConnection|WANPPPConnection/i.test(`${h.st} ${h.usn}`))
      || descriptions.some((d) => /InternetGatewayDevice/i.test(d.deviceType || '')
        || d.services.some((s) => /WAN(IP|PPP)Connection/i.test(s.type)));

    const svc = services.find((s) => /WANIPConnection/i.test(s.type))
      || services.find((s) => /WANPPPConnection/i.test(s.type));

    let controlConfirmed = false;
    let externalIp = '';
    let controlError = '';
    if (svc && svc.control) {
      try {
        const base = new URL(svc.base || descriptions[0]?.location || `http://${target}/`);
        const controlUrl = new URL(svc.control, `${base.protocol}//${base.host}`).toString();
        if (!localUrl(controlUrl, target)) throw new Error('UPnP control URL is not on the local network');
        const text = await core.soapAction(controlUrl, svc.type, 'GetExternalIPAddress');
        const m = text.match(/<NewExternalIPAddress>([^<]+)<\/NewExternalIPAddress>/i);
        if (m) {
          controlConfirmed = true;
          externalIp = m[1].trim();
        } else if (/GetExternalIPAddressResponse/i.test(text)) {
          controlConfirmed = true;
        }
      } catch (e) {
        controlError = e.message || 'UPnP control probe failed';
      }
    }

    const first = descriptions.find((d) => d.manufacturer || d.model) || descriptions[0] || {};
    return {
      discovered: hits.length > 0 || descriptions.length > 0,
      igd,
      controlConfirmed,
      externalIp,
      controlError,
      manufacturer: first.manufacturer || '',
      model: first.model || '',
      friendly: first.friendly || '',
      server: hits.map((h) => h.server).filter(Boolean)[0] || '',
      deviceType: first.deviceType || hits.map((h) => h.st).filter(Boolean)[0] || '',
      services: services.map((s) => ({ type: s.type, control: s.control })),
    };
  }

  async function fingerprintRouter(target, ctx) {
    const open = new Set(ctx.ports.filter((p) => p.open).map((p) => p.port));
    const httpPorts = [80, 8080].filter((p) => open.has(p));
    const httpsPorts = [443, 8443].filter((p) => open.has(p));

    const probes = await Promise.all([
      ...httpsPorts.map(async (port) => ({ port, tls: true, res: await core.httpProbe(target, port, true, 1800) })),
      ...httpPorts.map(async (port) => ({ port, tls: false, res: await core.httpProbe(target, port, false, 1800) })),
    ]);
    const certs = await Promise.all(
      httpsPorts.map(async (port) => ({ port, cert: await core.certProbe(target, 1800, port) })),
    );

    const scoreProbe = (p) => (p.res?.server ? 2 : 0) + (p.res?.title ? 2 : 0) + (p.res?.status ? 1 : 0);
    const primary = [...probes].sort((a, b) => scoreProbe(b) - scoreProbe(a))[0] || null;
    const certHit = certs.find((c) => c.cert?.subject) || certs[0] || { cert: {} };
    const http = primary
      ? { port: primary.port, scheme: primary.tls ? 'https' : 'http', ...primary.res }
      : { port: null, scheme: null, server: '', title: '', realm: '', status: null, location: '' };
    const web = probes.map((p) => ({
      port: p.port,
      scheme: p.tls ? 'https' : 'http',
      server: p.res?.server || '',
      title: p.res?.title || '',
      status: p.res?.status ?? null,
      location: p.res?.location || '',
    }));

    const services = ctx.ports.filter((p) => p.open).map((p) => ({ port: p.port, label: p.label }));
    const verdict = core.identifyDevice({
      ip: target,
      vendor: ctx.vendor,
      hostname: '',
      services,
      http,
      cert: certHit.cert,
      upnp: ctx.upnp,
    });

    const upnpModel = [ctx.upnp?.manufacturer, ctx.upnp?.model].filter(Boolean).join(' ').trim();
    const model = upnpModel || verdict.model || '';
    const vendor = ctx.vendor && ctx.vendor !== 'Unknown'
      ? ctx.vendor
      : (ctx.upnp?.manufacturer || 'Unknown');
    const evidence = [...new Set([
      ...(verdict.evidence || []),
      ...(ctx.mac ? [`Gateway MAC vendor: ${ctx.vendor || 'Unknown'} (${ctx.mac})`] : []),
      ...(http.server ? [`HTTP server: ${http.server}`] : []),
      ...(http.title ? [`Web page title: ${http.title}`] : []),
      ...(certHit.cert?.subject ? [`TLS certificate: ${certHit.cert.subject}`] : []),
      ...(ctx.upnp?.friendly ? [`UPnP friendly name: ${ctx.upnp.friendly}`] : []),
    ])].slice(0, 8);

    return {
      vendor,
      model,
      kind: 'router',
      confidence: upnpModel ? 'high' : (verdict.confidence || 'low'),
      evidence,
      http,
      web,
      cert: certHit.cert || {},
      upnp: {
        manufacturer: ctx.upnp?.manufacturer || '',
        model: ctx.upnp?.model || '',
        friendly: ctx.upnp?.friendly || '',
      },
    };
  }

  async function runScan(job, target, gateway, onProgress) {
    const startedMs = Date.now();
    onProgress(0.08, 'Scanning router ports');
    const ports = (await core.mapLimit(ROUTER_PORTS, 12, async (meta) => {
      const r = await core.checkPort(target, meta.port, 800);
      return { ...meta, open: Boolean(r && r.open), ms: r ? r.ms : null };
    })).filter(Boolean);

    onProgress(0.4, 'Checking UPnP');
    let ssdp = [];
    try { ssdp = await core.ssdpSweep(2200); } catch { ssdp = []; }
    const upnp = await checkUpnp(target, ssdp);

    onProgress(0.58, 'Checking NAT-PMP/PCP');
    const natpmp = await checkNatPmp(target, gateway.interface?.ip || target);

    onProgress(0.72, 'Fingerprinting router');
    const fingerprint = await fingerprintRouter(target, {
      ports,
      mac: gateway.mac,
      vendor: gateway.vendor,
      upnp,
    });

    onProgress(0.9, 'Assessing risk');
    const gw = {
      ...gateway,
      ip: target,
      reachable: true,
      latencyMs: null,
    };
    const assessment = assessRouter({ gateway: gw, ports, upnp, natpmp, fingerprint });
    const scannedAt = new Date().toISOString();
    return {
      gateway: gw,
      ports,
      upnp,
      natpmp,
      fingerprint,
      ...assessment,
      scope: {
        side: 'lan',
        externalChecked: false,
        note: 'LAN-side checks only. External/WAN exposure and default admin credentials were not tested.',
      },
      scannedAt,
      startedAt: new Date(startedMs).toISOString(),
      durationMs: Date.now() - startedMs,
    };
  }

  async function scanRouter({ ip = null, onProgress = () => {} } = {}) {
    const gateway = await discoverGateway();
    if (!gateway.ip) throw new Error('No IPv4 default gateway found. Connect to a home/office Wi-Fi or LAN and try again.');
    const target = await resolveTarget(ip, gateway);
    return runScan(null, target, gateway, onProgress);
  }

  function cleanupJobs() {
    const cutoff = Date.now() - JOB_TTL;
    for (const [id, job] of jobs) {
      if (job.finishedAt && new Date(job.finishedAt).getTime() < cutoff) jobs.delete(id);
    }
  }

  async function startScan({ ip = null } = {}) {
    const gateway = await discoverGateway();
    if (!gateway.ip) throw new Error('No IPv4 default gateway found. Connect to a home/office Wi-Fi or LAN and try again.');
    const target = await resolveTarget(ip, gateway);
    cleanupJobs();

    const id = `router-${Date.now().toString(36)}-${(seq++).toString(36)}`;
    const job = {
      id,
      status: 'running',
      phase: 'Starting',
      progress: 0,
      target,
      gateway: {
        ip: gateway.ip,
        mac: gateway.mac,
        vendor: gateway.vendor,
        source: gateway.source,
        interface: gateway.interface,
      },
      result: null,
      error: null,
      startedAt: new Date().toISOString(),
      finishedAt: null,
    };
    jobs.set(id, job);

    runScan(job, target, gateway, (progress, phase) => {
      job.progress = progress;
      job.phase = phase;
    }).then((result) => {
      job.status = 'done';
      job.progress = 1;
      job.phase = 'Done';
      job.result = result;
      job.finishedAt = new Date().toISOString();
      latest = result;
    }).catch((e) => {
      job.status = 'error';
      job.progress = 1;
      job.phase = 'Failed';
      job.error = e.message || 'router scan failed';
      job.finishedAt = new Date().toISOString();
    });

    return job;
  }

  function getJob(id) {
    return jobs.get(id) || null;
  }

  function latestResult() {
    return latest;
  }

  return { discoverGateway, scanRouter, startScan, getJob, latestResult };
}

module.exports = {
  createRouterSecurity,
  assessRouter,
  riskLevel,
  ROUTER_PORTS,
  PORT_RULES,
  SEVERITY_WEIGHT,
};
