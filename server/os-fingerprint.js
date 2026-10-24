/* Operating-system fingerprinting — no admin/raw sockets required.
 *
 * Sources, strongest first:
 *   SNMP sysDescr ... routers, printers and NAS boxes often expose firmware
 *   SSH banner ..... OpenSSH/Dropbear builds reveal distro or embedded OS
 *   HTTP headers ... IIS/Windows, Ubuntu/Debian web stacks, RouterOS, OpenWrt
 *   SMB dialect .... minimum Windows generation (never an exact build)
 *   TTL ............ OS family hint only (64 Unix-like, 128 Windows, 255 network)
 *   Hostname ....... weak hint (iPhone, MacBook, Android, Raspberry Pi)
 *
 * Exact versions are only shown when a device actually leaks them. Otherwise
 * the result is an OS family with a confidence level — the same honest limit
 * Fing and similar scanners hit without credentials or an installed agent.
 */
'use strict';

const crypto = require('crypto');
const dgram = require('dgram');
const net = require('net');

const SYS_DESCR_OID = '1.3.6.1.2.1.1.1.0';
const SOURCE_RANK = { snmp: 0, ssh: 1, http: 2, smb: 3, hostname: 4, ports: 5, ttl: 6 };
const SOURCE_LABELS = {
  snmp: 'SNMP sysDescr',
  ssh: 'SSH banner',
  http: 'HTTP headers',
  smb: 'SMB negotiation',
  hostname: 'hostname',
  ports: 'open ports',
  ttl: 'TTL',
};

function parseTtl(text) {
  const m = String(text || '').match(/\bttl[=:]\s*(\d{1,3})\b/i);
  return m ? Number(m[1]) : null;
}

/* Nearest common initial TTL. A routed reply is lower than its initial value
 * by one per hop, so the nearest bucket above the observed value is the best
 * guess at the sender's stack default. */
function initialTtl(ttl) {
  const n = Number(ttl);
  if (!Number.isFinite(n) || n <= 0 || n > 255) return null;
  for (const bucket of [32, 64, 128, 255]) if (n <= bucket) return bucket;
  return null;
}

function osFromTtl(ttl) {
  const init = initialTtl(ttl);
  if (!init) return null;
  const evidence = [`TTL ${ttl} (initial ${init})`];
  if (init === 128) return { name: 'Windows', version: '', family: 'windows', confidence: 'low', source: 'ttl', evidence };
  if (init === 64) return { name: 'Linux/Unix-like', version: '', family: 'unix', confidence: 'low', source: 'ttl', evidence };
  if (init === 32) return { name: 'Embedded device', version: '', family: 'embedded', confidence: 'low', source: 'ttl', evidence };
  return { name: 'Network device (Unix-like)', version: '', family: 'network', confidence: 'low', source: 'ttl', evidence };
}

function parseSshBanner(raw) {
  const banner = String(raw || '').trim().split(/\r?\n/)[0];
  if (!/^SSH-/i.test(banner)) return null;
  const software = (banner.match(/^SSH-[\d.]+-(.+)$/i) || [])[1] || banner;
  const evidence = [`SSH banner: ${banner.slice(0, 160)}`];
  const make = (name, version, family, confidence) => ({ name, version, family, confidence, source: 'ssh', evidence });

  const win = software.match(/OpenSSH_for_Windows[_-]?([\w.]+)/i);
  if (win) return make('Windows', `OpenSSH for Windows ${win[1]}`, 'windows', 'medium');

  const open = software.match(/OpenSSH[_-]?([\w.]+)/i);
  if (open) {
    const distro = software.match(/\b(Ubuntu|Debian|Raspbian|Alpine|CentOS|Fedora|Red Hat|SUSE)\b/i)?.[1];
    if (distro) return make(`${distro} Linux`, `OpenSSH ${open[1]}`, 'linux', 'medium');
    if (/FreeBSD/i.test(software)) return make('FreeBSD', `OpenSSH ${open[1]}`, 'bsd', 'medium');
    if (/OpenBSD/i.test(software)) return make('OpenBSD', `OpenSSH ${open[1]}`, 'bsd', 'medium');
    return make('Linux/Unix-like', `OpenSSH ${open[1]}`, 'unix', 'low');
  }

  const dropbear = software.match(/Dropbear[_-]?([\w.]+)/i);
  if (dropbear) return make('Embedded Linux', `Dropbear ${dropbear[1]}`, 'linux', 'low');
  if (/routeros|mikrotik/i.test(software)) return make('MikroTik RouterOS', software, 'routeros', 'medium');
  if (/cisco/i.test(software)) return make('Cisco IOS', software, 'network', 'medium');
  if (/sun_ssh/i.test(software)) return make('Solaris', software, 'unix', 'medium');
  if (/freebsd/i.test(software)) return make('FreeBSD', software, 'bsd', 'medium');
  if (/openbsd/i.test(software)) return make('OpenBSD', software, 'bsd', 'medium');
  return make('SSH-enabled device', software, null, 'low');
}

function parseHttpOs(http = {}) {
  const server = String(http.server || '').trim();
  const title = String(http.title || '').trim();
  const text = `${server} ${title}`.trim();
  const lower = text.toLowerCase();
  if (!lower) return null;

  const evidence = [];
  if (server) evidence.push(`HTTP Server: ${server.slice(0, 140)}`);
  if (title) evidence.push(`Web title: ${title.slice(0, 100)}`);
  const make = (name, version, family, confidence) => ({ name, version, family, confidence, source: 'http', evidence });

  let m = server.match(/Microsoft-IIS\/([\d.]+)/i);
  if (m) return make('Windows', `IIS ${m[1]}`, 'windows', 'medium');
  m = server.match(/Microsoft-HTTPAPI\/([\d.]+)/i);
  if (m) return make('Windows', `HTTP.sys ${m[1]}`, 'windows', 'medium');
  if (/microsoft-httpapi|microsoft-iis/i.test(server)) return make('Windows', 'Microsoft HTTP stack', 'windows', 'medium');

  if (/routeros|mikrotik/i.test(text)) {
    m = text.match(/(?:routeros|mikrotik)[^\d]*([\d.]+)/i);
    return make('MikroTik RouterOS', m ? `RouterOS ${m[1]}` : 'RouterOS', 'routeros', 'high');
  }
  if (/openwrt|lede/i.test(text)) {
    m = text.match(/(?:openwrt|lede)[^\d]*([\d.]+)/i);
    return make('OpenWrt', m ? `OpenWrt ${m[1]}` : 'OpenWrt', 'linux', 'high');
  }
  if (/synology|diskstation|\bdsm\b/i.test(text)) {
    m = text.match(/(?:dsm|diskstation)[^\d]*([\d.]+)/i);
    return make('Synology DSM', m ? `DSM ${m[1]}` : 'DSM', 'linux', 'medium');
  }
  if (/\bqnap\b|\bqts\b/i.test(text)) {
    m = text.match(/qts[^\d]*([\d.]+)/i);
    return make('QNAP QTS', m ? `QTS ${m[1]}` : 'QTS', 'linux', 'medium');
  }

  const stack = server.match(/\b(Apache|nginx|lighttpd)\/([\w.\-]+)/i);
  const distro = text.match(/\b(Ubuntu|Debian|Raspbian|Alpine|CentOS|Fedora|Red Hat|SUSE)\b/i)?.[1];
  if (distro) return make(`${distro} Linux`, stack ? `${stack[1]} ${stack[2]}` : '', 'linux', 'medium');
  if (/freebsd/i.test(text)) return make('FreeBSD', stack ? `${stack[1]} ${stack[2]}` : '', 'bsd', 'medium');
  if (/cisco/i.test(text)) return make('Cisco IOS', '', 'network', 'low');
  if (/\b(lighttpd|boa|goahead|rompager|uhttpd|thttpd)\b/i.test(server)) {
    return make('Embedded firmware', stack ? `${stack[1]} ${stack[2]}` : '', 'embedded', 'low');
  }
  if (stack) return make('Linux/Unix-like', `${stack[1]} ${stack[2]}`, 'unix', 'low');
  if (/microsoft|windows/i.test(text)) return make('Windows', '', 'windows', 'low');
  return null;
}

const SMB_DIALECTS = {
  0x0202: ['Windows Vista / Server 2008 era', 'SMB 2.0.2'],
  0x0210: ['Windows 7 / Server 2008 R2 era', 'SMB 2.1'],
  0x0300: ['Windows 8 / Server 2012 era', 'SMB 3.0'],
  0x0302: ['Windows 8.1 / Server 2012 R2 era', 'SMB 3.0.2'],
  0x0311: ['Windows 10/11 / Server 2016+ era', 'SMB 3.1.1'],
};

function parseSmbDialect(dialect, ctx = {}) {
  const info = SMB_DIALECTS[Number(dialect)];
  if (!info) return null;
  const microsoft = /microsoft/i.test(String(ctx.vendor || ''));
  return {
    name: microsoft ? 'Windows' : 'Windows or Samba',
    version: `${info[1]} — ${info[0]}`,
    family: 'windows',
    confidence: microsoft ? 'medium' : 'low',
    source: 'smb',
    evidence: [`SMB negotiation selected ${info[1]}`],
  };
}

function parseSnmpSysDescr(raw) {
  const text = String(raw || '').replace(/\s+/g, ' ').trim();
  if (!text) return null;
  const evidence = [`SNMP sysDescr: ${text.slice(0, 180)}`];
  const make = (name, version, family, confidence) => ({ name, version, family, confidence, source: 'snmp', evidence });
  let m;

  if ((m = text.match(/OpenWrt[^\d]*([\d.]+)/i))) return make('OpenWrt', `OpenWrt ${m[1]}`, 'linux', 'high');
  if (/OpenWrt/i.test(text)) return make('OpenWrt', '', 'linux', 'high');
  if ((m = text.match(/RouterOS[^\d]*([\d.]+)/i))) return make('MikroTik RouterOS', `RouterOS ${m[1]}`, 'routeros', 'high');
  if (/RouterOS|MikroTik/i.test(text)) return make('MikroTik RouterOS', 'RouterOS', 'routeros', 'high');
  if ((m = text.match(/Cisco IOS[^,]*?(?:Version\s+)?([\w().]+)/i))) return make('Cisco IOS', m[1], 'network', 'high');
  if (/Cisco IOS/i.test(text)) return make('Cisco IOS', '', 'network', 'medium');
  if ((m = text.match(/(?:Synology|DiskStation|DSM)[^\d]*([\d.]+)/i))) return make('Synology DSM', `DSM ${m[1]}`, 'linux', 'high');
  if ((m = text.match(/Windows NT\s+(?:Version\s+)?([\d.]+[^\s,;]*)/i))) return make('Windows', `NT ${m[1]}`, 'windows', 'medium');
  if ((m = text.match(/Windows\s+([\d.]+[^\s,;]*)/i))) return make('Windows', m[1], 'windows', 'medium');
  if (/Windows/i.test(text)) return make('Windows', '', 'windows', 'medium');
  if ((m = text.match(/Linux\s+\S+\s+([\d][\w.\-]*)/i))) return make('Linux', `kernel ${m[1]}`, 'linux', 'high');
  if (/Linux/i.test(text)) return make('Linux', '', 'linux', 'medium');
  if ((m = text.match(/FreeBSD[^\d]*([\d.]+)/i))) return make('FreeBSD', m[1], 'bsd', 'high');
  if (/FreeBSD/i.test(text)) return make('FreeBSD', '', 'bsd', 'medium');
  if (/printer|laserjet|officejet|jetdirect/i.test(text)) return make('Printer firmware', text.slice(0, 80), 'embedded', 'low');
  return make('Embedded network OS', text.slice(0, 80), 'embedded', 'low');
}

function parseHostnameOs(hostname) {
  const h = String(hostname || '').toLowerCase();
  if (!h) return null;
  const make = (name, family) => ({ name, version: '', family, confidence: 'low', source: 'hostname', evidence: [`Hostname: ${hostname}`] });
  if (/iphone|ipad|ipod/.test(h)) return make('iOS/iPadOS', 'ios');
  if (/macbook|imac|mac-?mini|mac-?studio|mac-?pro/.test(h)) return make('macOS', 'macos');
  if (/android|pixel|sm-[a-z0-9]|galaxy|oneplus|redmi|xiaomi/.test(h)) return make('Android', 'android');
  if (/raspberry|raspberrypi/.test(h)) return make('Raspberry Pi OS', 'linux');
  if (/openwrt|lede/.test(h)) return make('OpenWrt', 'linux');
  if (/windows|desktop-|laptop-|win-/.test(h)) return make('Windows', 'windows');
  if (/router|gateway|access-?point|deco|archer|repeater|extender/.test(h)) return make('Network device firmware', 'embedded');
  return null;
}

function osFromServices(services, vendor = '') {
  const ports = new Set((services || []).map((s) => Number(s.port)));
  const v = String(vendor || '').toLowerCase();
  const make = (name, family, evidence) => ({ name, version: '', family, confidence: 'low', source: 'ports', evidence });
  if (ports.has(62078)) return make('iOS/iPadOS', 'ios', ['Port 62078 open (iPhone sync service)']);
  if (ports.has(5555)) return make('Android', 'android', ['Port 5555 open (Android ADB)']);
  if (ports.has(548)) return make('macOS', 'macos', ['Port 548 open (Apple Filing Protocol)']);
  if (ports.has(3389)) return make('Windows', 'windows', ['Port 3389 open (Remote Desktop)']);
  if (ports.has(445) && /microsoft/.test(v)) return make('Windows', 'windows', ['Port 445 open with a Microsoft NIC vendor']);
  if (ports.has(22) && !ports.has(3389) && !ports.has(445)) return make('Linux/Unix-like', 'unix', ['Port 22 open, no Windows service ports']);
  return null;
}

/* Combine every signal into one verdict. Explicit protocol evidence always
 * beats TTL/hostname guesses; conflicting explicit families lower confidence
 * instead of silently picking a winner. */
function classifyOs(input = {}) {
  const sources = [];
  const add = (v) => { if (v) sources.push(v); };
  add(parseSnmpSysDescr(input.snmpSysDescr));
  add(parseSshBanner(input.sshBanner));
  add(parseHttpOs(input.http));
  add(parseSmbDialect(input.smbDialect, { vendor: input.vendor }));

  const ttlVerdict = osFromTtl(input.ttl);
  const at = new Date().toISOString();
  if (!sources.length) {
    const hint = parseHostnameOs(input.hostname) || parseHostnameOs(input.mdnsName) || parseHostnameOs(input.nbname) || osFromServices(input.services, input.vendor) || ttlVerdict;
    if (!hint) return null;
    return {
      ...hint,
      evidence: [...hint.evidence, ...(ttlVerdict && hint.source !== 'ttl' ? ttlVerdict.evidence : [])].slice(0, 6),
      at,
    };
  }

  sources.sort((a, b) => (SOURCE_RANK[a.source] ?? 9) - (SOURCE_RANK[b.source] ?? 9));
  const best = { ...sources[0], evidence: [...sources[0].evidence] };
  for (const other of sources.slice(1)) {
    if (!other.name || other.name === best.name) continue;
    if (other.family && best.family && other.family !== best.family) {
      best.evidence.push(`Conflicting signal: ${other.name}${other.version ? ` (${other.version})` : ''} via ${SOURCE_LABELS[other.source] || other.source}`);
      if (best.confidence !== 'low') best.confidence = 'low';
    } else {
      best.evidence.push(`Also: ${other.name}${other.version ? ` (${other.version})` : ''}`);
    }
  }
  if (ttlVerdict) best.evidence.push(ttlVerdict.evidence[0]);
  best.evidence = [...new Set(best.evidence)].slice(0, 8);
  best.at = at;
  return best;
}

/* ---------- network probes ---------- */

function probeSsh(ip, timeoutMs = 1200, port = 22) {
  return new Promise((resolve) => {
    let done = false;
    let text = '';
    const sock = new net.Socket();
    let timer = null;
    const finish = (value) => {
      if (done) return;
      done = true;
      if (timer) clearTimeout(timer);
      try { sock.destroy(); } catch { /* ignore */ }
      resolve(value || '');
    };
    timer = setTimeout(() => finish(text.split(/\r?\n/)[0].trim()), timeoutMs + 150);
    timer.unref?.();
    sock.setTimeout(timeoutMs);
    sock.on('data', (chunk) => {
      text += chunk.toString('latin1');
      if (text.length > 512 || text.includes('\n')) finish(text.split(/\r?\n/)[0].trim());
    });
    sock.on('timeout', () => finish(''));
    sock.on('error', () => finish(''));
    sock.connect(port, ip);
  });
}

function buildSmb2Negotiate() {
  const dialects = [0x0202, 0x0210, 0x0300, 0x0302];
  const body = Buffer.alloc(36 + dialects.length * 2);
  body.writeUInt16LE(36, 0);
  body.writeUInt16LE(dialects.length, 2);
  body.writeUInt16LE(1, 4);
  body.writeUInt16LE(0, 6);
  body.writeUInt32LE(0, 8);
  crypto.randomBytes(16).copy(body, 12);
  body.writeUInt32LE(0, 28);
  body.writeUInt16LE(0, 32);
  body.writeUInt16LE(0, 34);
  dialects.forEach((d, i) => body.writeUInt16LE(d, 36 + i * 2));

  const header = Buffer.alloc(64);
  Buffer.from([0xFE, 0x53, 0x4D, 0x42]).copy(header, 0);
  header.writeUInt16LE(64, 4);
  header.writeUInt16LE(0, 6);
  header.writeUInt32LE(0, 8);
  header.writeUInt16LE(0, 12);
  header.writeUInt16LE(1, 14);
  header.writeUInt32LE(0, 16);
  header.writeUInt32LE(0, 20);
  header.writeBigUInt64LE(0n, 24);
  header.writeUInt32LE(0, 32);
  header.writeUInt32LE(0, 36);
  header.writeBigUInt64LE(0n, 40);

  const packet = Buffer.concat([header, body]);
  const nb = Buffer.alloc(4);
  nb[0] = 0;
  nb.writeUIntBE(packet.length, 1, 3);
  return Buffer.concat([nb, packet]);
}

function probeSmb2(ip, timeoutMs = 1500, port = 445) {
  return new Promise((resolve) => {
    let done = false;
    let buf = Buffer.alloc(0);
    const sock = new net.Socket();
    let timer = null;
    const finish = (value) => {
      if (done) return;
      done = true;
      if (timer) clearTimeout(timer);
      try { sock.destroy(); } catch { /* ignore */ }
      resolve(value || null);
    };
    timer = setTimeout(() => finish(null), timeoutMs + 150);
    timer.unref?.();
    sock.setTimeout(timeoutMs);
    sock.on('connect', () => {
      try { sock.write(buildSmb2Negotiate()); } catch { finish(null); }
    });
    sock.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length < 4) return;
      const len = (buf[1] << 16) | (buf[2] << 8) | buf[3];
      if (buf.length < 4 + len) return;
      if (len < 72) { finish(null); return; }
      const status = buf.readUInt32LE(12);
      if (status !== 0) { finish(null); return; }
      finish(buf.readUInt16LE(72));
    });
    sock.on('timeout', () => finish(null));
    sock.on('error', () => finish(null));
    sock.connect(port, ip);
  });
}

function berLength(n) {
  if (n < 0x80) return Buffer.from([n]);
  const bytes = [];
  let v = n;
  while (v > 0) { bytes.unshift(v & 0xff); v = Math.floor(v / 256); }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag, value) {
  return Buffer.concat([Buffer.from([tag]), berLength(value.length), value]);
}

function berInt(n) {
  let hex = Math.max(0, Math.floor(n)).toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  let bytes = Buffer.from(hex, 'hex');
  if (!bytes.length) bytes = Buffer.from([0]);
  if (bytes[0] & 0x80) bytes = Buffer.concat([Buffer.from([0]), bytes]);
  return tlv(0x02, bytes);
}

function oidValue(oid) {
  const parts = String(oid).split('.').map(Number);
  const bytes = [40 * parts[0] + parts[1]];
  for (const part of parts.slice(2)) {
    const stack = [];
    let v = part;
    do { stack.unshift(v & 0x7f); v = Math.floor(v / 128); } while (v > 0);
    for (let i = 0; i < stack.length - 1; i++) stack[i] |= 0x80;
    bytes.push(...stack);
  }
  return Buffer.from(bytes);
}

function buildSnmpGet(oid, community = 'public') {
  const requestId = crypto.randomInt(1, 0x7fffffff);
  const varbind = tlv(0x30, Buffer.concat([
    tlv(0x06, oidValue(oid)),
    tlv(0x05, Buffer.alloc(0)),
  ]));
  const pdu = tlv(0xA0, Buffer.concat([
    berInt(requestId), berInt(0), berInt(0), tlv(0x30, varbind),
  ]));
  return tlv(0x30, Buffer.concat([
    berInt(1),
    tlv(0x04, Buffer.from(String(community))),
    pdu,
  ]));
}

function readTlv(buf, offset) {
  if (offset + 2 > buf.length) return null;
  let len = buf[offset + 1];
  let start = offset + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (!n || start + n > buf.length) return null;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[start + i];
    start += n;
  }
  const end = start + len;
  if (end > buf.length) return null;
  return { tag: buf[offset], start, end };
}

function findSnmpSysDescr(buf) {
  const oid = oidValue(SYS_DESCR_OID);
  for (let i = 0; i <= buf.length - oid.length - 2; i++) {
    if (buf[i] !== 0x06 || buf[i + 1] !== oid.length) continue;
    if (!buf.subarray(i + 2, i + 2 + oid.length).equals(oid)) continue;
    const value = readTlv(buf, i + 2 + oid.length);
    if (value && value.tag === 0x04) return buf.subarray(value.start, value.end).toString('utf8');
  }
  return '';
}

function probeSnmp(ip, community = 'public', timeoutMs = 1200) {
  return new Promise((resolve) => {
    let done = false;
    let timer = null;
    const sock = dgram.createSocket('udp4');
    const finish = (value) => {
      if (done) return;
      done = true;
      if (timer) clearTimeout(timer);
      try { sock.close(); } catch { /* ignore */ }
      resolve(value || '');
    };
    timer = setTimeout(() => finish(''), timeoutMs);
    timer.unref?.();
    sock.on('message', (msg) => {
      const value = findSnmpSysDescr(msg);
      if (value) finish(value);
    });
    sock.on('error', () => finish(''));
    try {
      sock.send(buildSnmpGet(SYS_DESCR_OID, community), 161, ip, (err) => {
        if (err) finish('');
      });
    } catch {
      finish('');
    }
  });
}

/* Orchestrator used by scans (shallow) and Identify (deep). */
async function probeOs(ip, ctx = {}, opts = {}) {
  const deep = Boolean(opts.deep);
  const services = ctx.services || [];
  const ports = new Set(services.map((s) => Number(s.port)));
  const out = {};
  const tasks = [];
  if (deep || ports.has(22)) {
    tasks.push(probeSsh(ip, opts.sshTimeoutMs || 1200).then((v) => { out.sshBanner = v; }).catch(() => {}));
  }
  if (deep || ports.has(445)) {
    tasks.push(probeSmb2(ip, opts.smbTimeoutMs || 1500).then((v) => { out.smbDialect = v; }).catch(() => {}));
  }
  if (deep) {
    tasks.push(probeSnmp(ip, opts.snmpCommunity || 'public', opts.snmpTimeoutMs || 1200)
      .then((v) => { out.snmpSysDescr = v; }).catch(() => {}));
  }
  await Promise.all(tasks);
  return classifyOs({ ...ctx, ...out });
}

module.exports = {
  SOURCE_LABELS,
  parseTtl,
  initialTtl,
  osFromTtl,
  parseSshBanner,
  parseHttpOs,
  parseSmbDialect,
  parseSnmpSysDescr,
  parseHostnameOs,
  osFromServices,
  classifyOs,
  probeSsh,
  probeSmb2,
  probeSnmp,
  probeOs,
  buildSmb2Negotiate,
  buildSnmpGet,
  findSnmpSysDescr,
};
