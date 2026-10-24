/* LAN-CAP — friendly-name discovery.
 *
 * DNS hostnames are often missing or useless on home/hostel LANs, which is
 * why other scanners appear to know "exact" names. This module asks the
 * devices themselves over mDNS/Bonjour (UDP 5353) and NetBIOS (UDP 137).
 * Both protocols are read-only and require no admin rights.
 */
const dgram = require('dgram');
const crypto = require('crypto');

const MDNS_GROUP = '224.0.0.251';
const MDNS_PORT = 5353;

/* Common service types: Apple/AirPlay, Chromecast, printers, file sharing,
 * Windows workstation discovery, HomeKit/Matter and a few media devices. */
const MDNS_SERVICES = [
  '_airplay._tcp.local',
  '_raop._tcp.local',
  '_googlecast._tcp.local',
  '_spotify-connect._tcp.local',
  '_http._tcp.local',
  '_ipp._tcp.local',
  '_printer._tcp.local',
  '_smb._tcp.local',
  '_device-info._tcp.local',
  '_workstation._tcp.local',
  '_companion-link._tcp.local',
  '_hap._tcp.local',
  '_homekit._tcp.local',
  '_ssh._tcp.local',
  '_sftp-ssh._tcp.local',
  '_afpovertcp._tcp.local',
  '_rfb._tcp.local',
  '_sonos._tcp.local',
  '_amzn-wplay._tcp.local',
  '_matter._tcp.local',
  '_sleep-proxy._udp.local',
];

function encodeName(name) {
  const parts = [];
  for (const label of String(name || '').split('.').filter(Boolean)) {
    const b = Buffer.from(label, 'utf8');
    parts.push(Buffer.from([b.length]), b);
  }
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}

function decodeName(buf, start) {
  const labels = [];
  let offset = start;
  let next = start;
  let jumped = false;
  let hops = 0;
  while (offset < buf.length) {
    const len = buf[offset];
    if (len === 0) {
      offset += 1;
      if (!jumped) next = offset;
      break;
    }
    if ((len & 0xc0) === 0xc0) {
      if (offset + 1 >= buf.length) break;
      const ptr = ((len & 0x3f) << 8) | buf[offset + 1];
      if (!jumped) next = offset + 2;
      jumped = true;
      offset = ptr;
      if (++hops > 24) break;
      continue;
    }
    if (len > 63 || offset + 1 + len > buf.length) break;
    labels.push(buf.subarray(offset + 1, offset + 1 + len).toString('utf8'));
    offset += 1 + len;
    if (!jumped) next = offset;
  }
  return { name: labels.join('.'), next };
}

function buildMdnsQuery(services = MDNS_SERVICES) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(services.length, 4);
  const questions = services.map((name) => {
    const q = Buffer.alloc(4);
    q.writeUInt16BE(12, 0);
    q.writeUInt16BE(1, 2);
    return Buffer.concat([encodeName(name), q]);
  });
  return Buffer.concat([header, ...questions]);
}

function unescapeDns(name) {
  return String(name || '')
    .replace(/\\(\d{3})/g, (_m, n) => String.fromCharCode(Number(n)))
    .replace(/\\(.)/g, '$1');
}

function cleanInstanceName(raw) {
  let s = unescapeDns(raw).trim();
  const dot = s.indexOf('._');
  if (dot > 0) s = s.slice(0, dot);
  if (s.includes('@')) s = s.slice(s.lastIndexOf('@') + 1).trim();
  if (!s || s.startsWith('_') || /^[\d.]+$/.test(s)) return '';
  if (/^[0-9a-f]{2}[:-][0-9a-f]{2}/i.test(s)) return '';
  if (/^[0-9a-f]{12,}$/i.test(s.replace(/[^0-9a-f]/gi, ''))) return '';
  if (/^(airplay|raop|googlecast|http|ipp|printer|workstation|companion-link|hap|homekit|ssh|sftp-ssh|afpovertcp|rfb|sonos|amzn-wplay|matter|sleep-proxy|device-info)$/i.test(s)) return '';
  return s.replace(/\s+/g, ' ').trim().slice(0, 120);
}

function nameScore(name) {
  if (!name) return -Infinity;
  let score = 0;
  if (/@/.test(name)) score -= 40;
  if (/^[A-F0-9-]{12,}$/i.test(name)) score -= 80;
  if (/^(unknown|device|localhost|android|iphone|ipad)$/i.test(name)) score -= 20;
  if (/\s/.test(name)) score += 3;
  if (/[a-z]/i.test(name)) score += 4;
  score += Math.min(name.length, 48) / 10;
  return score;
}

function parseMdnsPacket(buf, sourceIp) {
  if (!buf || buf.length < 12) return null;
  const qd = buf.readUInt16BE(4);
  const an = buf.readUInt16BE(6);
  const ns = buf.readUInt16BE(8);
  const ar = buf.readUInt16BE(10);
  let off = 12;
  for (let i = 0; i < qd; i++) {
    const d = decodeName(buf, off);
    off = d.next + 4;
    if (off > buf.length) return null;
  }
  const result = {
    ip: String(sourceIp || '').replace(/^::ffff:/, ''),
    names: [],
    hostname: '',
    model: '',
    services: [],
  };
  const total = an + ns + ar;
  for (let i = 0; i < total; i++) {
    if (off + 2 > buf.length) break;
    const owner = decodeName(buf, off);
    off = owner.next;
    if (off + 10 > buf.length) break;
    const type = buf.readUInt16BE(off);
    const rdlen = buf.readUInt16BE(off + 8);
    const rstart = off + 10;
    const rend = rstart + rdlen;
    if (rend > buf.length) break;

    if (type === 12) {
      const ptr = decodeName(buf, rstart).name;
      const n = cleanInstanceName(ptr);
      if (n) {
        result.names.push(n);
        if (!result.services.includes(owner.name)) result.services.push(owner.name);
      }
    } else if (type === 33 && rdlen > 6) {
      const srv = decodeName(buf, rstart + 6).name;
      const host = cleanInstanceName(srv);
      if (host) result.hostname = host;
    } else if (type === 16) {
      let p = rstart;
      while (p < rend) {
        const len = buf[p];
        p += 1;
        if (!len || p + len > rend) break;
        const entry = buf.subarray(p, p + len).toString('utf8');
        p += len;
        const eq = entry.indexOf('=');
        if (eq < 1) continue;
        const key = entry.slice(0, eq).toLowerCase();
        const val = unescapeDns(entry.slice(eq + 1)).trim();
        if ((key === 'model' || key === 'md' || key === 'am') && val) result.model = val.slice(0, 100);
        if (key === 'fn' && val) result.names.push(cleanInstanceName(val));
      }
    } else if (type === 1 && rdlen === 4) {
      const host = cleanInstanceName(owner.name);
      if (host && !result.hostname) result.hostname = host;
    }
    off = rend;
  }

  result.names = [...new Set(result.names.filter(Boolean))];
  result.name = result.names.sort((a, b) => nameScore(b) - nameScore(a))[0] || '';
  if (!result.name && !result.hostname && !result.model) return null;
  return result;
}

function sweepMdns(durationMs = 2500) {
  return new Promise((resolve) => {
    const found = new Map();
    let done = false;
    let sock;
    try {
      sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    } catch {
      resolve([]);
      return;
    }
    const finish = () => {
      if (done) return;
      done = true;
      try { sock.close(); } catch { /* already closed */ }
      resolve([...found.values()]);
    };
    const timer = setTimeout(finish, durationMs);
    timer.unref?.();
    const merge = (info) => {
      if (!info || !info.ip) return;
      const prev = found.get(info.ip) || {};
      found.set(info.ip, {
        ip: info.ip,
        name: nameScore(info.name) >= nameScore(prev.name) ? info.name : prev.name,
        hostname: prev.hostname || info.hostname,
        model: prev.model || info.model,
        services: [...new Set([...(prev.services || []), ...(info.services || [])])],
      });
    };
    sock.on('error', finish);
    sock.on('message', (msg, rinfo) => {
      try { merge(parseMdnsPacket(msg, rinfo.address)); } catch { /* ignore malformed packet */ }
    });
    sock.bind(MDNS_PORT, () => {
      try { sock.addMembership(MDNS_GROUP); } catch { /* interface may not support it */ }
      try {
        sock.setMulticastTTL(255);
        sock.setMulticastLoopback(true);
      } catch { /* optional */ }
      const query = buildMdnsQuery();
      const send = () => {
        try { sock.send(query, MDNS_PORT, MDNS_GROUP); } catch { /* optional */ }
      };
      send();
      const again = setTimeout(send, 350);
      again.unref?.();
    });
  });
}

function encodeNbName(name = '*') {
  const padded = (String(name).toUpperCase() + ' '.repeat(15)).slice(0, 15) + '\0';
  const out = Buffer.alloc(32);
  for (let i = 0; i < 16; i++) {
    const c = padded.charCodeAt(i);
    out[i * 2] = 0x41 + (c >> 4);
    out[i * 2 + 1] = 0x41 + (c & 15);
  }
  return Buffer.concat([Buffer.from([32]), out, Buffer.from([0])]);
}

function buildNbstatQuery() {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(crypto.randomInt(1, 0xffff), 0);
  header.writeUInt16BE(1, 4);
  const tail = Buffer.alloc(4);
  tail.writeUInt16BE(0x0021, 0);
  tail.writeUInt16BE(0x0001, 2);
  return Buffer.concat([header, encodeNbName('*'), tail]);
}

function parseNbstatResponse(buf) {
  if (!buf || buf.length < 12) return '';
  const qd = buf.readUInt16BE(4);
  const an = buf.readUInt16BE(6);
  let off = 12;
  for (let i = 0; i < qd; i++) {
    const d = decodeName(buf, off);
    off = d.next + 4;
    if (off > buf.length) return '';
  }
  for (let i = 0; i < an; i++) {
    const d = decodeName(buf, off);
    off = d.next;
    if (off + 10 > buf.length) return '';
    const type = buf.readUInt16BE(off);
    const rdlen = buf.readUInt16BE(off + 8);
    const rstart = off + 10;
    if (rstart + rdlen > buf.length) return '';
    if (type === 0x21 && rdlen >= 1) {
      const count = buf[rstart];
      let p = rstart + 1;
      const names = [];
      for (let n = 0; n < count && p + 18 <= buf.length; n++, p += 18) {
        const raw = buf.subarray(p, p + 15).toString('ascii').replace(/\0.*$/, '').trim();
        const suffix = buf[p + 15];
        const flags = buf.readUInt16BE(p + 16);
        if (!raw || (flags & 0x8000)) continue;
        if (suffix === 0x00 || suffix === 0x20) names.push({ name: raw, suffix });
      }
      names.sort((a, b) => (a.suffix === 0x00 ? -1 : 1) - (b.suffix === 0x00 ? -1 : 1));
      if (names[0]) return names[0].name;
    }
    off = rstart + rdlen;
  }
  return '';
}

function netbiosName(ip, timeoutMs = 400) {
  return new Promise((resolve) => {
    let done = false;
    const sock = dgram.createSocket('udp4');
    const finish = (name) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { sock.close(); } catch { /* already closed */ }
      resolve(name || '');
    };
    const timer = setTimeout(() => finish(''), timeoutMs);
    timer.unref?.();
    sock.on('error', () => finish(''));
    sock.on('message', (msg) => {
      try { finish(parseNbstatResponse(msg)); } catch { finish(''); }
    });
    try {
      sock.send(buildNbstatQuery(), 137, ip, (err) => { if (err) finish(''); });
    } catch { finish(''); }
  });
}

async function sweepNetbios(ips, timeoutMs = 400, concurrency = 48) {
  const list = [...new Set(ips || [])];
  const out = [];
  for (let i = 0; i < list.length; i += concurrency) {
    const chunk = list.slice(i, i + concurrency);
    const results = await Promise.all(chunk.map(async (ip) => ({ ip, name: await netbiosName(ip, timeoutMs) })));
    for (const r of results) if (r.name) out.push(r);
  }
  return out;
}

module.exports = {
  MDNS_SERVICES,
  encodeName,
  decodeName,
  encodeNbName,
  buildMdnsQuery,
  parseMdnsPacket,
  sweepMdns,
  buildNbstatQuery,
  parseNbstatResponse,
  netbiosName,
  sweepNetbios,
  cleanInstanceName,
};
