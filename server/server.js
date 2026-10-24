/* LAN-CAP backend — Node + Express, no admin needed.
 * Serves the REST API used by the React client and (in production)
 * the built client itself from ../client/dist.
 */
'use strict';

const cors = require('cors');
const { execFile } = require('child_process');
const dns = require('dns').promises;
const express = require('express');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { promisify } = require('util');
require('dotenv').config({ path: path.join(__dirname, '.env') });

const execFileAsync = promisify(execFile);
const PORT = Number(process.env.PORT || 5174);
const HOST = process.env.HOST || '127.0.0.1';
const DATA_DIR = path.join(__dirname, 'data');
const NOTES_FILE = path.join(DATA_DIR, 'notes.json');
const HISTORY_FILE = path.join(DATA_DIR, 'history.json');
const DEVICES_FILE = path.join(DATA_DIR, 'devices.json');
const TRUSTED_FILE = path.join(DATA_DIR, 'trusted.json');
const RETENTION_DAYS = 4;
const cloneStore = require('./db');
const cloneDetector = require('./detector');
const osFp = require('./os-fingerprint');
const nameDisc = require('./discovery-names');
const { createRouterSecurity } = require('./router-security');
const { createTools } = require('./tools');

const DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443];

/* Service discovery: small fast port set probed on every discovered host
 * (when serviceScan is on), so devices can be labeled Web/SSH/Printer/Cam. */
const SERVICE_PORTS = [22, 80, 443, 445, 139, 554, 631, 8080, 8443, 9100];
const SERVICE_LABELS = {
  22: 'SSH', 80: 'Web', 443: 'Web', 445: 'SMB', 139: 'NetBIOS',
  554: 'Camera', 631: 'Printer', 8080: 'Web', 8443: 'Web', 9100: 'Printer',
};

async function scanServices(ip, timeoutMs = 400) {
  const found = await mapLimit(SERVICE_PORTS, 10, (port) => checkPort(ip, port, timeoutMs));
  return found.filter((r) => r.open).map((r) => ({ port: r.port, label: SERVICE_LABELS[r.port] || 'Open', ms: r.ms }));
}

/* Strong service signals override the vendor heuristic (a JetDirect/IPP
 * port means printer even if the NIC vendor is generic, etc.). */
function refineType(type, services) {
  const ports = new Set((services || []).map((s) => s.port));
  if (ports.has(9100) || ports.has(631)) return 'printer';
  if (ports.has(554) || ports.has(8554)) return 'camera';
  return type;
}

/* ---------- device fingerprinting (no admin needed) ----------
 * Embedded devices leak their identity over plain protocols:
 *  - HTTP: Server header / page <title> / auth realm (often exact models)
 *  - HTTPS: TLS certificate subject/issuer (many vendors put model in CN)
 *  - SSDP/UPnP: multicast discovery replies + device XML (manufacturer+model)
 * OS/version comes from exposed service banners and headers (see
 * os-fingerprint.js); raw TCP-window fingerprinting still needs admin. */
function httpProbe(ip, port, useTls, timeoutMs = 2500) {
  return new Promise((resolve) => {
    const lib = useTls ? require('https') : require('http');
    const out = { server: '', title: '', realm: '', status: null, location: '' };
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };
    try {
      const req = lib.get({ host: ip, port, path: '/', timeout: timeoutMs, rejectUnauthorized: false }, (res) => {
        out.status = Number(res.statusCode) || null;
        out.location = String(res.headers.location || '');
        out.server = String(res.headers.server || '');
        const www = String(res.headers['www-authenticate'] || '');
        const m = www.match(/realm="([^"]+)"/i);
        if (m) out.realm = m[1];
        let body = '';
        res.on('data', (c) => { if (body.length < 8192) body += c; });
        res.on('end', () => {
          const t = body.match(/<title[^>]*>([^<]{1,120})<\/title>/i);
          if (t) out.title = t[1].trim();
          finish(out);
        });
      });
      req.on('timeout', () => { req.destroy(); finish(out); });
      req.on('error', () => finish(out));
      setTimeout(() => finish(out), timeoutMs + 500).unref?.();
    } catch { finish(out); }
  });
}

function certProbe(ip, timeoutMs = 2500, port = 443) {
  return new Promise((resolve) => {
    const out = { subject: '', issuer: '' };
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };
    try {
      const tls = require('tls');
      const sock = tls.connect({ host: ip, port, rejectUnauthorized: false, timeout: timeoutMs },
        () => {
          try {
            const c = sock.getPeerCertificate() || {};
            out.subject = c.subject ? [c.subject.CN, c.subject.O].filter(Boolean).join(' / ') : '';
            out.issuer = c.issuer ? [c.issuer.CN, c.issuer.O].filter(Boolean).join(' / ') : '';
          } catch { /* ignore */ }
          sock.destroy();
          finish(out);
        });
      sock.on('timeout', () => { sock.destroy(); finish(out); });
      sock.on('error', () => finish(out));
      setTimeout(() => finish(out), timeoutMs + 500).unref?.();
    } catch { finish(out); }
  });
}

function ssdpSweep(timeoutMs = 2500) {
  return new Promise((resolve) => {
    const found = new Map();
    let done = false;
    const finish = () => { if (!done) { done = true; try { sock.close(); } catch {} resolve([...found.values()]); } };
    try {
      const dgram = require('dgram');
      const sock = dgram.createSocket('udp4');
      sock.on('message', (msg, rinfo) => {
        const text = msg.toString('utf8', 0, 2048);
        if (!/HTTP\/1\.\d 200/i.test(text.slice(0, 60))) return;
        const get = (re) => { const m = text.match(re); return m ? m[1].trim() : ''; };
        const key = `${rinfo.address}|${get(/^LOCATION:\s*(.+)$/im) || get(/^ST:\s*(.+)$/im)}`;
        if (!found.has(key)) {
          found.set(key, {
            ip: rinfo.address,
            location: get(/^LOCATION:\s*(.+)$/im),
            server: get(/^SERVER:\s*(.+)$/im),
            st: get(/^ST:\s*(.+)$/im),
            usn: get(/^USN:\s*(.+)$/im),
          });
        }
      });
      sock.on('error', finish);
      sock.bind(0, () => {
        try {
          const req = Buffer.from([
            'M-SEARCH * HTTP/1.1', 'HOST: 239.255.255.250:1900', 'MAN: "ns=01; ns=01"',
            'MX: 2', 'ST: ssdp:all', '', '',
          ].join('\r\n'));
          sock.setMulticastTTL(2);
          sock.send(req, 0, req.length, 1900, '239.255.255.250');
        } catch { /* ignore */ }
      });
      setTimeout(finish, timeoutMs).unref?.();
    } catch { finish(); }
  });
}

function fetchUpnpDesc(url, timeoutMs = 2500) {
  return new Promise((resolve) => {
    const out = { manufacturer: '', model: '', friendly: '' };
    if (!url || !/^https?:\/\//i.test(url)) return resolve(out);
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };
    try {
      const lib = url.toLowerCase().startsWith('https') ? require('https') : require('http');
      const req = lib.get(url, { timeout: timeoutMs, rejectUnauthorized: false }, (res) => {
        let body = '';
        res.on('data', (c) => { if (body.length < 16384) body += c; });
        res.on('end', () => {
          const get = (tag) => { const m = body.match(new RegExp(`<${tag}[^>]*>([^<]{1,120})</${tag}>`, 'i')); return m ? m[1].trim() : ''; };
          out.manufacturer = get('manufacturer');
          out.model = get('modelName') || get('modelNumber');
          out.friendly = get('friendlyName');
          finish(out);
        });
      });
      req.on('timeout', () => { req.destroy(); finish(out); });
      req.on('error', () => finish(out));
      setTimeout(() => finish(out), timeoutMs + 500).unref?.();
    } catch { finish(out); }
  });
}

/* Deterministic verdict from fingerprint evidence. Returns
 * { model, kind, confidence: 'high'|'medium'|'low', evidence[] }. */
function identifyDevice(fp) {
  const evidence = [];
  const { vendor = '', hostname = '', services = [], http = {}, cert = {}, upnp = {} } = fp;
  const hasPort = (...ps) => (services || []).some((s) => ps.includes(s.port));

  if (upnp.model || upnp.manufacturer) {
    const model = [upnp.manufacturer, upnp.model].filter(Boolean).join(' ');
    evidence.push(`UPnP announces: ${[upnp.friendly, model].filter(Boolean).join(' — ')}`);
    return { model, kind: kindFromText(`${model} ${upnp.friendly}`), confidence: 'high', evidence };
  }
  const clues = [
    [http.server, 'HTTP Server header'],
    [http.realm, 'login realm'],
    [http.title, 'web page title'],
    [cert.subject, 'TLS certificate'],
  ];
  // Generic embedded webservers: recognizable, but could be anything
  // (usually routers, APs, cameras, printers) — medium confidence, no kind.
  const embedded = `${http.server} ${http.realm}`.match(/goahead|rompager|allegrosoft|boa\/|uhttpd|httpd[\s\/]*2/i);
  if (embedded) {
    evidence.push(`HTTP Server header: ${http.server.slice(0, 100)}`);
    return { model: `Embedded web device (${embedded[0]})`, kind: null, confidence: 'medium', evidence };
  }
  for (const [text, label] of clues) {
    if (!text) continue;
    evidence.push(`${label}: ${text.slice(0, 100)}`);
    const m = String(text).match(/(sonos|philips\s*hue|hikvision|dahua|axis|synology|qnap|asus|netgear|ubiquiti|mikrotik|canon|epson|brother|roku|chromecast|echo|kindle|playstation| xbox |xbox|homepod|nest|ring|wyze|reolink|amcrest|foscam|tapo|kasa|shelly|tuya|espressif|raspberry|arduino|octoprint|pihole|openwrt|fritz!box|deco|eero|orbi|veloe|hue\s*bridge|tradfri|smartthings|home\s*assistant)/i);
    if (m) {
      const model = prettyModel(m[1], text);
      return { model, kind: kindFromText(`${model} ${text}`) || inferType(vendor, hostname), confidence: 'high', evidence };
    }
  }
  if (hasPort(9100, 631)) {
    evidence.push('Printer ports open (9100/631)');
    return { model: vendor !== 'Unknown' ? `${vendor} printer` : 'Network printer', kind: 'printer', confidence: 'medium', evidence };
  }
  if (hasPort(554, 8554)) {
    evidence.push('Camera stream port open (RTSP)');
    return { model: vendor !== 'Unknown' ? `${vendor} camera` : 'IP camera', kind: 'camera', confidence: 'medium', evidence };
  }
  if (hostname) {
    evidence.push(`Hostname: ${hostname}`);
    const t = inferType(vendor, hostname);
    if (t !== 'unknown') return { model: '', kind: t, confidence: 'medium', evidence };
  }
  if (vendor && vendor !== 'Unknown') evidence.push(`MAC vendor: ${vendor}`);
  return { model: '', kind: null, confidence: 'low', evidence };
}

function prettyModel(hit, text) {
  const h = hit.toLowerCase().replace(/\s+/g, ' ').trim();
  const after = String(text).match(new RegExp(`${hit.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*[/:v-]*\\s*([\\w .-]{1,24})`, 'i'));
  const base = h.replace(/^./, (c) => c.toUpperCase());
  return after && after[1].trim() ? `${base} ${after[1].trim()}`.slice(0, 60) : base;
}

function kindFromText(text) {
  const t = String(text).toLowerCase();
  const has = (...ks) => ks.some((k) => t.includes(k));
  if (has('bulb', 'light', 'hue', 'tradfri', 'lamp')) return 'iot';
  if (has('printer', 'laserjet', 'officejet', 'jetdirect')) return 'printer';
  if (has('camera', 'cam ', 'doorbell', 'nvr', 'dvr')) return 'camera';
  if (has('playstation', 'xbox', 'nintendo')) return 'console';
  if (has('sonos', 'speaker', 'soundbar', 'echo', 'homepod', 'alexa')) return 'speaker';
  if (has(' tv', 'television', 'bravia', 'roku', 'chromecast', 'fire tv', 'appletv')) return 'tv';
  if (has('router', 'gateway', 'access point', 'openwrt', 'fritz', 'deco', 'eero', 'orbi')) return 'router';
  if (has('phone', 'iphone', 'pixel', 'galaxy')) return 'phone';
  if (has('nas', 'synology', 'qnap')) return 'computer';
  return null;
}

/* Collect a fingerprint for one IP (used by /api/identify and scans). */
async function fingerprintIp(ip, ctx = {}) {
  const ports = new Set((ctx.services || []).map((s) => s.port));
  const wantHttp = ports.size === 0 || ports.has(80) || ports.has(8080) || ports.has(8443);
  const wantTls = ports.size === 0 || ports.has(443);
  const [http, cert] = await Promise.all([
    wantHttp ? httpProbe(ip, ports.has(8080) && !ports.has(80) ? 8080 : 80, false) : { server: '', title: '', realm: '' },
    wantTls ? certProbe(ip) : { subject: '', issuer: '' },
  ]);
  return { ip, vendor: ctx.vendor || '', hostname: ctx.hostname || '', services: ctx.services || [], http, cert, upnp: ctx.upnp || {} };
}

/* Full identify pipeline for one IP (shared by /api/identify and /api/ai-guess). */
async function identifyIp(ip) {
  const inv = readJson(DEVICES_FILE, {});
  const ctx = inv[ip] || { vendor: 'Unknown', hostname: '', services: [] };
  const fp = await fingerprintIp(ip, ctx);
  try {
    const all = await ssdpSweep(2000);
    const hit = all.find((s) => s.ip === ip);
    if (hit) {
      fp.upnp = { ...hit };
      if (hit.location) Object.assign(fp.upnp, await fetchUpnpDesc(hit.location));
    }
  } catch { /* ssdp optional */ }
  const verdict = identifyDevice({ ip, vendor: ctx.vendor, hostname: ctx.hostname, services: ctx.services || [], http: fp.http, cert: fp.cert, upnp: fp.upnp });
  const entry = { model: verdict.model, kind: verdict.kind, confidence: verdict.confidence, evidence: verdict.evidence, at: new Date().toISOString() };
  let ttl = null;
  try { ttl = (await pingHost(ip, 1)).ttl; } catch { /* TTL is optional */ }
  let os = null;
  try {
    os = await osFp.probeOs(ip, {
      ttl,
      vendor: ctx.vendor,
      hostname: ctx.hostname,
      services: ctx.services || [],
      http: fp.http,
      upnp: fp.upnp,
    }, {
      deep: true,
      snmpCommunity: process.env.SNMP_COMMUNITY || 'public',
    });
  } catch { /* OS detection is best-effort */ }
  if (inv[ip]) {
    inv[ip].fp = entry;
    if (verdict.kind) inv[ip].type = verdict.kind;
    if (os) inv[ip].os = os;
    if (fp.upnp && (fp.upnp.friendlyName || fp.upnp.modelName)) {
      inv[ip].upnp = {
        friendlyName: fp.upnp.friendlyName || '',
        modelName: fp.upnp.modelName || '',
        modelDescription: fp.upnp.modelDescription || '',
        manufacturer: fp.upnp.manufacturer || '',
        location: fp.upnp.location || '',
        server: fp.upnp.server || '',
      };
    }
    writeJson(DEVICES_FILE, inv);
  }
  return { fp: { http: fp.http, cert: fp.cert, upnp: fp.upnp }, verdict: entry, os, upnp: fp.upnp };
}

/* Optional LLM layer: local Ollama first, OpenAI-compatible cloud fallback.
 * Never required — deterministic verdicts work offline.
 * Ollama is the default: with OLLAMA_HOST/OLLAMA_MODEL set (see .env),
 * /api/ai-guess calls the local model directly. */
function ollamaConfig() {
  return {
    host: (process.env.OLLAMA_HOST || 'http://localhost:11434').replace(/\/$/, ''),
    model: process.env.OLLAMA_MODEL || 'llama3.1',
  };
}

/* Probe the local Ollama daemon: reachable? model pulled? Shared by
 * /api/ai-status, /api/health and the /api/ai-guess error hints. */
async function aiStatus(timeoutMs = 5000) {
  const { host, model } = ollamaConfig();
  const status = {
    provider: 'ollama',
    host,
    model,
    reachable: false,
    modelAvailable: false,
    models: [],
    openaiConfigured: Boolean(process.env.OPENAI_API_KEY),
    error: null,
  };
  try {
    const r = await fetch(`${host}/api/tags`, { signal: AbortSignal.timeout(timeoutMs) });
    if (!r.ok) {
      status.error = `Ollama HTTP ${r.status}`;
      return status;
    }
    status.reachable = true;
    const j = await r.json().catch(() => ({}));
    const names = (j.models || []).map((m) => String(m.name || m.model || ''));
    status.models = names;
    const want = model.toLowerCase();
    status.modelAvailable = names.some((n) => {
      const l = n.toLowerCase();
      return l === want || l === `${want}:latest` || l.startsWith(`${want}:`);
    });
    if (!status.modelAvailable) status.error = `model "${model}" not pulled — run: ollama pull ${model}`;
  } catch (e) {
    status.error = `Ollama not reachable at ${host} — run: ollama serve (${e.cause?.message || e.message || e})`;
  }
  return status;
}

async function llmGuess(summary) {
  const prompt = `You identify LAN devices from network fingerprints. Reply with ONE short line: the most likely specific device (examples: "Philips Hue Bridge", "Sonos One speaker", "Generic IP camera"). If unsure, reply exactly "Unknown".\nFingerprint: ${JSON.stringify(summary).slice(0, 1500)}`;
  const { host: ollamaHost, model: ollamaModel } = ollamaConfig();
  try {
    const r = await fetch(`${ollamaHost}/api/generate`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: ollamaModel, prompt, stream: false }),
      signal: AbortSignal.timeout(60000),
    });
    if (r.ok) {
      const j = await r.json();
      if (j.response && String(j.response).trim()) {
        return { guess: String(j.response).trim().split('\n')[0].slice(0, 140), source: `ollama:${ollamaModel}` };
      }
      // Model name unknown to Ollama returns 404 with {"error":"model ... not found"}.
      try {
        if (String(j.error || '').includes('not found')) {
          throw new Error(`ollama model "${ollamaModel}" not found — run: ollama pull ${ollamaModel}`);
        }
      } catch (e) { if (e.message.startsWith('ollama model')) throw e; }
    } else {
      const body = await r.text().catch(() => '');
      if (r.status === 404 && /not found/i.test(body)) {
        const err = new Error(`ollama model "${ollamaModel}" not found — run: ollama pull ${ollamaModel}`);
        err.code = 'MODEL_MISSING';
        throw err;
      }
    }
  } catch (e) {
    if (e.code === 'MODEL_MISSING' || /ollama model ".+" not found/.test(e.message || '')) throw e;
    /* ollama absent/down — fall through to cloud, else null below */
    if (!process.env.OPENAI_API_KEY) {
      const err = new Error(`Ollama not reachable at ${ollamaHost} — run: ollama serve`);
      err.code = 'OLLAMA_DOWN';
      err.cause = e;
      // Don't throw yet: cloud fallback may still work. Record for hint.
      llmGuess.lastOllamaError = err;
    }
  }
  if (process.env.OPENAI_API_KEY) {
    try {
      const r = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${process.env.OPENAI_API_KEY}` },
        body: JSON.stringify({ model: process.env.OPENAI_MODEL || 'gpt-4o-mini', messages: [{ role: 'user', content: prompt }], max_tokens: 60 }),
        signal: AbortSignal.timeout(25000),
      });
      if (r.ok) {
        const j = await r.json();
        const t = j.choices?.[0]?.message?.content?.trim().split('\n')[0];
        if (t) return { guess: t.slice(0, 140), source: 'openai' };
      }
    } catch { /* ignore */ }
  }
  return null;
}

/* ---------- UPnP WAN monitor (honest totals, not per-device) ----------
 * Home routers expose TOTAL up/down bytes via UPnP IGD — never per-device
 * breakdowns (the spec has none; vendors don't add them). So this reports
 * live whole-connection throughput; per-device "who's hogging" needs
 * SNMP-managed or OpenWrt-class gear and is out of scope for a no-admin app. */
const wan = { ctrlUrl: null, service: null, checkedAt: 0, last: null, upBytes: null, downBytes: null, rateUp: 0, rateDown: 0, at: null };

function soapAction(ctrlUrl, service, action) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };
    try {
      const u = new URL(ctrlUrl);
      const body = `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:${action} xmlns:u="${service}"/></s:Body></s:Envelope>`;
      const lib = u.protocol === 'https:' ? require('https') : require('http');
      const req = lib.request({
        host: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80), path: u.pathname,
        method: 'POST', timeout: 4000, rejectUnauthorized: false,
        headers: { 'Content-Type': 'text/xml; charset="utf-8"', SOAPAction: `"${service}#${action}"`, 'Content-Length': Buffer.byteLength(body) },
      }, (res) => {
        let text = '';
        res.on('data', (c) => { if (text.length < 16384) text += c; });
        res.on('end', () => finish(text));
      });
      req.on('timeout', () => { req.destroy(); finish(''); });
      req.on('error', () => finish(''));
      req.end(body);
      setTimeout(() => finish(''), 4500).unref?.();
    } catch { finish(''); }
  });
}

async function getWanStats() {
  const now = Date.now();
  if (!wan.ctrlUrl && now - wan.checkedAt < 60000) return { supported: false };
  if (!wan.ctrlUrl) {
    wan.checkedAt = now;
    try {
      const all = await ssdpSweep(2500);
      for (const s of all) {
        if (!s.location) continue;
        try {
          const lib = s.location.toLowerCase().startsWith('https') ? require('https') : require('http');
          const xml = await new Promise((res) => {
            const req = lib.get(s.location, { timeout: 4000 }, (r) => {
              let t = ''; r.on('data', (c) => { if (t.length < 32768) t += c; }); r.on('end', () => res(t));
            });
            req.on('timeout', () => { req.destroy(); res(''); });
            req.on('error', () => res(''));
          });
          const svc = [...xml.matchAll(/<service>([\s\S]*?)<\/service>/gi)]
            .map((m) => ({
              type: (m[1].match(/<serviceType>([^<]+)<\/serviceType>/i) || [])[1] || '',
              ctrl: (m[1].match(/<controlURL>([^<]+)<\/controlURL>/i) || [])[1] || '',
            }))
            .find((x) => /WANCommonInterfaceConfig/i.test(x.type));
          if (svc && svc.ctrl) {
            const base = new URL(s.location);
            wan.ctrlUrl = new URL(svc.ctrl, `${base.protocol}//${base.host}`).toString();
            wan.service = (xml.match(/<serviceType>([^<]*WANCommonInterfaceConfig[^<]*)<\/serviceType>/i) || [])[1];
            break;
          }
        } catch { /* next candidate */ }
      }
    } catch { /* no upnp */ }
    if (!wan.ctrlUrl) return { supported: false };
  }
  try {
    const [up, down] = await Promise.all([
      soapAction(wan.ctrlUrl, wan.service, 'GetTotalBytesSent'),
      soapAction(wan.ctrlUrl, wan.service, 'GetTotalBytesReceived'),
    ]);
    const num = (t, tag) => { const m = t.match(new RegExp(`<${tag}>(\\d+)</${tag}>`)); return m ? Number(m[1]) : null; };
    const u = num(up, 'NewTotalBytesSent');
    const d = num(down, 'NewTotalBytesReceived');
    if (u === null || d === null) { wan.ctrlUrl = null; return { supported: false }; }
    if (wan.last) {
      const dt = Math.max(1, (now - wan.last.at) / 1000);
      wan.rateUp = Math.max(0, (u - wan.last.u) / dt);
      wan.rateDown = Math.max(0, (d - wan.last.d) / dt);
    }
    wan.last = { u, d, at: now };
    wan.upBytes = u; wan.downBytes = d; wan.at = new Date().toISOString();
    return { supported: true, upBytes: u, downBytes: d, rateUpBps: Math.round(wan.rateUp), rateDownBps: Math.round(wan.rateDown), at: wan.at };
  } catch { wan.ctrlUrl = null; return { supported: false }; }
}

/* ---------- speed test: link rate + real throughput ----------
 * Two different numbers, often confused:
 *  - LINK RATE: the PHY rate the Wi-Fi radio negotiated with the access
 *    point (e.g. 866 Mbps on 802.11ac) — the ceiling of the wireless hop.
 *    The OS reports it; it is NOT measured traffic.
 *  - INTERNET SPEED: real throughput to the outside world, measured by
 *    streaming bytes from a speed-test server and pushing bytes back.
 * The connection runs at the smaller of the two. */
const SPEED_TEST_SOURCES = {
  ping: 'https://speed.cloudflare.com/__down?bytes=0',
  down: 'https://speed.cloudflare.com/__down?bytes=95000000',
  up: 'https://speed.cloudflare.com/__up',
  meta: 'https://speed.cloudflare.com/meta',
};
const SPEED_TEST_FALLBACKS = [
  'https://proof.ovh.net/files/100Mb.dat',
];
const DOWNLOAD_MS = Number(process.env.SPEEDTEST_DOWNLOAD_MS || 8000);
const UPLOAD_MS = Number(process.env.SPEEDTEST_UPLOAD_MS || 6000);
const UPLOAD_CHUNK = 256 * 1024;

function speedTestConfig() {
  return {
    ping: process.env.SPEEDTEST_PING_URL || SPEED_TEST_SOURCES.ping,
    down: process.env.SPEEDTEST_DOWN_URL || SPEED_TEST_SOURCES.down,
    up: process.env.SPEEDTEST_UP_URL || SPEED_TEST_SOURCES.up,
    meta: process.env.SPEEDTEST_META_URL || SPEED_TEST_SOURCES.meta,
  };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* Combine two abort signals (Node 18 has no AbortSignal.any). */
function anySignal(a, b) {
  const c = new AbortController();
  const fire = () => c.abort();
  if (a.aborted || b.aborted) c.abort();
  a.addEventListener('abort', fire, { once: true });
  b.addEventListener('abort', fire, { once: true });
  return c.signal;
}

/* Round-trip time to the test server (headers only, connection reused). */
async function measureLatency(url, count = 5) {
  const samples = [];
  for (let i = 0; i < count; i++) {
    const t0 = performance.now();
    try {
      const r = await fetch(url, { cache: 'no-store', signal: AbortSignal.timeout(8000) });
      await r.arrayBuffer().catch(() => {});
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      samples.push(performance.now() - t0);
    } catch { /* skip a failed probe */ }
    await sleep(120);
  }
  if (!samples.length) return null;
  const avg = samples.reduce((a, b) => a + b, 0) / samples.length;
  const variance = samples.length > 1
    ? samples.reduce((a, v) => a + (v - avg) ** 2, 0) / (samples.length - 1)
    : 0;
  return {
    avgMs: Math.round(avg),
    minMs: Math.round(Math.min(...samples)),
    maxMs: Math.round(Math.max(...samples)),
    jitterMs: Math.round(Math.sqrt(variance)),
    samples: samples.map((s) => Math.round(s)),
  };
}

/* Stream bytes for a fixed window, then abort. Returns bits per second. */
async function measureDownload(url, durationMs = DOWNLOAD_MS, onProgress, externalSignal) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), durationMs);
  const signal = externalSignal ? anySignal(controller.signal, externalSignal) : controller.signal;
  const t0 = performance.now();
  let bytes = 0;
  let error = null;
  try {
    const res = await fetch(url, { cache: 'no-store', signal });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const reader = res.body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.length;
      if (onProgress) onProgress(bytes, (performance.now() - t0) / 1000);
    }
  } catch (e) {
    if (!controller.signal.aborted && !(externalSignal && externalSignal.aborted)) error = e;
  } finally {
    clearTimeout(timer);
  }
  const seconds = (performance.now() - t0) / 1000;
  if (!bytes || seconds < 0.2) return { bytes, seconds: Number(seconds.toFixed(2)), bps: 0, error: error ? error.message : 'no data received' };
  return { bytes, seconds: Number(seconds.toFixed(2)), bps: Math.round((bytes * 8) / seconds), error: error ? error.message : null };
}

/* Stream upload data for a fixed window. A fixed-size POST made slow links
 * sit at "70%" for over a minute, so upload is now time-boxed like download. */
async function measureUpload(url, durationMs = UPLOAD_MS, onProgress, externalSignal) {
  const chunk = Buffer.alloc(UPLOAD_CHUNK);
  for (let i = 0; i < chunk.length; i += 4096) chunk[i] = i % 251;

  const controller = new AbortController();
  const signal = externalSignal ? anySignal(controller.signal, externalSignal) : controller.signal;
  const timer = setTimeout(() => {
    windowClosed = true;
    controller.abort();
  }, durationMs + 250);
  const t0 = performance.now();
  let bytes = 0;
  let windowClosed = false;
  let sendError = null;

  const body = new ReadableStream({
    pull(streamController) {
      if (windowClosed || signal.aborted) {
        streamController.close();
        return;
      }
      const seconds = (performance.now() - t0) / 1000;
      if (seconds >= durationMs / 1000) {
        windowClosed = true;
        streamController.close();
        return;
      }
      streamController.enqueue(chunk);
      bytes += chunk.length;
    },
  });
  const ticker = setInterval(() => {
    if (onProgress) onProgress(bytes, (performance.now() - t0) / 1000);
  }, 250);

  try {
    const res = await fetch(url, {
      method: 'POST',
      body,
      duplex: 'half',
      headers: { 'Content-Type': 'application/octet-stream' },
      signal,
    });
    await res.arrayBuffer().catch(() => {});
    if (!res.ok) sendError = `HTTP ${res.status}`;
  } catch (e) {
    if (!windowClosed && !(externalSignal && externalSignal.aborted)) sendError = e.message;
  } finally {
    clearTimeout(timer);
    clearInterval(ticker);
  }

  const seconds = Math.min((performance.now() - t0) / 1000, durationMs / 1000);
  if (!bytes || seconds < 0.2) {
    return { bytes, seconds: Number(seconds.toFixed(2)), bps: 0, error: sendError || 'no data sent' };
  }
  return { bytes, seconds: Number(seconds.toFixed(2)), bps: Math.round((bytes * 8) / seconds), error: sendError };
}

/* Test-server identity (ISP / edge colo) — best effort. */
async function fetchSpeedMeta(url) {
  try {
    const r = await fetch(url, { signal: AbortSignal.timeout(6000) });
    if (!r.ok) return null;
    const j = await r.json();
    return {
      colo: j.colo || null,
      country: j.country || null,
      city: j.city || null,
      asOrganization: j.asOrganization || null,
      asn: j.asn || null,
      clientIp: j.clientIp || null,
    };
  } catch {
    return null;
  }
}

/* Negotiated link rate of the active adapter (wired or wireless). */
let adapterCache = { at: 0, value: null };
function adapterLinkSpeed(ifaceName) {
  if (Date.now() - adapterCache.at < 60000) return adapterCache.value;
  let value = null;
  try {
    if (process.platform === 'win32') {
      const { execFileSync } = require('child_process');
      const out = execFileSync('powershell', [
        '-NoProfile', '-NonInteractive', '-Command',
        "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object Name,InterfaceDescription,LinkSpeed | ConvertTo-Json -Compress",
      ], { timeout: 9000, encoding: 'utf8' });
      const parsed = JSON.parse((out || '').trim() || '[]');
      const rows = Array.isArray(parsed) ? parsed : [parsed];
      const row = rows.find((r) => r && r.Name && ifaceName && String(r.Name).toLowerCase() === String(ifaceName).toLowerCase())
        || rows.find((r) => r && r.Name);
      if (row) {
        const raw = String(row.LinkSpeed || '');
        const g = raw.match(/([\d.]+)\s*Gbps/i);
        const m = raw.match(/([\d.]+)\s*Mbps/i);
        value = { name: row.Name, desc: row.InterfaceDescription || '', raw, linkMbps: g ? Number(g[1]) * 1000 : (m ? Number(m[1]) : null) };
      }
    } else if (process.platform === 'linux' && ifaceName) {
      const raw = fs.readFileSync(`/sys/class/net/${ifaceName}/speed`, 'utf8').trim();
      const v = Number(raw);
      value = { name: ifaceName, desc: '', raw: `${raw} Mb/s`, linkMbps: v > 0 ? v : null };
    }
  } catch { /* adapter rate is best-effort */ }
  adapterCache = { at: Date.now(), value };
  return value;
}

/* Snapshot of the link this machine is on: interface, Wi-Fi radio details
 * and the negotiated link rate. */
async function linkSnapshot() {
  const { iface } = await pickInterface();
  const wifi = getWifiInfo();
  const w = (iface && wifi.find((x) => x.name && x.name.toLowerCase() === String(iface.name).toLowerCase()))
    || wifi[0] || null;
  const adapter = adapterLinkSpeed(iface ? iface.name : null);
  const wifiMbps = w ? (w.rxMbps || w.txMbps || null) : null;
  return {
    interface: iface ? { name: iface.name, ip: iface.ip, cidr: iface.cidr, ssid: iface.ssid || null } : null,
    wifi: w ? {
      ssid: w.ssid || null, bssid: w.bssid || null, signal: w.signal || null,
      band: w.band || null, channel: w.channel || null, radio: w.radio || null,
      rxMbps: w.rxMbps || null, txMbps: w.txMbps || null,
    } : null,
    adapter,
    linkMbps: wifiMbps || (adapter ? adapter.linkMbps : null),
  };
}

/* Speed-test jobs (one at a time per client, polled for progress). */
const speedJobs = new Map();
let speedSeq = 0;

function speedJobPublic(job) {
  return {
    id: job.id, status: job.status, phase: job.phase, progress: job.progress,
    liveBps: job.liveBps, latency: job.latency, download: job.download, upload: job.upload,
    meta: job.meta, link: job.link, gatewayMs: job.gatewayMs, source: job.source || null,
    error: job.error, startedAt: job.startedAt, finishedAt: job.finishedAt,
  };
}

/* Try the primary source, then mirrors, until one actually delivers bytes. */
async function downloadWithFallbacks(job, cfg) {
  const urls = [cfg.down, ...SPEED_TEST_FALLBACKS];
  let last = null;
  for (const url of urls) {
    if (job.cancelled) break;
    const r = await measureDownload(url, DOWNLOAD_MS, (bytes, secs) => {
      job.progress = 0.12 + Math.min(1, secs / (DOWNLOAD_MS / 1000)) * 0.58;
      job.liveBps = Math.round((bytes * 8) / Math.max(1, secs));
      job.source = url;
    }, job.controller.signal);
    if (r && r.bps > 0) { r.source = url; return r; }
    last = r;
  }
  return last;
}

async function runSpeedTest(job) {
  const cfg = speedTestConfig();
  try {
    job.phase = 'latency';
    job.progress = 0.05;
    job.latency = await measureLatency(cfg.ping);
    if (job.cancelled) return;

    job.phase = 'download';
    job.progress = 0.12;
    job.download = await downloadWithFallbacks(job, cfg);
    if (job.cancelled) return;
    job.liveBps = 0;
    job.progress = 0.7;

    job.phase = 'upload';
    job.upload = await measureUpload(cfg.up, UPLOAD_MS, (bytes, secs) => {
      job.progress = 0.7 + Math.min(1, secs / (UPLOAD_MS / 1000)) * 0.18;
      job.liveBps = Math.round((bytes * 8) / Math.max(1, secs));
    }, job.controller.signal);
    if (job.cancelled) return;
    job.liveBps = 0;
    job.progress = 0.9;

    job.phase = 'meta';
    job.progress = 0.93;
    job.meta = await fetchSpeedMeta(cfg.meta);
    job.link = await linkSnapshot();
    if (job.link && job.link.interface) {
      try {
        const { hosts } = parseCidr(job.link.interface.cidr);
        const gateway = hosts[0];
        if (gateway) {
          const p = await pingHost(gateway, 1);
          job.gatewayMs = p.alive ? p.ms : null;
        }
      } catch { /* gateway optional */ }
    }
    job.phase = 'done';
    job.status = 'done';
  } catch (e) {
    job.status = job.cancelled ? 'cancelled' : 'error';
    job.error = e.message;
  } finally {
    if (job.status === 'done') job.progress = 1;
    job.finishedAt = new Date().toISOString();
  }
}

function startSpeedTest() {
  // Keep the map small: finished jobs stay pollable for a few minutes.
  const cutoff = Date.now() - 10 * 60 * 1000;
  for (const [id, j] of speedJobs) if (j.finishedAt && new Date(j.finishedAt).getTime() < cutoff) speedJobs.delete(id);
  const id = `speed-${Date.now().toString(36)}-${(speedSeq++).toString(36)}`;
  const job = {
    id, status: 'running', phase: 'starting', progress: 0, liveBps: 0,
    latency: null, download: null, upload: null, meta: null, link: null, gatewayMs: null,
    source: null, error: null, cancelled: false, controller: new AbortController(),
    startedAt: new Date().toISOString(), finishedAt: null,
  };
  speedJobs.set(id, job);
  runSpeedTest(job);
  return job;
}

/* Full IEEE OUI registry (generated from standards-oui.ieee.org/oui/oui.txt
 * into oui.json: { "aa:bb:cc": "Vendor Name" }). Falls back to a small
 * built-in map if oui.json is missing. */
let OUI = null;
try {
  OUI = JSON.parse(fs.readFileSync(path.join(__dirname, 'oui.json'), 'utf8'));
} catch {
  OUI = {
    '3c:22:fb': 'Apple', '00:1b:63': 'Apple', 'dc:a6:32': 'Raspberry Pi',
    'b8:27:eb': 'Raspberry Pi', '14:5a:fc': 'Espressif',
  };
}

/* Friendly short names for registry entries that are verbose or trade names. */
const VENDOR_ALIASES = {
  'samsung electronics': 'Samsung',
  'lg electronics': 'LG',
  'xiaomi communications': 'Xiaomi',
  'tp-link systems': 'TP-Link',
  'raspberry pi trading': 'Raspberry Pi',
  'raspberry pi foundation': 'Raspberry Pi',
  'intel corporate': 'Intel',
  'hewlett packard': 'HP',
  'hp inc': 'HP',
  'azurewave technology': 'AzureWave',
  'liteon technology': 'Lite-On',
  'hon hai precision': 'Foxconn',
  'hon hai precision ind': 'Foxconn',
  'realme chongqing': 'Realme',
  'cybertan technology': 'CyberTAN',
};

/* Heuristic device-type detection (Fing-style icons), from hostname first,
 * then vendor. Returns a stable type key; the client maps it to icon+label. */
function inferType(vendor, hostname) {
  const h = String(hostname || '').toLowerCase();
  const v = String(vendor || '').toLowerCase();
  const has = (...keys) => keys.some((k) => h.includes(k) || v.includes(k));

  if (/iphone|ipad|pixel|galaxy|android|oneplus|redmi|poco|oppo|vivo|realme|nokia|motorola|huawei|honor|nothing phone|fairphone/.test(h))
    return h.includes('ipad') || h.includes('tablet') ? 'tablet' : 'phone';
  if (/macbook|thinkpad|dell|lenovo|latitude|desktop|laptop|\bpc\b|workstation|surface|imac|mac-mini|nuc/.test(h)) return 'computer';
  if (/tv|bravia|roku|chromecast|firetv|fire-tv|apple-tv|appletv|shield|miracast|smart-tv/.test(h)) return 'tv';
  if (/echo|alexa|sonos|homepod|nest audio|nest mini|speaker|soundbar|home-pod/.test(h)) return 'speaker';
  if (/cam|camera|doorbell|dvr|nvr|door-bell|ring-/.test(h) && !h.includes('cambridge')) return 'camera';
  if (/print|laserjet|officejet|deskjet|canon|epson|brother/.test(h)) return 'printer';
  if (/playstation|ps5|ps4|xbox|nintendo|switch-/.test(h)) return 'console';
  if (/router|gateway|unifi|deco|velop|orbi|eero|fritz|openwrt|mikrotik|edgerouter/.test(h)) return 'router';

  if (has('samsung', 'xiaomi', 'oneplus', 'oppo', 'vivo', 'realme', 'motorola', 'huawei', 'honor', 'nothing', 'fairphone', 'nokia', 'tecno', 'infinix')) return 'phone';
  if (has('dell', 'hewlett', 'lenovo', 'acer', 'asus', 'intel', 'microsoft', 'lite-on', 'gigabyte', 'msi', 'apple')) return 'computer';
  if (has('sonos', 'bose', 'harman', 'jbl', 'denon', 'marantz', 'yamaha')) return 'speaker';
  if (has('dahua', 'hikvision', 'axis communications', 'hanwha', 'reolink', 'amcrest', 'foscam', 'wyze')) return 'camera';
  if (has('canon', 'epson', 'brother', 'xerox', 'lexmark', 'kyocera', 'ricoh')) return 'printer';
  if (has('nintendo', 'sony interactive', 'playstation', 'xbox')) return 'console';
  if (has('sony', 'lg', 'tcl', 'vizio', 'hisense', 'philips', 'panasonic', 'sharp', 'roku')) return 'tv';
  if (has('amazon')) return 'speaker';
  if (has('google')) return has('nest') ? 'speaker' : 'phone';
  if (has('espressif', 'arduino', 'particle', 'shelly', 'tuya', 'smart life')) return 'iot';
  if (has('raspberry', 'orange pi', 'banana pi', 'odroid', 'beagle')) return 'iot';
  if (has('cisco', 'netgear', 'ubiquiti', 'linksys', 'd-link', 'tenda', 'tp-link', 'juniper', 'arista', 'ruckus', 'aruba', 'zyxel', 'hpe', 'extreme networks', 'cybertan')) return 'router';
  if (has('ring', 'ecobee', 'honeywell', 'philips hue', 'ikea')) return 'iot';
  if (has('wemo', 'kasa', 'meross', 'eufy', 'arlo', 'blink')) return 'iot';
  return 'unknown';
}

// ---------- helpers ----------
function ensureDataDir() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

function numOrNull(v) {
  const n = Number(v);
  return v === null || v === undefined || v === '' || Number.isNaN(n) ? null : n;
}

function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return fallback;
  }
}

function writeJson(file, obj) {
  ensureDataDir();
  fs.writeFileSync(file, JSON.stringify(obj, null, 2));
}

ensureDataDir();

/* Local file storage stats: everything lives in server/data/*.json,
 * pruned to RETENTION_DAYS. No database server needed. */
async function storageStats() {
  const devices = readJson(DEVICES_FILE, {});
  const history = readJson(HISTORY_FILE, []);
  const notes = readJson(NOTES_FILE, {});
  const trusted = readJson(TRUSTED_FILE, {});
  const at = (e) => new Date(e.lastSeen || e.finishedAt || e.startedAt || 0).getTime();
  const oldest = [...Object.values(devices), ...history]
    .map(at).filter(Boolean).sort((a, b) => a - b)[0] || null;
  return {
    provider: 'local-json',
    dataDir: 'server/data',
    retentionDays: RETENTION_DAYS,
    devices: Object.keys(devices).length,
    online: Object.values(devices).filter((d) => d.online).length,
    scanHistory: history.length,
    deviceSightings: Object.values(devices).reduce((n, d) => n + (d.sightings || 0), 0),
    notes: Object.keys(notes).length,
    trusted: Object.keys(trusted).length,
    oldestRecord: oldest ? new Date(oldest).toISOString() : null,
    sqlite: cloneStore.stats(),
  };
}

function pruneJsonRetention() {
  const cutoff = Date.now() - RETENTION_DAYS * 24 * 3600 * 1000;
  const inventory = readJson(DEVICES_FILE, {});
  const freshInventory = Object.fromEntries(Object.entries(inventory).filter(([, device]) => {
    const seen = new Date(device.lastSeen || 0).getTime();
    return !seen || seen >= cutoff;
  }));
  if (Object.keys(freshInventory).length !== Object.keys(inventory).length) writeJson(DEVICES_FILE, freshInventory);
  const history = readJson(HISTORY_FILE, []);
  const freshHistory = history.filter((entry) => {
    const at = new Date(entry.finishedAt || entry.startedAt || 0).getTime();
    return !at || at >= cutoff;
  });
  if (freshHistory.length !== history.length) writeJson(HISTORY_FILE, freshHistory);
}

pruneJsonRetention();

function maskToPrefix(mask) {
  if (/^\d+$/.test(String(mask))) return Number(mask);
  const parts = String(mask).split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return 24;
  const bits = parts.map((n) => n.toString(2).padStart(8, '0')).join('');
  const m = bits.match(/^1*/)[0].length;
  return m;
}

function ipToInt(ip) {
  const p = ip.split('.').map(Number);
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}

function intToIp(n) {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

function parseCidr(cidr) {
  const m = String(cidr).trim().match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
  if (!m) throw new Error(`Invalid CIDR: ${cidr} (expected like 192.168.1.0/24)`);
  const octets = m[1].split('.').map(Number);
  if (octets.some((n) => n < 0 || n > 255)) throw new Error(`Invalid CIDR: ${cidr}`);
  const prefix = Number(m[2]);
  if (prefix < 16 || prefix > 30) throw new Error('Prefix must be /16–/30 (larger ranges need narrowing)');
  const ipInt = ipToInt(m[1]);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const networkInt = (ipInt & mask) >>> 0;
  const broadcastInt = (networkInt | (~mask >>> 0)) >>> 0;
  const hosts = [];
  for (let n = networkInt + 1; n < broadcastInt && hosts.length < 8192; n++) hosts.push(intToIp(n));
  return { network: `${intToIp(networkInt)}/${prefix}`, hosts };
}

function normalizeMac(raw) {
  const cleaned = String(raw).trim().toLowerCase().replace(/-/g, ':');
  return /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(cleaned) ? cleaned : null;
}

async function getArpTable() {
  try {
    const { stdout } = await execFileAsync('arp', ['-a'], { timeout: 10000 });
    const table = {};
    const re = /(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:-]{17})/g;
    let m;
    while ((m = re.exec(stdout))) {
      const mac = normalizeMac(m[2]);
      if (mac && mac !== 'ff:ff:ff:ff:ff:ff') table[m[1]] = mac;
    }
    return table;
  } catch {
    return {};
  }
}

function getInterfaces() {
  const out = [];
  const all = os.networkInterfaces();
  const wifi = getWifiInfo();
  const wifiByName = {};
  for (const w of wifi) wifiByName[w.name.toLowerCase()] = w;
  for (const [name, addrs] of Object.entries(all)) {
    for (const a of addrs || []) {
      if (a.family !== 'IPv4' || a.internal) continue;
      if (a.address.startsWith('169.254.')) continue;
      const prefix = maskToPrefix(a.netmask);
      if (prefix >= 31) continue; // VPN/WARP point-to-point, not a LAN
      try {
        const { network } = parseCidr(`${a.address}/${prefix}`);
        const w = wifiByName[name.toLowerCase()];
        out.push({
          name, ip: a.address, cidr: network, prefix,
          // Windows hotspot ("Local Area Connection* N", 192.168.137.x) is its
          // own NAT subnet: scanning it shows ONLY hotspot clients.
          hotspot: /local area connection/i.test(name) || a.address.startsWith('192.168.137.'),
          ssid: w ? w.ssid : null,
        });
      } catch {
        /* skip unusable */
      }
    }
  }
  return out;
}

/* Which access point YOU are connected to (SSID/BSSID/signal). Best-effort
 * per OS; returns [] when unavailable. Note this only describes your own
 * connection — clients cannot see which AP *other* devices use when all APs
 * share one subnet, so per-AP device lists are impossible without
 * controller access (true for Fing too).
 * rxMbps/txMbps are the PHY rates negotiated with the AP (e.g. 866 on
 * 802.11ac) — the ceiling for the wireless hop, not measured throughput. */
function getWifiInfo() {
  try {
    if (process.platform === 'win32') {
      const { execFileSync } = require('child_process');
      const out = execFileSync('netsh', ['wlan', 'show', 'interfaces'], { timeout: 8000, encoding: 'utf8' });
      const blocks = out.split(/^\s*Name\s*:/m).slice(1);
      return blocks.map((b) => {
        const get = (re) => { const m = b.match(re); return m ? m[1].trim() : null; };
        const state = get(/^\s*State\s*:\s*(.+)$/m);
        if (!state || !/connect/i.test(state)) return null;
        return {
          name: get(/^\s*(.+)$/m) || '',
          ssid: get(/^\s*SSID\s*:\s*(.+)$/m),
          bssid: get(/^\s*(?:AP\s*)?BSSID\s*:\s*(.+)$/m),
          signal: get(/^\s*Signal\s*:\s*(.+)$/m),
          band: get(/^\s*Band\s*:\s*(.+)$/m),
          channel: get(/^\s*Channel\s*:\s*(.+)$/m),
          radio: get(/^\s*Radio type\s*:\s*(.+)$/m),
          rxMbps: numOrNull(get(/^\s*Receive rate \(Mbps\)\s*:\s*([\d.]+)/m)),
          txMbps: numOrNull(get(/^\s*Transmit rate \(Mbps\)\s*:\s*([\d.]+)/m)),
        };
      }).filter(Boolean);
    }
    if (process.platform === 'darwin') {
      const { execFileSync } = require('child_process');
      const out = execFileSync(
        '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport',
        ['-I'], { timeout: 8000, encoding: 'utf8' });
      const get = (re) => { const m = out.match(re); return m ? m[1].trim() : null; };
      const ssid = get(/^\s*SSID:\s*(.+)$/m);
      if (!ssid) return [];
      return [{
        name: 'Wi-Fi', ssid, bssid: get(/^\s*BSSID:\s*(.+)$/m), signal: get(/^\s*agrCtlRSSI:\s*(.+)$/m),
        band: null, channel: get(/^\s*channel:\s*(.+)$/m),
        radio: null,
        rxMbps: numOrNull(get(/^\s*maxRate\s*:\s*([\d.]+)/m)),
        txMbps: numOrNull(get(/^\s*lastTxRate\s*:\s*([\d.]+)/m)),
      }];
    }
    // linux: NetworkManager if present
    const { execFileSync } = require('child_process');
    const out = execFileSync('nmcli', ['-t', '-f', 'NAME,TYPE,DEVICE', 'connection', 'show', '--active'], { timeout: 8000, encoding: 'utf8' });
    const wifi = [];
    for (const line of out.split('\n')) {
      const [name, type, device] = line.split(':');
      if (type && type.includes('wireless') && device) {
        let ssid = name, bssid = null, signal = null, rate = null;
        try {
          const d = execFileSync('nmcli', ['-t', '-f', 'ACTIVE,SSID,BSSID,SIGNAL,RATE', 'device', 'wifi', 'list', 'ifname', device], { timeout: 8000, encoding: 'utf8' });
          const row = d.split('\n').find((l) => l.startsWith('yes:'));
          if (row) { const parts = row.split(':'); ssid = parts[1] || ssid; bssid = parts[2] || null; signal = parts[3] ? `${parts[3]}%` : null; rate = numOrNull((parts[4] || '').match(/([\d.]+)/)?.[1]); }
        } catch { /* keep basic info */ }
        wifi.push({ name: device, ssid, bssid, signal, band: null, channel: null, radio: null, rxMbps: rate, txMbps: rate });
      }
    }
    return wifi;
  } catch {
    return [];
  }
}

function pingArgs(ip, timeoutS) {
  if (process.platform === 'win32') return ['-n', '1', '-w', String(Math.round(timeoutS * 1000)), ip];
  if (process.platform === 'darwin') return ['-c', '1', '-t', String(Math.max(1, Math.round(timeoutS))), ip];
  return ['-c', '1', '-W', String(Math.max(1, Math.round(timeoutS))), ip];
}

function pingHost(ip, timeoutS) {
  return new Promise((resolve) => {
    const start = Date.now();
    const child = execFile('ping', pingArgs(ip, timeoutS), { timeout: (timeoutS + 3) * 1000 }, (err, stdout) => {
      const ms = Date.now() - start;
      const ttl = err ? null : osFp.parseTtl(stdout);
      resolve({ ip, alive: !err, ms: !err ? ms : null, ttl });
    });
    child.on('error', () => resolve({ ip, alive: false, ms: null, ttl: null }));
  });
}

async function mapLimit(items, limit, fn, onItem) {
  const results = new Array(items.length);
  let next = 0;
  async function worker() {
    while (next < items.length) {
      const i = next++;
      try {
        results[i] = await fn(items[i], i);
      } catch {
        results[i] = null;
      }
      if (onItem) onItem(i, results[i]);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

function reverseLookup(ip, timeoutMs = 1500) {
  return Promise.race([
    dns.reverse(ip).then((names) => (names && names[0]) || '').catch(() => ''),
    new Promise((res) => setTimeout(() => res(''), timeoutMs)),
  ]);
}

function lookupVendor(mac) {
  const norm = normalizeMac(mac || '');
  if (!norm) return { mac: mac || '', vendor: 'Unknown', oui: '' };
  const oui = norm.slice(0, 8);
  const raw = OUI[oui];
  if (!raw) return { mac: norm, vendor: 'Unknown', oui };
  return { mac: norm, vendor: VENDOR_ALIASES[raw.toLowerCase()] || raw, oui };
}

function checkPort(ip, port, timeoutMs) {
  return new Promise((resolve) => {
    const start = Date.now();
    const sock = new net.Socket();
    let done = false;
    const finish = (open) => {
      if (done) return;
      done = true;
      sock.destroy();
      resolve({ port, open, ms: open ? Date.now() - start : null });
    };
    sock.setTimeout(timeoutMs);
    sock.once('connect', () => finish(true));
    sock.once('timeout', () => finish(false));
    sock.once('error', () => finish(false));
    sock.connect(port, ip);
  });
}

// ---------- scan jobs ----------
const jobs = new Map();
let seq = 0;

function jobPublic(job) {
  const { clients, ...rest } = job;
  return rest;
}

function broadcast(job) {
  const payload = `data: ${JSON.stringify(jobPublic(job))}\n\n`;
  for (const res of job.clients) {
    try {
      res.write(payload);
    } catch {
      /* client gone */
    }
  }
}

function appendHistory(entry) {
  const h = readJson(HISTORY_FILE, []);
  h.unshift(entry);
  writeJson(HISTORY_FILE, h.slice(0, 50));
}

/* This AP's BSSID, cached for 5 min: tags every observation with a
 * network-location signal, so the detector can tell "same MAC, two APs". */
let bssidCache = { at: 0, bssid: '' };
function currentBssid() {
  if (Date.now() - bssidCache.at < 5 * 60 * 1000) return bssidCache.bssid;
  try {
    const bssid = (getWifiInfo().find((w) => w.bssid) || {}).bssid || '';
    bssidCache = { at: Date.now(), bssid };
  } catch {
    /* wifi info is best-effort */
  }
  return bssidCache.bssid;
}

/* Persistent device inventory: every scan merges into devices.json with
 * firstSeen/lastSeen/online, so the client can show offline devices,
 * "NEW" badges, and a stable list across scans. Every merge also appends
 * MAC<->IP sightings to SQLite for the clone detector's correlation. */
function mergeInventory(rows, { network = null, full = false } = {}) {
  const now = new Date().toISOString();
  const inv = readJson(DEVICES_FILE, {});
  const cutoff = Date.now() - RETENTION_DAYS * 24 * 3600 * 1000;
  for (const [ip, device] of Object.entries(inv)) {
    if (device.lastSeen && new Date(device.lastSeen).getTime() < cutoff) delete inv[ip];
  }
  const seen = new Set();
  let newCount = 0;
  for (const r of rows) {
    seen.add(r.ip);
    const prev = inv[r.ip];
    if (!prev) newCount++;
    const mac = r.mac || (prev && prev.mac) || '';
    // Hardware-address history: if an IP's MAC changes, something hijacked
    // it (or DHCP moved). Kept to last 3 for the watchdog.
    let prevMacs = (prev && prev.macHistory) || [];
    let macChangedAt = (prev && prev.macChangedAt) || null;
    if (prev && prev.mac && mac && prev.mac !== mac) {
      prevMacs = [...prevMacs.filter((m) => m !== prev.mac), prev.mac].slice(-3);
      macChangedAt = now;
    }
    inv[r.ip] = {
      ip: r.ip,
      mac,
      hostname: r.hostname || (prev && prev.hostname) || '',
      vendor: (r.vendor && r.vendor !== 'Unknown' ? r.vendor : (prev && prev.vendor)) || 'Unknown',
      type: r.type && r.type !== 'unknown' ? r.type : (prev && prev.type) || 'unknown',
      services: r.services && r.services.length ? r.services : (prev && prev.services) || [],
      fp: (r.fp && (r.fp.model || ((r.fp.evidence || []).length))) ? r.fp : (prev && prev.fp) || null,
      upnp: r.upnp && (r.upnp.friendlyName || r.upnp.modelName) ? r.upnp : (prev && prev.upnp) || null,
      mdns: r.mdns && r.mdns.name ? r.mdns : (prev && prev.mdns) || null,
      nbname: r.nbname || (prev && prev.nbname) || '',
      os: (r.os && r.os.name) ? r.os : (prev && prev.os) || null,
      source: r.source,
      firstSeen: (prev && prev.firstSeen) || now,
      lastSeen: now,
      sightings: ((prev && prev.sightings) || 0) + 1,
      macHistory: prevMacs,
      macChangedAt,
      online: true,
    };
    r.isNew = !prev;
    r.firstSeen = inv[r.ip].firstSeen;
    r.lastSeen = now;
    r.online = true;
    if (!prev && watch.on) {
      watch.newSince.push({ ip: r.ip, mac: inv[r.ip].mac, vendor: inv[r.ip].vendor, at: now });
      if (watch.newSince.length > 50) watch.newSince = watch.newSince.slice(-50);
    }
  }
  if (full && network) {
    try {
      const set = new Set(parseCidr(network).hosts);
      for (const [ip, e] of Object.entries(inv)) {
        if (set.has(ip) && !seen.has(ip)) e.online = false;
      }
    } catch { /* bad network: skip offline marking */ }
  }
  writeJson(DEVICES_FILE, inv);
  try {
    cloneStore.record(rows.filter((r) => r.mac && r.ip), { bssid: currentBssid(), retentionDays: RETENTION_DAYS });
  } catch {
    /* observation logging must never break a scan */
  }
  return { newCount, total: Object.keys(inv).length };
}

/* ---------- watchdog: clone / hijack / stranger detection ----------
 * Works without privileges from ARP + behavior data already collected:
 *  - duplicate MAC on 2+ online IPs  -> clone (CRITICAL)
 *  - one IP cycling hardware addresses -> hijack/DHCP move (CRITICAL)
 *  - one MAC, 2+ hostnames ever       -> identity flip (WARN)
 *  - trusted MAC appearing elsewhere  -> clone of YOUR device (CRITICAL)
 * Packet-TTL OS-fingerprinting would need raw sockets (admin) — the
 * equivalent here is behavioral: ports/services/fingerprints per MAC.
 * Pure function of (inventory, trusted) for testability. */
function analyzeThreats(inv, trusted = {}) {
  const now = new Date().toISOString();
  const threats = [];
  const byMac = {};
  // Locally-administered bit set => randomized privacy address (iOS/Android
  // rotate these), NOT a burned-in factory MAC.
  const randomized = (m) => { const c = String(m || '').charAt(1).toLowerCase(); return c !== '' && '2367abef'.includes(c); };
  for (const d of Object.values(inv)) {
    if (!d.mac) continue;
    (byMac[d.mac] = byMac[d.mac] || []).push(d);
  }
  const tnorm = {};
  for (const [m, t] of Object.entries(trusted)) tnorm[m.toLowerCase()] = t;

  for (const [mac, ds] of Object.entries(byMac)) {
    const online = ds.filter((d) => d.online);
    if (online.length > 1) {
      const sorted = [...online].sort((a, b) => new Date(a.firstSeen || 0) - new Date(b.firstSeen || 0));
      const suspect = sorted[sorted.length - 1];
      threats.push({
        id: `dup:${mac}`, sev: 'critical', kind: 'duplicate-mac', mac, at: now,
        title: `Possible MAC clone: ${mac} live on ${online.length} IPs`,
        desc: `Newest arrival ${suspect.ip}${suspect.hostname ? ` (${suspect.hostname})` : ''} is the likely impostor.`,
        holders: online.map((d) => ({ ip: d.ip, hostname: d.hostname || '', vendor: d.vendor || 'Unknown', firstSeen: d.firstSeen || null, suspect: d.ip === suspect.ip })),
      });
    }
    const names = [...new Set(ds.map((d) => d.hostname).filter(Boolean))];
    if (names.length > 1) {
      threats.push({
        id: `flip:${mac}`, sev: 'warn', kind: 'identity-flip', mac,
        title: `One MAC, ${names.length} identities: ${mac}`,
        desc: `Seen as ${names.slice(0, 4).join(', ')} — renamed device or spoofed NIC.`,
        holders: ds.map((d) => ({ ip: d.ip, hostname: d.hostname || '', vendor: d.vendor || 'Unknown', firstSeen: d.firstSeen || null })),
        at: now,
      });
    }
    const t = tnorm[mac.toLowerCase()];
    if (t) {
      const elsewhere = online.filter((d) => t.ip && d.ip !== t.ip);
      if (t.ip && elsewhere.length) {
        threats.push({
          id: `trusted:${mac}`, sev: 'critical', kind: 'trusted-clone', mac,
          title: `Your device "${t.name || mac}" is being cloned`,
          desc: `Trusted on ${t.ip}, but also live on ${elsewhere.map((d) => d.ip).join(', ')}.`,
          holders: elsewhere.map((d) => ({ ip: d.ip, hostname: d.hostname || '', vendor: d.vendor || 'Unknown', firstSeen: d.firstSeen || null, suspect: true })),
          at: now,
        });
      }
    }
  }
  for (const d of Object.values(inv)) {
    if (d.mac && (d.macHistory || []).length) {
      // Privacy rotation (either side randomized) is benign phone behavior —
      // only burned-in -> burned-in changes are hijack suspects.
      const privacy = randomized(d.mac) || (d.macHistory || []).some(randomized);
      threats.push({
        id: `ipflip:${d.ip}`,
        sev: privacy ? 'info' : 'critical',
        kind: privacy ? 'mac-rotation' : 'ip-hijack',
        mac: d.mac,
        title: privacy
          ? `${d.ip} rotated its MAC address (privacy address)`
          : `${d.ip} changed hardware address`,
        desc: privacy
          ? `Was ${(d.macHistory || []).join(', ')} — now ${d.mac}. Matches iOS/Android private-address rotation: almost certainly the same device, not a hijack.`
          : `Was ${(d.macHistory || []).join(', ')} — now ${d.mac}. Possible hijack or DHCP reassignment.`,
        holders: [{ ip: d.ip, hostname: d.hostname || '', vendor: d.vendor || 'Unknown', firstSeen: d.firstSeen || null }],
        at: d.macChangedAt || now,
      });
    }
  }
  const order = { critical: 0, warn: 1, info: 2 };
  threats.sort((a, b) => order[a.sev] - order[b.sev]);
  return threats;
}

/* Connection stability probe: repeated pings expose contention flapping
 * (two NICs fighting over one slot show violent loss/jitter). */
async function stabilityCheck(ip, count = 6, timeoutS = 1) {
  const samples = [];
  for (let i = 0; i < Math.min(20, Math.max(1, count)); i++) {
    const t0 = Date.now();
    try {
      const r = await pingHost(ip, timeoutS);
      samples.push(r.alive ? Date.now() - t0 : null);
    } catch { samples.push(null); }
  }
  const ok = samples.filter((s) => s !== null);
  const lossPct = Math.round((1 - ok.length / samples.length) * 100);
  const jitter = ok.length > 1
    ? Math.round(ok.slice(1).reduce((a, v, i) => a + Math.abs(v - ok[i]), 0) / (ok.length - 1))
    : 0;
  return {
    ip, sent: samples.length, received: ok.length, lossPct,
    minMs: ok.length ? Math.min(...ok) : null,
    avgMs: ok.length ? Math.round(ok.reduce((a, b) => a + b, 0) / ok.length) : null,
    maxMs: ok.length ? Math.max(...ok) : null,
    jitterMs: jitter,
    unstable: lossPct >= 30 || jitter > 150,
  };
}

/* ---------- background watch (mini-IDS) ----------
 * Watches the ARP cache on a timer and merges sightings into the inventory.
 * Anything first-seen while watching lands in watch.newSince, which the
 * client polls to raise instant in-app + browser-notification alerts.
 * No extra deps (no socket.io): same effect over plain polling. */
const watch = { on: false, timer: null, intervalSec: 15, lastCheck: null, newSince: [] };

function watchState() {
  return { watching: watch.on, intervalSec: watch.intervalSec, lastCheck: watch.lastCheck, newSince: watch.newSince.slice(-50) };
}

async function watchTick() {
  const table = await getArpTable();
  const rows = Object.entries(table).map(([ip, mac]) => {
    const vendor = lookupVendor(mac).vendor;
    return { ip, mac, hostname: '', vendor, type: inferType(vendor, ''), source: 'arp' };
  });
  mergeInventory(rows, { full: false });
  watch.lastCheck = new Date().toISOString();
  return watchState();
}

function startWatch(intervalSec = 15) {
  stopWatch();
  watch.on = true;
  watch.intervalSec = Math.min(120, Math.max(5, Number(intervalSec) || 15));
  watch.newSince = [];
  watch.lastCheck = null;
  watchTick().catch(() => {});
  watch.timer = setInterval(() => watchTick().catch(() => {}), watch.intervalSec * 1000);
  if (watch.timer.unref) watch.timer.unref();
  return watchState();
}

function stopWatch() {
  watch.on = false;
  if (watch.timer) clearInterval(watch.timer);
  watch.timer = null;
  return watchState();
}

/* Best LAN interface by ARP overlap (shared with /api/interfaces logic). */
async function pickInterface() {
  const ifaces = getInterfaces();
  if (!ifaces.length) return { iface: null, arp: {} };
  const arp = await getArpTable();
  const ips = Object.keys(arp);
  let best = ifaces[0];
  let bestScore = -1;
  for (const i of ifaces) {
    let score = 0;
    try {
      const set = new Set(parseCidr(i.cidr).hosts);
      score = ips.filter((ip) => set.has(ip)).length;
    } catch { score = 0; }
    if (score > bestScore) { best = i; bestScore = score; }
  }
  return { iface: best, arp };
}

async function runScan(job, opts) {
  const { timeout, workers, arpOnly, resolveNames, serviceScan } = opts;
  try {
    const arpFirst = await getArpTable();
    if (arpOnly) {
      const ips = Object.keys(arpFirst).sort((a, b) => ipToInt(a) - ipToInt(b));
      const names = resolveNames
        ? Object.fromEntries(await mapLimit(ips, 32, async (ip) => [ip, await reverseLookup(ip)]))
        : {};
      let mdnsMap = {};
      let nbMap = {};
      try {
        job.note = `Probing device names (mDNS/NetBIOS)…`;
        broadcast(job);
        const mdns = await nameDisc.sweepMdns(2000);
        mdnsMap = Object.fromEntries(mdns.map((m) => [m.ip, m]));
      } catch { /* names are best-effort */ }
      try {
        const nb = await nameDisc.sweepNetbios(ips, 350, 48);
        nbMap = Object.fromEntries(nb.map((n) => [n.ip, n.name]));
      } catch { /* names are best-effort */ }
      job.rows = ips.map((ip) => {
        const vendor = lookupVendor(arpFirst[ip]).vendor;
        const hostname = names[ip] || mdnsMap[ip]?.hostname || mdnsMap[ip]?.name || nbMap[ip] || '';
        const mdns = mdnsMap[ip] ? { name: mdnsMap[ip].name, services: mdnsMap[ip].services || [], model: mdnsMap[ip].model || '' } : null;
        const nbname = nbMap[ip] || '';
        const os = osFp.classifyOs({ vendor, hostname, mdnsName: mdns?.name, nbname });
        return { ip, mac: arpFirst[ip], hostname, vendor, type: inferType(vendor, hostname), mdns, nbname, os, source: 'arp' };
      });
      job.status = 'done';
      job.done = ips.length;
      job.total = ips.length;
      job.finishedAt = new Date().toISOString();
      mergeInventory(job.rows, { full: false });
      appendHistory({ id: job.id, cidr: job.cidr, total: ips.length, found: ips.length, arpOnly: true, startedAt: job.startedAt, finishedAt: job.finishedAt });
      broadcast(job);
      return;
    }

    const { network, hosts } = parseCidr(job.cidr);
    job.network = network;
    job.total = hosts.length;
    broadcast(job);

    const alive = [];
    const ttlByIp = new Map();
    await mapLimit(hosts, workers, (h) => pingHost(h, timeout), (_i, r) => {
      job.done += 1;
      if (r && r.alive) {
        alive.push(r.ip);
        if (r.ttl) ttlByIp.set(r.ip, r.ttl);
        job.aliveCount = alive.length;
      }
      if (job.done % 10 === 0 || job.done === job.total) broadcast(job);
    });

    if (job.cancelled) {
      job.status = 'cancelled';
      job.finishedAt = new Date().toISOString();
      broadcast(job);
      return;
    }

    const arpFresh = await getArpTable();
    let arp = arpFresh;
    alive.sort((a, b) => ipToInt(a) - ipToInt(b));
    // Second chance for missing MACs: ping races ARP-cache population, so
    // re-ping the stragglers once and re-read the cache before giving up.
    const missing = alive.filter((ip) => !arp[ip]);
    if (missing.length) {
      job.note = `Resolving ${missing.length} missing MAC address${missing.length === 1 ? '' : 'es'}…`;
      broadcast(job);
      await mapLimit(missing, 64, (h) => pingHost(h, Math.min(timeout, 1)));
      arp = { ...arp, ...(await getArpTable()) };
    }
    const names = resolveNames
      ? Object.fromEntries(await mapLimit(alive, 32, async (ip) => [ip, await reverseLookup(ip)]))
      : {};
    if (serviceScan && alive.length) {
      job.note = `Identifying services on ${alive.length} devices…`;
      broadcast(job);
    }
    job.rows = await mapLimit(alive, 32, async (ip) => {      const vendor = arp[ip] ? lookupVendor(arp[ip]).vendor : 'Unknown';
      const hostname = names[ip] || '';
      const services = serviceScan ? await scanServices(ip) : [];
      return {
        ip, mac: arp[ip] || '', hostname, vendor, services,
        type: refineType(inferType(vendor, hostname), services), source: 'ping',
      };
    });
    job.rows.sort((a, b) => ipToInt(a.ip) - ipToInt(b.ip));

    /* Fingerprint pass: one SSDP sweep for the whole subnet + HTTP/TLS
     * probes only on hosts with web ports (or UPnP announcements). */
    const fpCtx = {};
    if (serviceScan && job.rows.length) {
      job.note = `Fingerprinting ${job.rows.length} devices…`;
      broadcast(job);
      let ssdp = [];
      try { ssdp = await ssdpSweep(2500); } catch { ssdp = []; }
      const urls = [...new Set(ssdp.filter((s) => s.location).map((s) => s.location))].slice(0, 15);
      const descByUrl = Object.fromEntries(
        await mapLimit(urls, 5, async (u) => [u, await fetchUpnpDesc(u)]));
      for (const r of job.rows) {
        try {
          const hit = ssdp.find((s) => s.ip === r.ip) || {};
          const upnp = { ...hit, ...((hit.location && descByUrl[hit.location]) || {}) };
          const ports = new Set((r.services || []).map((s) => s.port));
          const interesting = ports.has(80) || ports.has(8080) || ports.has(8443) || ports.has(443)
            || upnp.location || upnp.server;
          let fp = { http: { server: '', title: '', realm: '' }, cert: { subject: '', issuer: '' }, upnp };
          if (interesting) {
            const probed = await fingerprintIp(r.ip, { vendor: r.vendor, hostname: r.hostname, services: r.services, upnp });
            fp = { http: probed.http, cert: probed.cert, upnp };
          }
          const verdict = identifyDevice({ ip: r.ip, vendor: r.vendor, hostname: r.hostname, services: r.services, ...fp });
          r.fp = { model: verdict.model, kind: verdict.kind, confidence: verdict.confidence, evidence: verdict.evidence };
          if (verdict.kind) r.type = verdict.kind;
          r.upnp = upnp && (upnp.friendlyName || upnp.modelName || upnp.modelDescription) ? {
            friendlyName: upnp.friendlyName || '',
            modelName: upnp.modelName || '',
            modelDescription: upnp.modelDescription || '',
            manufacturer: upnp.manufacturer || '',
            location: upnp.location || '',
            server: upnp.server || '',
          } : null;
          fpCtx[r.ip] = { http: fp.http, upnp };
        } catch { /* one host must not break the scan */ }
      }
    }

    /* OS pass: TTL is free (already in the ping stage); SSH/SMB banners are
     * only attempted on hosts that actually expose those ports. SNMP stays
     * on-demand in Identify so a normal scan never becomes an SNMP sweep. */
    if (job.rows.length) {
      job.note = `Detecting operating systems on ${job.rows.length} devices…`;
      broadcast(job);
      await mapLimit(job.rows, 24, async (r) => {
        try {
          const ctx = fpCtx[r.ip] || {};
          const base = {
            ttl: ttlByIp.get(r.ip) || null,
            vendor: r.vendor,
            hostname: r.hostname,
            services: r.services || [],
            http: ctx.http || {},
            upnp: ctx.upnp || {},
            mdnsName: r.mdns?.name || '',
            nbname: r.nbname || '',
          };
          if (ctx.upnp && (ctx.upnp.friendlyName || ctx.upnp.modelName)) {
            r.upnp = {
              friendlyName: ctx.upnp.friendlyName || '',
              modelName: ctx.upnp.modelName || '',
              modelDescription: ctx.upnp.modelDescription || '',
              manufacturer: ctx.upnp.manufacturer || '',
              location: ctx.upnp.location || '',
              server: ctx.upnp.server || '',
            };
          }
          const os = serviceScan ? await osFp.probeOs(r.ip, base) : osFp.classifyOs(base);
          if (os) r.os = os;
        } catch { /* one host must not break the scan */ }
      });
    }
    job.status = 'done';
    job.finishedAt = new Date().toISOString();
    const inv = mergeInventory(job.rows, { network, full: true });
    job.newCount = inv.newCount;
    appendHistory({ id: job.id, cidr: network, total: hosts.length, found: alive.length, arpOnly: false, startedAt: job.startedAt, finishedAt: job.finishedAt });
    broadcast(job);
  } catch (err) {
    job.status = 'error';
    job.error = err.message;
    job.finishedAt = new Date().toISOString();
    broadcast(job);
  }
}

// ---------- app ----------
const app = express();
app.disable('x-powered-by');

/* Local-first security: only loopback and RFC1918 origins may call the API.
 * Requests without an Origin header (curl, the scanner itself) still work. */
const PRIVATE_ORIGIN = /^https?:\/\/(?:localhost|127(?:\.\d{1,3}){3}|\[::1\]|10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})(?::\d+)?$/i;
const originAllowed = (origin) => !origin || PRIVATE_ORIGIN.test(origin);

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-site');
  if (req.method !== 'GET' && req.method !== 'HEAD' && req.method !== 'OPTIONS'
    && req.headers.origin && !originAllowed(req.headers.origin)) {
    return res.status(403).json({ error: 'Origin not allowed' });
  }
  next();
});

app.use(cors({
  origin: (origin, cb) => cb(null, originAllowed(origin)),
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
}));
app.use(express.json({ limit: '256kb' }));

const routerSecurity = createRouterSecurity({
  checkPort,
  httpProbe,
  certProbe,
  ssdpSweep,
  soapAction,
  identifyDevice,
  pickInterface,
  getArpTable,
  lookupVendor,
  parseCidr,
  ipToInt,
  pingHost,
  mapLimit,
});

const tools = createTools({
  getInterfaces,
  getWifiInfo,
  getArpTable,
  parseCidr,
  storageStats,
});

function routerJobPublic(job) {
  return {
    id: job.id,
    status: job.status,
    phase: job.phase,
    progress: job.progress,
    target: job.target,
    gateway: job.gateway,
    result: job.result,
    error: job.error,
    startedAt: job.startedAt,
    finishedAt: job.finishedAt,
  };
}

app.get('/api/router-security', (_req, res) => {
  res.json({
    latest: routerSecurity.latestResult(),
    scope: {
      side: 'lan',
      externalChecked: false,
      note: 'LAN-side checks only. External/WAN exposure and default admin credentials were not tested.',
    },
  });
});

app.post('/api/router-security/scan', async (req, res) => {
  const { ip = null } = req.body || {};
  if (ip !== null && typeof ip !== 'string') return res.status(400).json({ error: 'ip must be a string' });
  try {
    const job = await routerSecurity.startScan({ ip });
    res.status(201).json(routerJobPublic(job));
  } catch (e) {
    res.status(400).json({ error: e.message || 'router scan failed' });
  }
});

app.get('/api/router-security/scan/:id', (req, res) => {
  const job = routerSecurity.getJob(req.params.id);
  if (!job) return res.status(404).json({ error: 'router scan not found' });
  res.json(routerJobPublic(job));
});

app.get('/api/tools/health', async (_req, res) => {
  try {
    res.json(await tools.health());
  } catch (e) {
    res.status(500).json({ error: e.message || 'health check failed' });
  }
});

app.post('/api/tools/ping', async (req, res) => {
  const { host, count, timeoutMs } = req.body || {};
  try {
    res.json(await tools.ping({ host, count, timeoutMs }));
  } catch (e) {
    res.status(400).json({ error: e.message || 'ping failed' });
  }
});

app.post('/api/tools/traceroute', async (req, res) => {
  const { host, maxHops, timeoutMs } = req.body || {};
  try {
    res.json(await tools.traceroute({ host, maxHops, timeoutMs }));
  } catch (e) {
    res.status(400).json({ error: e.message || 'traceroute failed' });
  }
});

app.post('/api/tools/dns-benchmark', async (req, res) => {
  const { domain, timeoutMs } = req.body || {};
  try {
    res.json(await tools.dnsBenchmark({ domain, timeoutMs }));
  } catch (e) {
    res.status(400).json({ error: e.message || 'DNS benchmark failed' });
  }
});

app.post('/api/tools/dns-lookup', async (req, res) => {
  const { host, timeoutMs } = req.body || {};
  try {
    res.json(await tools.dnsLookup({ host, timeoutMs }));
  } catch (e) {
    res.status(400).json({ error: e.message || 'DNS lookup failed' });
  }
});

app.get('/api/tools/wifi', async (_req, res) => {
  try {
    res.json(await tools.wifi());
  } catch (e) {
    res.status(500).json({ error: e.message || 'Wi-Fi scan failed' });
  }
});

app.get('/api/tools/dhcp', async (_req, res) => {
  try {
    res.json(await tools.dhcp());
  } catch (e) {
    res.status(500).json({ error: e.message || 'DHCP diagnostics failed' });
  }
});

app.get('/api/tools/hidden-cameras', (_req, res) => {
  try {
    const devices = readJson(DEVICES_FILE, {});
    const notes = readJson(NOTES_FILE, {});
    res.json(tools.hiddenCameras(devices, notes));
  } catch (e) {
    res.status(500).json({ error: e.message || 'camera inventory analysis failed' });
  }
});

app.get('/api/health', async (_req, res) => {
  // Light touch: report AI backend state so the client can show
  // "AI ready" instead of failing on first click. Fast timeout on purpose.
  let ai = null;
  try {
    ai = await aiStatus(2000);
  } catch { ai = null; }
  res.json({ ok: true, platform: process.platform, time: new Date().toISOString(), ai });
});

app.get('/api/ai-status', async (_req, res) => {
  res.json(await aiStatus());
});

app.get('/api/interfaces', async (_req, res) => {
  const ifaces = getInterfaces();
  const wifi = getWifiInfo();
  const arp = await getArpTable();
  const ips = Object.keys(arp);
  const scored = ifaces.map((i) => {
    let score = 0;
    try {
      const { hosts } = parseCidr(i.cidr);
      const set = new Set(hosts);
      score = ips.filter((ip) => set.has(ip)).length;
    } catch {
      score = 0;
    }
    return { ...i, arpHits: score };
  }).sort((a, b) => b.arpHits - a.arpHits);
  res.json({ interfaces: scored, recommended: scored[0]?.cidr || null, wifi });
});

app.get('/api/arp', async (_req, res) => {
  const table = await getArpTable();
  res.json({
    count: Object.keys(table).length,
    entries: Object.entries(table)
      .map(([ip, mac]) => {
        const vendor = lookupVendor(mac).vendor;
        return { ip, mac, vendor, type: inferType(vendor, '') };
      })
      .sort((a, b) => ipToInt(a.ip) - ipToInt(b.ip)),
  });
});

app.get('/api/scans', (_req, res) => {
  const live = [...jobs.values()].map(jobPublic).sort((a, b) => (b.startedAt || '').localeCompare(a.startedAt || ''));
  const cutoff = Date.now() - RETENTION_DAYS * 24 * 3600 * 1000;
  const history = readJson(HISTORY_FILE, []).filter((entry) => {
    const at = new Date(entry.finishedAt || entry.startedAt || 0).getTime();
    return !at || at >= cutoff;
  });
  res.json({ jobs: live, history });
});

app.get('/api/storage', async (_req, res) => {
  res.json(await storageStats());
});

app.post('/api/scans', async (req, res) => {
  const { cidr = null, timeout = 0.8, workers = 128, arpOnly = false, resolveNames = false, serviceScan = true } = req.body || {};
  if (timeout < 0.2 || timeout > 5) return res.status(400).json({ error: 'timeout must be 0.2–5s' });
  if (workers < 1 || workers > 512) return res.status(400).json({ error: 'workers must be 1–512' });
  let network = null;
  if (!arpOnly) {
    try {
      if (cidr) {
        network = parseCidr(cidr).network;
      } else {
        const ifaces = getInterfaces();
        if (!ifaces.length) return res.status(400).json({ error: 'No LAN interface found — pass cidr explicitly' });
        const arp = await getArpTable();
        const ips = Object.keys(arp);
        let best = ifaces[0];
        let bestScore = -1;
        for (const i of ifaces) {
          try {
            const set = new Set(parseCidr(i.cidr).hosts);
            const score = ips.filter((ip) => set.has(ip)).length;
            if (score > bestScore) { best = i; bestScore = score; }
          } catch { /* ignore */ }
        }
        network = best.cidr;
      }
    } catch (e) {
      return res.status(400).json({ error: e.message });
    }
  }
  const id = `scan-${Date.now().toString(36)}-${(seq++).toString(36)}`;
  const job = {
    id, status: 'running', cidr: network, network,
    total: 0, done: 0, aliveCount: 0, rows: [],
    arpOnly: Boolean(arpOnly), error: null,
    startedAt: new Date().toISOString(), finishedAt: null,
    cancelled: false, clients: new Set(),
  };
  jobs.set(id, job);
  runScan(job, { timeout: Number(timeout), workers: Number(workers), arpOnly: Boolean(arpOnly), resolveNames: Boolean(resolveNames), serviceScan: serviceScan !== false });
  res.status(201).json(jobPublic(job));
});

app.get('/api/scans/:id', (req, res) => {
  const job = jobs.get(req.params.id);
  if (!job) return res.status(404).json({ error: 'scan not found' });
  res.json(jobPublic(job));
});

app.get('/api/scans/:id/events', (req, res) => {
  const job = jobs.get(req.params.id);
  if (!job) return res.status(404).json({ error: 'scan not found' });
  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
  res.write(`data: ${JSON.stringify(jobPublic(job))}\n\n`);
  job.clients.add(res);
  req.on('close', () => job.clients.delete(res));
});

app.delete('/api/scans/:id', (req, res) => {
  const job = jobs.get(req.params.id);
  if (!job) return res.status(404).json({ error: 'scan not found' });
  job.cancelled = true;
  res.json({ ok: true, id: job.id });
});

app.get('/api/watch', (_req, res) => {
  res.json(watchState());
});

app.post('/api/watch', (req, res) => {
  const { intervalSec = 15 } = req.body || {};
  res.status(201).json(startWatch(intervalSec));
});

app.delete('/api/watch', (_req, res) => {
  res.json(stopWatch());
});

app.post('/api/identify', async (req, res) => {
  const { ip } = req.body || {};
  if (!ip || !/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return res.status(400).json({ error: 'valid ip required' });
  try {
    res.json(await identifyIp(ip));
  } catch (e) {
    res.status(500).json({ error: e.message || 'identify failed' });
  }
});

app.post('/api/ai-guess', async (req, res) => {
  const { ip } = req.body || {};
  if (!ip || !/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return res.status(400).json({ error: 'valid ip required' });
  try {
    const { fp, verdict } = await identifyIp(ip);
    let ai = null;
    try {
      ai = await llmGuess({ ip, verdict: verdict.model || verdict.kind, evidence: verdict.evidence, http: fp.http, cert: fp.cert });
    } catch (e) {
      // Model missing / daemon down with a specific fix — surface it directly.
      if (e.code === 'MODEL_MISSING' || /ollama model/i.test(e.message || '')) {
        return res.status(501).json({ error: 'ollama model missing', hint: e.message, aiStatus: await aiStatus() });
      }
    }
    if (!ai) {
      const st = await aiStatus();
      const hint = !st.reachable
        ? `Ollama not reachable at ${st.host} — run: ollama serve (then: ollama pull ${st.model}).`
        : !st.modelAvailable
          ? `Ollama is up but model "${st.model}" is not pulled — run: ollama pull ${st.model}. Found: ${st.models.join(', ') || '(none)'}.`
          : 'Ollama did not return a guess — try again, or set OPENAI_API_KEY as fallback.';
      return res.status(501).json({ error: 'no AI guess produced', hint, aiStatus: st });
    }
    res.json({ ip, ai });
  } catch (e) {
    res.status(500).json({ error: e.message || 'ai-guess failed' });
  }
});

app.get('/api/wan', async (_req, res) => {
  res.json(await getWanStats());
});

/* Link snapshot: interface, Wi-Fi radio details and the negotiated link
 * rate (the PHY rate, not measured traffic). */
app.get('/api/link', async (_req, res) => {
  try {
    res.json(await linkSnapshot());
  } catch (e) {
    res.status(500).json({ error: e.message || 'link info failed' });
  }
});

/* Speed test: latency + download + upload throughput to a test server.
 * Runs as a job so the client can show live progress. */
app.post('/api/speedtest', (_req, res) => {
  const job = startSpeedTest();
  res.status(201).json(speedJobPublic(job));
});

app.get('/api/speedtest/:id', (req, res) => {
  const job = speedJobs.get(req.params.id);
  if (!job) return res.status(404).json({ error: 'speed test not found' });
  res.json(speedJobPublic(job));
});

app.delete('/api/speedtest/:id', (req, res) => {
  const job = speedJobs.get(req.params.id);
  if (!job) return res.status(404).json({ error: 'speed test not found' });
  job.cancelled = true;
  job.status = 'cancelled';
  job.controller.abort();
  res.json({ ok: true, id: job.id });
});

app.get('/api/threats', (_req, res) => {
  const inv = readJson(DEVICES_FILE, {});
  const trusted = readJson(TRUSTED_FILE, {});
  const threats = analyzeThreats(inv, trusted);
  res.json({ count: threats.length, critical: threats.filter((t) => t.sev === 'critical').length, threats });
});

/* MAC clone detector table: every known MAC with its IPs, sighting window,
 * suspicion score and status. Correlates SQLite sightings with the live
 * inventory (online flags), so DHCP/roaming history doesn't cry wolf. */
app.get('/api/clones', (_req, res) => {
  try {
    const inv = readJson(DEVICES_FILE, {});
    const trusted = readJson(TRUSTED_FILE, {});
    const observations = cloneStore.recentObservations();
    const rows = cloneDetector.buildCloneTable({ observations, inventory: inv, trusted });
    res.json({
      count: rows.length,
      suspicious: rows.filter((r) => r.level === 'suspicious').length,
      likely: rows.filter((r) => r.level === 'likely').length,
      signals: Object.entries(cloneDetector.POINTS).map(([key, points]) => ({ key, points })),
      rows,
    });
  } catch (e) {
    res.status(500).json({ error: e.message || 'clone table failed' });
  }
});

app.get('/api/trusted', (_req, res) => {
  res.json(readJson(TRUSTED_FILE, {}));
});

app.post('/api/trusted', (req, res) => {
  const { mac, name = '', ip = '' } = req.body || {};
  const norm = normalizeMac(mac || '');
  if (!norm) return res.status(400).json({ error: 'valid mac required (aa:bb:cc:dd:ee:ff)' });
  if (ip && !/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return res.status(400).json({ error: 'valid ip required' });
  const all = readJson(TRUSTED_FILE, {});
  all[norm] = { name: String(name).slice(0, 80), ip, addedAt: new Date().toISOString() };
  writeJson(TRUSTED_FILE, all);
  res.status(201).json({ mac: norm, ...all[norm] });
});

app.delete('/api/trusted/:mac', (req, res) => {
  const norm = normalizeMac(req.params.mac || '');
  const all = readJson(TRUSTED_FILE, {});
  if (!norm || !all[norm]) return res.status(404).json({ error: 'not in trusted list' });
  delete all[norm];
  writeJson(TRUSTED_FILE, all);
  res.json({ ok: true, mac: norm });
});

app.post('/api/stability', async (req, res) => {
  const { ip, count = 6 } = req.body || {};
  if (!ip || !/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return res.status(400).json({ error: 'valid ip required' });
  res.json(await stabilityCheck(ip, Number(count) || 6));
});

app.get('/api/scans/:id/export', (req, res) => {
  const job = jobs.get(req.params.id);
  if (!job) return res.status(404).json({ error: 'scan not found' });
  const format = (req.query.format || 'json').toLowerCase();
  if (format === 'csv') {
    const lines = ['ip,mac,hostname,vendor,type,source'];
    for (const r of job.rows) {
      const esc = (v) => `"${String(v || '').replace(/"/g, '""')}"`;
      lines.push([r.ip, r.mac, r.hostname, r.vendor, r.type, r.source].map(esc).join(','));
    }
    res.header('Content-Type', 'text/csv').header('Content-Disposition', `attachment; filename="${job.id}.csv"`);
    return res.send(lines.join('\n'));
  }
  res.header('Content-Disposition', `attachment; filename="${job.id}.json"`);
  res.json(job.rows);
});

app.post('/api/ping', async (req, res) => {
  const { ip, timeout = 1 } = req.body || {};
  if (!ip || !/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return res.status(400).json({ error: 'valid ip required' });
  res.json(await pingHost(ip, Math.min(5, Math.max(0.2, Number(timeout) || 1))));
});

app.post('/api/ports', async (req, res) => {
  const { ip, ports = DEFAULT_PORTS, timeoutMs = 1000 } = req.body || {};
  if (!ip || !/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return res.status(400).json({ error: 'valid ip required' });
  const list = [...new Set((ports || []).map(Number).filter((p) => p >= 1 && p <= 65535))].slice(0, 100);
  if (!list.length) return res.status(400).json({ error: 'no valid ports' });
  const results = await mapLimit(list, 20, (port) => checkPort(ip, port, Math.min(5000, timeoutMs)));
  res.json({ ip, open: results.filter((r) => r.open), all: results });
});

app.get('/api/vendor/:mac', (req, res) => {
  res.json(lookupVendor(req.params.mac));
});

app.get('/api/notes', (_req, res) => {
  res.json(readJson(NOTES_FILE, {}));
});

/* Persistent inventory across scans: online/offline, first/last seen,
 * plus this machine ("self") and the likely gateway for highlighting. */
app.get('/api/devices', async (_req, res) => {
  const inv = readJson(DEVICES_FILE, {});
  const { iface } = await pickInterface();
  let gatewayIp = null;
  if (iface) {
    try {
      gatewayIp = parseCidr(iface.cidr).hosts[0] || null; // network base + 1
    } catch { gatewayIp = null; }
  }
  const devices = Object.values(inv)
    .map((d) => ({
      ...d,
      isSelf: !!iface && d.ip === iface.ip,
      isGateway: !!gatewayIp && d.ip === gatewayIp,
    }))
    .sort((a, b) => ipToInt(a.ip) - ipToInt(b.ip));
  if (iface && !devices.some((d) => d.isSelf)) {
    const now = new Date().toISOString();
    devices.unshift({
      ip: iface.ip, mac: '', hostname: '', vendor: 'This device',
      type: 'computer', source: 'self', firstSeen: now, lastSeen: now,
      online: true, isSelf: true, isGateway: false,
    });
  }
  res.json({
    selfIp: iface ? iface.ip : null,
    gatewayIp,
    network: iface ? iface.cidr : null,
    wifi: getWifiInfo(),
    online: devices.filter((d) => d.online).length,
    count: devices.length,
    devices,
  });
});

app.put('/api/notes/:ip', (req, res) => {
  const { ip } = req.params;
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return res.status(400).json({ error: 'valid ip required' });
  const TYPES = ['phone', 'tablet', 'computer', 'tv', 'speaker', 'camera', 'printer', 'console', 'router', 'iot', 'unknown'];
  const { name = '', notes = '', favorite = false, hidden = false, type = null } = req.body || {};
  const all = readJson(NOTES_FILE, {});
  const prev = all[ip] || {};
  all[ip] = {
    name: String(name).slice(0, 80), notes: String(notes).slice(0, 1000),
    favorite: Boolean(favorite), hidden: Boolean(hidden),
    type: TYPES.includes(type) ? type : (TYPES.includes(prev.type) ? prev.type : null),
    updatedAt: new Date().toISOString(),
  };
  writeJson(NOTES_FILE, all);
  res.json(all[ip]);
});

// Serve built React client when present (npm run build in ../client).
const distDir = path.join(__dirname, '..', 'client', 'dist');
if (fs.existsSync(distDir)) {
  app.use(express.static(distDir, {
    index: false,
    etag: true,
    setHeaders(res, filePath) {
      if (filePath.endsWith('index.html')) {
        res.setHeader('Cache-Control', 'no-cache');
      } else if (/[\\/]assets[\\/].*-[A-Za-z0-9_-]{8}\./.test(filePath)) {
        res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
      }
    },
  }));
  app.get(/^(?!\/api).*/, (_req, res) => {
    res.setHeader('Cache-Control', 'no-cache');
    res.sendFile(path.join(distDir, 'index.html'));
  });
}

if (require.main === module) {
  ensureDataDir();
  const server = app.listen(PORT, HOST, () => {
    const exposed = HOST === '0.0.0.0' || HOST === '::';
    const shown = exposed ? 'localhost' : HOST;
    console.log(`LAN-CAP API on http://${shown}:${PORT}${exposed ? ' (all interfaces)' : ''}`);
    if (exposed) {
      console.warn('  Warning: the API is reachable from other devices on this network and has no login. Use HOST=127.0.0.1 for local-only access.');
    }
  });
  const shutdown = () => {
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 2000).unref();
  };
  process.once('SIGINT', shutdown);
  process.once('SIGTERM', shutdown);
  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.error(
        `\nPort ${PORT} is already in use — another instance of the LAN-CAP API is running.\n` +
        `  Stop it first:  Stop-Process -Id <PID> -Force\n` +
        `  Or pick another port:  set PORT=<other> in server/.env\n` +
        `  The already-running instance is fine — just open http://localhost:${PORT}\n`
      );
      process.exit(1);
    }
    console.error(err);
    process.exit(1);
  });
}

module.exports = { app, parseCidr, normalizeMac, lookupVendor, inferType, refineType, scanServices, identifyDevice, fingerprintIp, ssdpSweep, analyzeThreats, stabilityCheck, ipToInt, getInterfaces, getArpTable, getWifiInfo, mergeInventory, startWatch, stopWatch, watchTick, watchState, getWanStats, storageStats, aiStatus, llmGuess, ollamaConfig, linkSnapshot, adapterLinkSpeed, measureLatency, measureDownload, measureUpload, startSpeedTest, speedJobPublic, routerSecurity, routerJobPublic };
