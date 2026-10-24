/* SQLite observation log for the MAC clone detector.
 * Zero new dependencies: uses Node's built-in node:sqlite (Node 22.5+).
 *
 * One row per MAC<->IP sighting, so the detector can correlate a MAC with
 * its IPs, timing, and AP location over days — not just "seen twice".
 * Storage: server/data/lan-cap.sqlite (override with LAN_CAP_DB).
 * Every function is best-effort: if SQLite is unavailable the detector
 * falls back to the live inventory and nothing throws.
 */
'use strict';

const fs = require('fs');
const path = require('path');

let DatabaseSync = null;
try {
  ({ DatabaseSync } = require('node:sqlite'));
} catch {
  DatabaseSync = null; // old Node: store stays a no-op
}

const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = process.env.LAN_CAP_DB || process.env.LAN_SCANNER_DB || path.join(DATA_DIR, 'lan-cap.sqlite');
const MAX_ROWS_PER_READ = 50000;

/* Adopt the database from the previous product name, once. */
function migrateLegacyDb() {
  if (process.env.LAN_CAP_DB || process.env.LAN_SCANNER_DB) return;
  const legacy = path.join(DATA_DIR, 'lan-scanner.sqlite');
  try {
    if (fs.existsSync(legacy) && !fs.existsSync(DB_FILE)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
      fs.renameSync(legacy, DB_FILE);
      for (const suffix of ['-wal', '-shm']) {
        if (fs.existsSync(legacy + suffix)) fs.renameSync(legacy + suffix, DB_FILE + suffix);
      }
    }
  } catch { /* migration is best-effort; a fresh DB is fine */ }
}

migrateLegacyDb();

let db = null;

function open() {
  if (db || !DatabaseSync) return db;
  try {
    fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
    db = new DatabaseSync(DB_FILE);
    db.exec(
      'CREATE TABLE IF NOT EXISTS observations(' +
      'id INTEGER PRIMARY KEY AUTOINCREMENT,' +
      'mac TEXT NOT NULL, ip TEXT NOT NULL, observed_at TEXT NOT NULL,' +
      'source TEXT DEFAULT "", hostname TEXT DEFAULT "",' +
      'vendor TEXT DEFAULT "", bssid TEXT DEFAULT "");' +
      'CREATE INDEX IF NOT EXISTS idx_obs_mac_time ON observations(mac, observed_at);' +
      'CREATE INDEX IF NOT EXISTS idx_obs_ip_time ON observations(ip, observed_at);'
    );
    return db;
  } catch {
    db = null;
    return null;
  }
}

/* Append one sighting per row. Never throws. */
function record(rows, { bssid = '', at = null, retentionDays = 4 } = {}) {
  if (!rows || !rows.length) return 0;
  const conn = open();
  if (!conn) return 0;
  const stamp = at || new Date().toISOString();
  let n = 0;
  try {
    const stmt = conn.prepare(
      'INSERT INTO observations(mac, ip, observed_at, source, hostname, vendor, bssid)' +
      ' VALUES (?, ?, ?, ?, ?, ?, ?)'
    );
    for (const r of rows) {
      if (!r || !r.mac || !r.ip) continue;
      stmt.run(
        String(r.mac).toLowerCase(), String(r.ip),
        stamp, String(r.source || ''), String(r.hostname || '').slice(0, 120),
        String(r.vendor || '').slice(0, 120), String(bssid || '')
      );
      n++;
    }
    prune(retentionDays);
  } catch {
    /* observation logging must never break a scan */
  }
  return n;
}

function prune(retentionDays = 4) {
  const conn = open();
  if (!conn) return;
  try {
    const cutoff = new Date(Date.now() - retentionDays * 86400 * 1000).toISOString();
    conn.prepare('DELETE FROM observations WHERE observed_at < ?').run(cutoff);
  } catch {
    /* ignore */
  }
}

/* All sightings since `sinceIso` (default: full retention window). Never throws. */
function recentObservations(sinceIso = null) {
  const conn = open();
  if (!conn) return [];
  try {
    const since = sinceIso || new Date(Date.now() - 4 * 86400 * 1000).toISOString();
    return conn.prepare(
      'SELECT mac, ip, observed_at, source, hostname, vendor, bssid' +
      ' FROM observations WHERE observed_at >= ? ORDER BY observed_at ASC LIMIT ?'
    ).all(since, MAX_ROWS_PER_READ);
  } catch {
    return [];
  }
}

function deleteByMac(mac) {
  const conn = open();
  if (!conn) return;
  try {
    conn.prepare('DELETE FROM observations WHERE mac = ?').run(String(mac).toLowerCase());
  } catch {
    /* ignore */
  }
}

function stats() {
  const conn = open();
  if (!conn) return { sqlite: false };
  try {
    const n = conn.prepare('SELECT COUNT(*) AS n FROM observations').get().n;
    const macs = conn.prepare('SELECT COUNT(DISTINCT mac) AS n FROM observations').get().n;
    const oldest = conn.prepare('SELECT MIN(observed_at) AS t FROM observations').get().t;
    return { sqlite: true, file: DB_FILE, observations: n, observedMacs: macs, oldestObservation: oldest || null };
  } catch {
    return { sqlite: false };
  }
}

module.exports = { record, recentObservations, deleteByMac, prune, stats, available: () => Boolean(open()) };
