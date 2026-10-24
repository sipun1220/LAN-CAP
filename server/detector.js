/* MAC clone detector — suspicion scoring engine (pure functions, no I/O).
 *
 * A MAC seen twice proves nothing (DHCP, roaming, reconnects). Confidence
 * comes from CORRELATION: same MAC + different IPs + overlapping activity
 * windows + ARP conflicts + AP location. Each signal adds points:
 *
 *   same MAC on 2+ IPs .................... +20  MULTI_IP
 *   2+ of those IPs active at the same time  +30  SIMULTANEOUS
 *   3+ IPs inside 1h (rapid movement) ...... +10  RAPID_MOVE
 *   one of its IPs also seen with another
 *     MAC (ARP flip-flop) ................. +30  ARP_CONFLICT
 *   same MAC seen via 2+ APs (BSSIDs) ...... +50  DIFF_LOCATION
 *   trusted MAC on an unexpected IP ....... +40  TRUSTED_CLONE
 *
 * Levels:  0–30 normal · 31–60 suspicious · 61–100 likely clone.
 * Privacy (randomized) MACs are capped at `suspicious`: iOS/Android
 * rotate these constantly, so a high score there is rotation, not cloning.
 */
'use strict';

const POINTS = {
  MULTI_IP: 20,
  SIMULTANEOUS: 30,
  RAPID_MOVE: 10,
  ARP_CONFLICT: 30,
  DIFF_LOCATION: 50,
  TRUSTED_CLONE: 40,
};

const SIMULTANEITY_MS = 10 * 60 * 1000; // "both active at once" window
const RAPID_WINDOW_MS = 60 * 60 * 1000; // rapid-movement window

/* Locally-administered bit set => randomized privacy address, not a
 * burned-in factory MAC (2nd hex char of first octet in 2,6,A-F...). */
function isRandomizedMac(mac) {
  const c = String(mac || '').charAt(1).toLowerCase();
  return c !== '' && '2367abef'.includes(c);
}

function levelFor(score) {
  if (score >= 61) return 'likely';
  if (score >= 31) return 'suspicious';
  return 'normal';
}

function ms(t) {
  const v = new Date(t || 0).getTime();
  return Number.isNaN(v) ? 0 : v;
}

/* Group raw sightings {mac, ip, observed_at, bssid?} by MAC. */
function groupByMac(observations) {
  const groups = new Map();
  for (const o of observations || []) {
    if (!o || !o.mac || !o.ip) continue;
    const mac = String(o.mac).toLowerCase();
    if (!groups.has(mac)) groups.set(mac, []);
    groups.get(mac).push(o);
  }
  return groups;
}

/* Map ip -> set of MACs seen on it (for ARP-conflict detection). */
function macsByIp(observations) {
  const map = new Map();
  for (const o of observations || []) {
    if (!o || !o.mac || !o.ip) continue;
    const key = String(o.ip);
    if (!map.has(key)) map.set(key, new Set());
    map.get(key).add(String(o.mac).toLowerCase());
  }
  return map;
}

/* Score one MAC group. `ipMacs` is the global ip->macs map (for conflicts).
 * `ctx` carries the trusted entry + live-inventory online flags. */
function scoreMac(mac, sightings, ipMacs, ctx = {}) {
  const signals = [];
  const byIp = new Map();
  for (const s of sightings) {
    const ip = String(s.ip);
    if (!byIp.has(ip)) byIp.set(ip, []);
    byIp.get(ip).push(s);
  }
  const ips = [...byIp.keys()];
  const latestPerIp = ips.map((ip) => Math.max(...byIp.get(ip).map((s) => ms(s.observed_at))));

  if (ips.length > 1) {
    signals.push({
      key: 'MULTI_IP', points: POINTS.MULTI_IP,
      detail: `One MAC on ${ips.length} IPs: ${ips.slice(0, 5).join(', ')}${ips.length > 5 ? '…' : ''}`,
    });
  }

  // Simultaneous activity: newest sightings of 2+ IPs within the window,
  // or the live inventory shows 2+ of them online right now.
  const onlineIps = new Set(ctx.onlineIps || []);
  const liveCount = ips.filter((ip) => onlineIps.has(ip)).length;
  const newest = Math.max(...latestPerIp, 0);
  const recentCount = latestPerIp.filter((t) => newest - t <= SIMULTANEITY_MS).length;
  if (ips.length > 1 && (liveCount >= 2 || recentCount >= 2)) {
    signals.push({
      key: 'SIMULTANEOUS', points: POINTS.SIMULTANEOUS,
      detail: liveCount >= 2
        ? `${liveCount} IPs online at once`
        : `${recentCount} IPs active within ${SIMULTANEITY_MS / 60000} min of each other`,
    });
  }

  // Rapid movement: 3+ distinct IPs inside the trailing rapid window.
  const cutoff = (ctx.now || Date.now()) - RAPID_WINDOW_MS;
  const recentIps = new Set(
    sightings.filter((s) => ms(s.observed_at) >= cutoff).map((s) => String(s.ip))
  );
  if (recentIps.size >= 3) {
    signals.push({
      key: 'RAPID_MOVE', points: POINTS.RAPID_MOVE,
      detail: `${recentIps.size} IPs in the last hour — DHCP rarely moves that fast`,
    });
  }

  // ARP conflict: one of this MAC's IPs was also claimed by another MAC.
  const conflicts = ips.filter((ip) => (ipMacs.get(ip) || new Set()).size > 1);
  if (conflicts.length) {
    signals.push({
      key: 'ARP_CONFLICT', points: POINTS.ARP_CONFLICT,
      detail: `${conflicts.slice(0, 3).join(', ')} answered for 2+ MACs — classic clone/ARP-spoof footprint`,
    });
  }

  // Different network location: same MAC behind 2+ APs.
  const bssids = new Set(sightings.map((s) => String(s.bssid || '')).filter(Boolean));
  if (bssids.size > 1) {
    signals.push({
      key: 'DIFF_LOCATION', points: POINTS.DIFF_LOCATION,
      detail: `Seen via ${bssids.size} access points — one radio can't be in two places`,
    });
  }

  // Trusted device wearing its MAC on an unexpected IP.
  const trusted = ctx.trusted || null;
  if (trusted && trusted.ip && !ips.includes(trusted.ip) && ips.length) {
    signals.push({
      key: 'TRUSTED_CLONE', points: POINTS.TRUSTED_CLONE,
      detail: `Locked to ${trusted.ip}${trusted.name ? ` ("${trusted.name}")` : ''} but live on ${ips.join(', ')}`,
    });
  }

  let score = Math.min(100, signals.reduce((n, s) => n + s.points, 0));
  const randomized = isRandomizedMac(mac);
  const capped = randomized && score > 60;
  if (capped) score = 60; // rotation, not cloning — never "likely"
  return { score, level: levelFor(score), signals, randomized, capped };
}

/* Build the full MAC table:
 *   [{ mac, ips[], firstSeen, lastSeen, score, level, signals[] }]
 * `observations` come from SQLite; `inventory` (devices.json) covers hosts
 * seen before logging began and supplies live online flags + vendors.
 * Sorted by score desc, then most-recent first. */
function buildCloneTable({ observations = [], inventory = {}, trusted = {}, now = Date.now() } = {}) {
  const invList = Object.values(inventory || {}).filter((d) => d && d.mac);
  // Seed pseudo-sightings from inventory so fresh installs still get a table.
  const seeded = observations.slice();
  for (const d of invList) {
    seeded.push({
      mac: String(d.mac).toLowerCase(), ip: d.ip,
      observed_at: d.lastSeen || d.firstSeen || new Date(now).toISOString(),
      hostname: d.hostname || '', vendor: d.vendor || '', bssid: '',
    });
  }
  const groups = groupByMac(seeded);
  const ipMacs = macsByIp(seeded);
  const onlineByMac = new Map();
  for (const d of invList) {
    if (!d.online) continue;
    const mac = String(d.mac).toLowerCase();
    if (!onlineByMac.has(mac)) onlineByMac.set(mac, new Set());
    onlineByMac.get(mac).add(d.ip);
  }
  const tnorm = {};
  for (const [m, t] of Object.entries(trusted || {})) tnorm[String(m).toLowerCase()] = t;

  const rows = [];
  for (const [mac, sightings] of groups) {
    const times = sightings.map((s) => ms(s.observed_at)).filter(Boolean);
    const scored = scoreMac(mac, sightings, ipMacs, {
      now, trusted: tnorm[mac] || null, onlineIps: onlineByMac.get(mac) || new Set(),
    });
    const byIp = new Map();
    for (const s of sightings) {
      const cur = byIp.get(s.ip);
      if (!cur || ms(s.observed_at) > ms(cur)) byIp.set(s.ip, s.observed_at);
    }
    const vendor = (sightings.find((s) => s.vendor && s.vendor !== 'Unknown') || {}).vendor || 'Unknown';
    rows.push({
      mac,
      vendor,
      ips: [...byIp.entries()].map(([ip, lastSeen]) => ({
        ip, lastSeen, online: (onlineByMac.get(mac) || new Set()).has(ip),
      })).sort((a, b) => ms(b.lastSeen) - ms(a.lastSeen)),
      firstSeen: times.length ? new Date(Math.min(...times)).toISOString() : null,
      lastSeen: times.length ? new Date(Math.max(...times)).toISOString() : null,
      sightings: sightings.length,
      ...scored,
    });
  }
  rows.sort((a, b) => b.score - a.score || ms(b.lastSeen) - ms(a.lastSeen));
  return rows;
}

module.exports = {
  POINTS, SIMULTANEITY_MS, RAPID_WINDOW_MS,
  isRandomizedMac, levelFor, groupByMac, macsByIp, scoreMac, buildCloneTable,
};
