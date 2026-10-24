'use strict';
// Isolate the SQLite observation log: point it at a temp file BEFORE
// ./server (which requires ./db) is loaded.
process.env.LAN_CAP_DB = require('path').join(require('os').tmpdir(), `lan-cap-test-${process.pid}.sqlite`);
// Quick backend self-test: node test.js (no network scan by default).
const assert = require('assert');
const { parseCidr, normalizeMac, lookupVendor, inferType, refineType, scanServices, identifyDevice, analyzeThreats, ipToInt, getInterfaces, getWifiInfo, mergeInventory, startWatch, stopWatch, watchTick } = require('./server');
const { assessRouter, riskLevel } = require('./router-security');
const {
  safeTarget, parsePingOutput, parseTraceroute, parseNetshWifi, parseNmcliWifi, parseAirportWifi, cameraCandidates,
} = require('./tools');

async function main() {
  // CIDR parsing
  const { network, hosts } = parseCidr('192.168.1.0/29');
  assert.strictEqual(network, '192.168.1.0/29');
  assert.strictEqual(hosts.length, 6, 'expected 6 hosts for /29');
  assert.ok(hosts.includes('192.168.1.1') && hosts.includes('192.168.1.6'));

  assert.throws(() => parseCidr('not-a-cidr'), /Invalid CIDR/);
  assert.throws(() => parseCidr('10.0.0.0/8'), /Prefix must/);

  // MAC normalize
  assert.strictEqual(normalizeMac('00-17-7C-8F-42-1B'), '00:17:7c:8f:42:1b');
  assert.strictEqual(normalizeMac('zz:zz:zz:zz:zz:zz'), null);

  // Vendor (full IEEE registry in oui.json)
  assert.strictEqual(lookupVendor('10:bd:3a:aa:bb:cc').vendor, 'Apple');
  assert.strictEqual(lookupVendor('b8:27:eb:aa:bb:cc').vendor, 'Raspberry Pi');
  assert.strictEqual(lookupVendor('6c:5a:b0:aa:bb:cc').vendor, 'TP-Link');
  assert.strictEqual(lookupVendor('11:22:33:44:55:66').vendor, 'Unknown');
  assert.ok(Object.keys(require('./oui.json')).length > 30000, 'expected full IEEE OUI registry');

  // Device-type inference
  assert.strictEqual(inferType('Apple', 'iPhone-12'), 'phone');
  assert.strictEqual(inferType('Dell', ''), 'computer');
  assert.strictEqual(inferType('Samsung Electronics', 'Living-Room-TV'), 'tv');
  assert.strictEqual(inferType('Sonos', ''), 'speaker');
  assert.strictEqual(inferType('Zhejiang Dahua Technology', ''), 'camera');
  assert.strictEqual(inferType('Cisco', ''), 'router');
  assert.strictEqual(inferType('Espressif', ''), 'iot');
  assert.strictEqual(inferType('Unknown', ''), 'unknown');

  // Service discovery labels + type refinement
  assert.strictEqual(refineType('unknown', [{ port: 9100 }]), 'printer');
  assert.strictEqual(refineType('iot', [{ port: 554 }]), 'camera');
  assert.strictEqual(refineType('phone', [{ port: 443, label: 'Web' }]), 'phone');
  const svc = await scanServices('127.0.0.1');
  assert.ok(Array.isArray(svc), 'service scan returns an array');
  assert.ok(svc.every((s) => s.port && s.label), 'each service has port+label');

  // Deterministic fingerprint verdicts (pure function, no network)
  const v1 = identifyDevice({ ip: '192.0.2.5', vendor: 'Unknown', hostname: '', services: [], http: { server: 'Sonos/57.1 UPnP/1.0', title: '', realm: '' }, cert: {}, upnp: {} });
  assert.strictEqual(v1.confidence, 'high');
  assert.ok(/sonos/i.test(v1.model), 'http Server header identifies Sonos');
  const v2 = identifyDevice({ ip: '192.0.2.6', vendor: 'Unknown', hostname: '', services: [], http: {}, cert: {}, upnp: { manufacturer: 'Philips', model: 'BSB002', friendly: 'Philips hue' } });
  assert.strictEqual(v2.confidence, 'high');
  assert.ok(/philips/i.test(v2.model), 'upnp model identifies Hue bridge');
  assert.strictEqual(v2.kind, 'iot');
  const v3 = identifyDevice({ ip: '192.0.2.7', vendor: 'Unknown', hostname: '', services: [], http: {}, cert: {}, upnp: {} });
  assert.strictEqual(v3.confidence, 'low');
  const v4 = identifyDevice({ ip: '192.0.2.8', vendor: 'Smartlink', hostname: '', services: [{ port: 80 }], http: { server: 'GoAhead-Webs', title: '', realm: '' }, cert: {}, upnp: {} });
  assert.strictEqual(v4.confidence, 'medium');
  assert.ok(/goahead/i.test(v4.model), 'embedded webserver recognized');

  // Watchdog: duplicate MAC, IP flip, trusted clone
  const invT = {
    '192.0.2.1': { ip: '192.0.2.1', mac: 'aa:bb:cc:dd:ee:01', hostname: 'mine', vendor: 'Apple', online: true, firstSeen: '2026-01-01T00:00:00.000Z' },
    '192.0.2.2': { ip: '192.0.2.2', mac: 'aa:bb:cc:dd:ee:01', hostname: 'intruder-pc', vendor: 'Unknown', online: true, firstSeen: '2026-01-02T00:00:00.000Z' },
    '192.0.2.3': { ip: '192.0.2.3', mac: '10:bd:3a:00:00:02', hostname: 'printer', vendor: 'HP', online: true, macHistory: ['10:bd:3a:00:00:09'], macChangedAt: '2026-01-03T00:00:00.000Z' },
  };
  const th = analyzeThreats(invT, { 'aa:bb:cc:dd:ee:01': { name: 'My iPhone', ip: '192.0.2.1' } });
  const kinds = th.map((t) => t.kind);
  assert.ok(kinds.includes('duplicate-mac'), 'duplicate MAC flagged');
  assert.ok(kinds.includes('trusted-clone'), 'trusted clone flagged');
  assert.ok(kinds.includes('ip-hijack'), 'ip hijack flagged');
  const dup = th.find((t) => t.kind === 'duplicate-mac');
  assert.ok(dup.holders.find((h) => h.suspect && h.ip === '192.0.2.2'), 'newest holder is the suspect');
  assert.deepStrictEqual(analyzeThreats({}, {}), [], 'empty inventory, no threats');

  // Privacy rotation (randomized MAC) is info, not a hijack
  const th2 = analyzeThreats({
    '192.0.2.9': { ip: '192.0.2.9', mac: '9e:a9:79:00:00:02', hostname: 'iphone', vendor: 'Unknown', online: true, macHistory: ['9e:a9:79:00:00:01'] },
  }, {});
  assert.strictEqual(th2.length, 1);
  assert.strictEqual(th2[0].kind, 'mac-rotation');
  assert.strictEqual(th2[0].sev, 'info');

  // IP sort helper
  assert.ok(ipToInt('10.0.0.2') > ipToInt('10.0.0.1'));

  // Interfaces (env-dependent, just must not throw)
  const ifaces = getInterfaces();
  // Wi-Fi info (env-dependent, must not throw; on this machine should see an SSID)
  const wifi = getWifiInfo();
  assert.ok(Array.isArray(wifi));
  console.log(`wifi: ${wifi.map((w) => `${w.ssid} (${w.bssid}, ${w.signal})`).join('; ') || '(none)'}`);
  assert.ok(Array.isArray(ifaces));
  console.log(`interfaces: ${ifaces.map((i) => i.cidr).join(', ') || '(none)'}`);

  // Inventory-backed tests share one backup/restore of the real devices.json
  const fs = require('fs');
  const path = require('path');
  const devFile = path.join(__dirname, 'data', 'devices.json');
  const backup = fs.existsSync(devFile) ? fs.readFileSync(devFile, 'utf8') : null;
  try {
    // Watch mode: brand-new MAC while watching lands in newSince
    startWatch(60);
    try {
      mergeInventory([
        { ip: '192.0.2.99', mac: 'de:ad:be:ef:00:01', hostname: '', vendor: 'Unknown', type: 'unknown', source: 'arp' },
      ], { full: false });
      const st = await watchTick();
      assert.ok(st.watching, 'watch stays on');
      assert.ok(st.newSince.some((e) => e.ip === '192.0.2.99'), 'new arrival recorded');
      assert.ok(st.lastCheck, 'lastCheck set');
    } finally {
      stopWatch();
    }

    // Full-scan merge marks missing hosts offline
    const r1 = mergeInventory([
      { ip: '192.0.2.10', mac: '10:bd:3a:00:00:01', hostname: '', vendor: 'Apple', type: 'phone', source: 'ping' },
    ], { network: '192.0.2.0/28', full: true });
    assert.strictEqual(r1.newCount, 1);
    const r2 = mergeInventory([
      { ip: '192.0.2.11', mac: '10:bd:3a:00:00:02', hostname: '', vendor: 'Apple', type: 'phone', source: 'ping' },
    ], { network: '192.0.2.0/28', full: true });
    assert.strictEqual(r2.newCount, 1);
    const inv = JSON.parse(fs.readFileSync(devFile, 'utf8'));
    assert.strictEqual(inv['192.0.2.10'].online, false, 'missing host goes offline on full scan');
    assert.strictEqual(inv['192.0.2.11'].online, true);
    assert.ok(inv['192.0.2.11'].firstSeen && inv['192.0.2.11'].lastSeen);
  } finally {
    if (backup === null) fs.rmSync(devFile, { force: true });
    else fs.writeFileSync(devFile, backup);
  }

  // ARP (env-dependent)
  const { getArpTable } = require('./server');
  const arp = await getArpTable();
  console.log(`arp entries: ${Object.keys(arp).length}`);

  // Clone detector: suspicion scoring (pure, no network)
  const detector = require('./detector');
  const T0 = Date.parse('2026-10-15T12:00:00.000Z');
  const iso = (ms) => new Date(ms).toISOString();
  const obs = (mac, ip, at, bssid = '') => ({ mac, ip, observed_at: iso(at), bssid });
  const MAC = '00:11:22:33:44:55'; // burned-in (2nd hex char '0')

  // Single MAC + single IP: nothing to correlate -> normal, score 0
  {
    const rows = [obs(MAC, '192.168.1.20', T0)];
    const t = detector.buildCloneTable({ observations: rows, now: T0 + 60000 });
    assert.strictEqual(t.length, 1);
    assert.strictEqual(t[0].score, 0);
    assert.strictEqual(t[0].level, 'normal');
  }

  // Textbook clone: same MAC, two IPs, active 2 min apart -> 20 + 30 = suspicious
  {
    const rows = [obs(MAC, '192.168.1.20', T0), obs(MAC, '192.168.1.35', T0 + 120000)];
    const t = detector.buildCloneTable({ observations: rows, now: T0 + 180000 });
    assert.strictEqual(t[0].score, 50);
    assert.strictEqual(t[0].level, 'suspicious');
    assert.ok(t[0].signals.some((s) => s.key === 'MULTI_IP'));
    assert.ok(t[0].signals.some((s) => s.key === 'SIMULTANEOUS'));
  }

  // Plus ARP flip-flop on one IP -> +30 -> 80, likely clone
  {
    const rows = [
      obs(MAC, '192.168.1.20', T0), obs(MAC, '192.168.1.35', T0 + 120000),
      obs('00:11:22:33:44:66', '192.168.1.35', T0 + 60000),
    ];
    const t = detector.buildCloneTable({ observations: rows, now: T0 + 180000 });
    const row = t.find((r) => r.mac === MAC.toLowerCase());
    assert.strictEqual(row.score, 80);
    assert.strictEqual(row.level, 'likely');
  }

  // DHCP-style sequential move (2h apart): only +20 -> normal, no false alarm
  {
    const rows = [obs(MAC, '192.168.1.20', T0), obs(MAC, '192.168.1.21', T0 + 2 * 3600000)];
    const t = detector.buildCloneTable({ observations: rows, now: T0 + 2 * 3600000 + 60000 });
    assert.strictEqual(t[0].score, 20);
    assert.strictEqual(t[0].level, 'normal');
  }

  // Privacy address with clone-like footprint: capped at suspicious, never likely
  {
    const rows = [
      obs('9e:a9:79:00:00:02', '192.168.1.20', T0), obs('9e:a9:79:00:00:02', '192.168.1.35', T0 + 120000),
      obs('00:11:22:33:44:66', '192.168.1.35', T0 + 60000),
    ];
    const t = detector.buildCloneTable({ observations: rows, now: T0 + 180000 });
    const row = t.find((r) => r.mac === '9e:a9:79:00:00:02');
    assert.strictEqual(row.level, 'suspicious');
    assert.ok(row.score <= 60 && row.capped, 'privacy rotation capped below likely');
  }

  // Trusted device on an unexpected single IP: +40 -> suspicious on its own
  {
    const rows = [obs(MAC, '192.168.1.35', T0)];
    const t = detector.buildCloneTable({
      observations: rows, now: T0 + 60000,
      trusted: { [MAC.toLowerCase()]: { name: 'My PC', ip: '192.168.1.20' } },
    });
    assert.strictEqual(t[0].score, 40);
    assert.strictEqual(t[0].level, 'suspicious');
  }

  // Two APs (BSSIDs): +50 location signal
  {
    const rows = [obs(MAC, '192.168.1.20', T0, 'aa:00:00:00:00:01'), obs(MAC, '192.168.1.35', T0 + 3600000 * 3, 'bb:00:00:00:00:02')];
    const t = detector.buildCloneTable({ observations: rows, now: T0 + 3600000 * 3 + 60000 });
    assert.ok(t[0].signals.some((s) => s.key === 'DIFF_LOCATION'));
    assert.ok(t[0].score >= 70 && t[0].level === 'likely');
  }

  // Inventory seeding: no SQLite rows yet -> table still built, sorted by score
  {
    const t = detector.buildCloneTable({
      observations: [],
      inventory: {
        '192.168.1.20': { ip: '192.168.1.20', mac: MAC, vendor: 'Test', online: true, lastSeen: iso(T0), firstSeen: iso(T0 - 3600000) },
      },
      now: T0 + 60000,
    });
    assert.strictEqual(t.length, 1);
    assert.strictEqual(t[0].level, 'normal');
  }

  // SQLite observation log round-trip (isolated temp DB)
  {
    const store = require('./db');
    assert.ok(store.available(), 'node:sqlite available');
    const TMAC = '02:00:5e:aa:bb:cc';
    store.record([{ mac: TMAC, ip: '192.0.2.77', source: 'test' }], { bssid: 'test-bssid' });
    const back = store.recentObservations(new Date(0).toISOString()).filter((o) => o.mac === TMAC);
    assert.ok(back.length >= 1 && back[0].ip === '192.0.2.77' && back[0].bssid === 'test-bssid');
    const st = store.stats();
    assert.ok(st.sqlite && st.observations >= 1, 'sqlite stats report rows');
    store.deleteByMac(TMAC);
    for (const suffix of ['', '-shm', '-wal']) {
      try { fs.unlinkSync(process.env.LAN_CAP_DB + suffix); } catch { /* ignore */ }
    }
  }

  // Tools: target validation and platform output parsers (pure)
  assert.strictEqual(safeTarget(' Example.COM. '), 'example.com');
  assert.strictEqual(safeTarget('192.168.1.1'), '192.168.1.1');
  assert.throws(() => safeTarget(''), /required/);
  assert.throws(() => safeTarget('-oProxyCommand=calc'), /hostname|IPv4/);
  assert.throws(() => safeTarget('bad host'), /hostname|IPv4/);
  assert.throws(() => safeTarget('a..b'), /empty label/);

  assert.strictEqual(parsePingOutput('Reply from 1.1.1.1: bytes=32 time=12ms TTL=57'), 12);
  assert.strictEqual(parsePingOutput('64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=8.41 ms'), 8.41);
  assert.strictEqual(parsePingOutput('Reply from 192.168.1.1: bytes=32 time<1ms TTL=64'), 0.5);
  assert.strictEqual(parsePingOutput('Request timed out.'), null);

  const winTrace = `Tracing route to example.com over a maximum of 3 hops\n\n  1    <1 ms    <1 ms    <1 ms  192.168.1.1\n  2     8 ms     7 ms     9 ms  10.0.0.1\n  3     *        *        *     Request timed out.\n`;
  const winHops = parseTraceroute(winTrace);
  assert.strictEqual(winHops.length, 3);
  assert.strictEqual(winHops[0].ip, '192.168.1.1');
  assert.deepStrictEqual(winHops[1].ms, [8, 7, 9]);
  assert.strictEqual(winHops[2].timeout, true);
  const nixTrace = `traceroute to example.com (93.184.216.34), 3 hops max\n 1  192.168.1.1  1.123 ms  0.912 ms  0.888 ms\n 2  * * *\n`;
  const nixHops = parseTraceroute(nixTrace);
  assert.strictEqual(nixHops.length, 2);
  assert.strictEqual(nixHops[0].ip, '192.168.1.1');
  assert.strictEqual(nixHops[1].timeout, true);

  const netsh = `SSID 1 : HomeNet\n    Network type            : Infrastructure\n    Authentication          : WPA2-Personal\n    Encryption              : CCMP\n    BSSID 1                 : 72:5a:b0:c0:16:cf\n         Signal             : 80%\n         Radio type         : 802.11ac\n         Band               : 5 GHz\n         Channel            : 36\n    BSSID 2                 : 72:5a:b0:c0:16:d0\n         Signal             : 55%\n         Channel            : 44\nSSID 2 : Guest\n    Authentication          : Open\n    Encryption              : None\n    BSSID 1                 : aa:bb:cc:dd:ee:ff\n         Signal             : 42%\n`;
  const netshNets = parseNetshWifi(netsh);
  assert.strictEqual(netshNets.length, 3);
  assert.strictEqual(netshNets[0].ssid, 'HomeNet');
  assert.strictEqual(netshNets[0].signalPct, 80);
  assert.strictEqual(netshNets[0].channel, 36);
  assert.strictEqual(netshNets[2].auth, 'Open');

  const nmcli = 'HomeNet:72\\:5A\\:B0\\:C0\\:16\\:CF:36:80:WPA2\nGuest:AA\\:BB\\:CC\\:DD\\:EE\\:FF:6:42:--';
  const nmNets = parseNmcliWifi(nmcli);
  assert.strictEqual(nmNets.length, 2);
  assert.strictEqual(nmNets[0].bssid, '72:5A:B0:C0:16:CF');
  assert.strictEqual(nmNets[0].signalPct, 80);
  assert.strictEqual(nmNets[1].ssid, 'Guest');

  const airport = '                            SSID BSSID             RSSI CHANNEL HT CC SECURITY\n                          HomeNet 72:5a:b0:c0:16:cf -55  36      Y  US WPA2(PSK/AES/AES)\n';
  const airNets = parseAirportWifi(airport);
  assert.strictEqual(airNets.length, 1);
  assert.strictEqual(airNets[0].ssid, 'HomeNet');
  assert.strictEqual(airNets[0].signalPct, 90);

  const cameras = cameraCandidates({
    '192.168.1.20': { ip: '192.168.1.20', mac: 'aa:bb:cc:dd:ee:01', vendor: 'Dahua', type: 'camera', online: true, ports: [{ port: 554 }, { port: 80 }] },
    '192.168.1.21': { ip: '192.168.1.21', mac: 'aa:bb:cc:dd:ee:02', vendor: 'Unknown', hostname: 'ipcam-garage', type: 'unknown', online: true, ports: [{ port: 554 }, { port: 8080 }] },
    '192.168.1.22': { ip: '192.168.1.22', mac: 'aa:bb:cc:dd:ee:03', vendor: 'HP', type: 'printer', online: true, ports: [{ port: 80 }] },
    '192.168.1.23': { ip: '192.168.1.23', mac: 'aa:bb:cc:dd:ee:04', vendor: 'Hikvision', type: 'camera', online: false, ports: [{ port: 554 }] },
  }, { '192.168.1.21': { name: 'Garage camera' } });
  assert.strictEqual(cameras.candidates.length, 2, 'only online camera-like devices are candidates');
  assert.strictEqual(cameras.likely, 2);
  assert.ok(cameras.candidates[0].reasons.some((reason) => /RTSP/.test(reason)));

  // Router security: pure risk assessment
  assert.strictEqual(riskLevel(0), 'safe');
  assert.strictEqual(riskLevel(1), 'low');
  assert.strictEqual(riskLevel(20), 'medium');
  assert.strictEqual(riskLevel(40), 'high');
  assert.strictEqual(riskLevel(70), 'critical');

  {
    const clean = assessRouter({
      gateway: { ip: '192.168.1.1', mac: '00:11:22:33:44:55', vendor: 'Unknown' },
      ports: [{ port: 80, label: 'HTTP', open: false }, { port: 443, label: 'HTTPS', open: true }],
      upnp: { discovered: false, igd: false },
      natpmp: { supported: false },
      fingerprint: { vendor: 'Unknown', model: '', http: { status: 200, server: 'nginx' } },
    });
    assert.strictEqual(clean.risk.score, 0);
    assert.strictEqual(clean.risk.level, 'safe');
    assert.strictEqual(clean.findings.length, 0);
    assert.strictEqual(clean.checks.find((c) => c.id === 'https').status, 'pass');
    assert.ok(clean.recommendations.length > 0, 'always gives baseline recommendations');
  }

  {
    const bad = assessRouter({
      gateway: { ip: '10.0.0.1', mac: 'aa:bb:cc:dd:ee:ff', vendor: 'Netgear' },
      ports: [
        { port: 23, label: 'Telnet', open: true },
        { port: 445, label: 'SMB', open: true },
        { port: 80, label: 'HTTP', open: true },
        { port: 443, label: 'HTTPS', open: false },
      ],
      upnp: { discovered: true, igd: true, controlConfirmed: true, externalIp: '203.0.113.7' },
      natpmp: { supported: true, protocol: 'NAT-PMP', externalIp: '203.0.113.7' },
      fingerprint: {
        vendor: 'Netgear', model: 'R7000', confidence: 'high',
        http: { status: 200, server: 'RomPager/4.07 UPnP/1.0', title: 'NETGEAR Router' },
      },
    });
    assert.strictEqual(bad.risk.score, 100, 'score is capped at 100');
    assert.strictEqual(bad.risk.level, 'critical');
    assert.ok(bad.findings.some((f) => f.id === 'port-23'));
    assert.ok(bad.findings.some((f) => f.id === 'upnp-igd'));
    assert.ok(bad.findings.some((f) => f.id === 'natpmp'));
    const rom = bad.findings.find((f) => f.cves.includes('CVE-2014-9222'));
    assert.ok(rom && rom.confidence === 'possible', 'fingerprint CVE match is labelled possible');
    assert.ok(bad.findings.some((f) => f.id === 'http-admin' && f.severity === 'medium'), 'HTTP-only admin UI is flagged');
    assert.ok(bad.checks.every((c) => c.id && c.label && c.status), 'every check has id/label/status');
  }

  {
    const redirected = assessRouter({
      gateway: { ip: '192.168.1.1' },
      ports: [{ port: 80, open: true }, { port: 443, open: true }],
      upnp: {},
      natpmp: {},
      fingerprint: {
        http: { status: 200, location: '', server: 'lighttpd' },
        web: [
          { port: 80, scheme: 'http', status: 301, location: 'https://192.168.1.1/' },
          { port: 443, scheme: 'https', status: 200, location: '' },
        ],
      },
    });
    assert.ok(!redirected.findings.some((f) => f.id === 'http-admin'), 'HTTP redirect to HTTPS is acceptable even when the HTTPS probe is the primary fingerprint');
  }

  console.log('All backend self-tests passed.');
}

main().catch((e) => { console.error('SELF-TEST FAILED:', e.message); process.exit(1); });
