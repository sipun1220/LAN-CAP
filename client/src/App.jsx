import { useEffect, useMemo, useRef, useState } from 'react';
import { api, subscribeScan } from './api.js';
import { Icon, DeviceIcon, SignalBars } from './icons.jsx';
import { TopoMap } from './topo.jsx';
import ToolsView from './ToolsView.jsx';
import './App.css';

const TERMINAL = new Set(['done', 'error', 'cancelled']);

const TYPE_META = {
  phone: { label: 'Phone' }, tablet: { label: 'Tablet' },
  computer: { label: 'Computer' }, tv: { label: 'TV' },
  speaker: { label: 'Speaker' }, camera: { label: 'Camera' },
  printer: { label: 'Printer' }, console: { label: 'Console' },
  router: { label: 'Router' }, iot: { label: 'Smart home' },
  unknown: { label: 'Device' },
};

function typeOf(d) {
  return TYPE_META[d.type] ? d.type : 'unknown';
}

function cleanName(s) {
  if (!s) return '';
  let x = String(s).trim();
  // strip common suffixes like "-PC", "._airplay", mDNS junk? keep simple
  x = x.replace(/\.(local|lan|home|work)$/i, '');
  x = x.replace(/-.*$/, (m) => {
    // keep short hyphenated brandy names? usually PC suffixes not useful
    if (/-pc|-desktop|-laptop|-macbook|-iphone|-ipad|-imac|-tv|-android$/i.test(m)) return '';
    return m;
  });
  // drop empty segments
  if (!x) return '';
  if (/^[0-9a-f]{2}[:-][0-9a-f]{2}/i.test(x)) return '';
  if (/^[\d.]+$/.test(x)) return '';
  return x;
}

function displayName(d, note) {
  if (note?.name) return note.name;
  const upnp = d.upnp?.friendlyName || d.upnp?.modelName;
  const cu = cleanName(upnp);
  if (cu) return cu;
  const h = cleanName(d.hostname);
  if (h) return h;
  if (d.fp?.model) return d.fp.model;
  if (d.vendor && d.vendor !== 'Unknown') return `${d.vendor} device`;
  if (d.type && d.type !== 'unknown' && TYPE_META[d.type]) return `Unknown ${TYPE_META[d.type].label.toLowerCase()}`;
  return 'Unknown device';
}

function deviceName(d, note) {
  if (note?.name) return note.name;
  const upnp = d.upnp?.friendlyName || d.upnp?.modelName;
  const cu = cleanName(upnp);
  if (cu) return cu;
  const h = cleanName(d.hostname);
  if (h) return h;
  if (d.vendor && d.vendor !== 'Unknown') return `${d.vendor} device`;
  return 'Unknown device';
}

function deviceModel(d) {
  return d.fp?.model || (d.vendor && d.vendor !== 'Unknown' ? d.vendor : 'Unknown model');
}

function osLabel(d) {
  const os = d.os;
  if (!os?.name) return '';
  return os.version ? `${os.name} · ${os.version}` : os.name;
}

function ipKey(ip) {
  return String(ip).split('.').reduce((a, p) => a * 256 + Number(p), 0);
}

function ago(iso) {
  if (!iso) return 'never';
  const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
  if (s < 10) return 'just now';
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function fmtTime(iso) {
  if (!iso) return '—';
  try { return new Date(iso).toLocaleString(); } catch { return iso; }
}

/* "New" = first seen within the last 24h. */
function isFresh(d) {
  if (!d.firstSeen) return false;
  return Date.now() - new Date(d.firstSeen).getTime() < 24 * 3600 * 1000;
}

/* Locally-administered MAC => randomized privacy address. */
function isRandomizedMac(mac) {
  const c = String(mac || '').charAt(1).toLowerCase();
  return c !== '' && '2367abef'.includes(c);
}

export default function App() {
  const [health, setHealth] = useState(null);
  const [ifaces, setIfaces] = useState([]);
  const [cidr, setCidr] = useState('');
  const [timeout, setTimeout] = useState(0.8);
  const [workers, setWorkers] = useState(128);
  const [arpOnly, setArpOnly] = useState(false);
  const [resolveNames, setResolveNames] = useState(false);
  const [serviceScan, setServiceScan] = useState(true);
  const [job, setJob] = useState(null);
  const [devices, setDevices] = useState([]);
  const [net, setNet] = useState({ selfIp: null, gatewayIp: null, network: null, wifi: [] });
  const [notes, setNotes] = useState({});
  const [history, setHistory] = useState([]);
  const [storage, setStorage] = useState(null);
  const [error, setError] = useState('');
  const [presence, setPresence] = useState('online');
  const [filter, setFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [sort, setSort] = useState('status');
  const [showHidden, setShowHidden] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [selected, setSelected] = useState(null);
  const [gwPing, setGwPing] = useState(null);
  const [bannerFor, setBannerFor] = useState(null);
  const [route, setRoute] = useState('overview');
  const [navOpen, setNavOpen] = useState(false);
  const [theme, setTheme] = useState(() => localStorage.getItem('lan-theme') || 'dark');
  const [accent, setAccent] = useState(() => localStorage.getItem('lan-accent') || 'blue');
  const [watchInfo, setWatchInfo] = useState(null);
  const [watching, setWatching] = useState(false);
  const [watchAlerts, setWatchAlerts] = useState([]);
  const [threats, setThreats] = useState({ count: 0, critical: 0, threats: [] });
  const [clones, setClones] = useState({ count: 0, suspicious: 0, likely: 0, rows: [], signals: [] });
  const [trusted, setTrusted] = useState({});
  const [tMac, setTMac] = useState('');
  const [tName, setTName] = useState('');
  const [tIp, setTIp] = useState('');
  const shownIds = useRef(new Set());

  const scanning = job && !TERMINAL.has(job.status);

  async function refreshInventory() {
    try {
      const d = await api.devices();
      setDevices(d.devices || []);
      setNet({ selfIp: d.selfIp, gatewayIp: d.gatewayIp, network: d.network, wifi: d.wifi || [] });
    } catch { /* offline */ }
    try {
      setThreats(await api.threats());
    } catch { /* offline */ }
    try {
      setClones(await api.clones());
    } catch { /* offline */ }
  }

  useEffect(() => {
    api.health().then(setHealth).catch(() => setHealth({ ok: false }));
    api.interfaces().then((d) => {
      setIfaces(d.interfaces || []);
      if (d.recommended) setCidr(d.recommended);
    }).catch(() => {});
    api.notes().then(setNotes).catch(() => {});
    api.trusted().then(setTrusted).catch(() => {});
    api.listScans().then((d) => setHistory([...(d.jobs || []), ...(d.history || [])].slice(0, 20))).catch(() => {});
    api.storage().then(setStorage).catch(() => {});
    refreshInventory();
  }, []);

  useEffect(() => {
    if (!job?.id || TERMINAL.has(job.status)) return;
    const unsub = subscribeScan(job.id, (next) => {
      setJob(next);
      if (TERMINAL.has(next.status)) {
        if (next.status === 'done' && next.newCount > 0) setBannerFor(next.id);
        refreshInventory();
        api.storage().then(setStorage).catch(() => {});
        api.listScans().then((d) => setHistory([...(d.jobs || []), ...(d.history || [])].slice(0, 20))).catch(() => {});
      }
    });
    return unsub;
  }, [job?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  async function startScan() {
    setError('');
    setBannerFor(null);
    try {
      const next = await api.startScan({
        cidr: cidr.trim() || null, timeout, workers, arpOnly, resolveNames, serviceScan,
      });
      setJob(next);
      setSelected(null);
    } catch (e) {
      setError(e.message);
    }
  }

  async function stopScan() {
    if (job?.id) {
      try { await api.cancelScan(job.id); } catch (e) { setError(e.message); }
    }
  }

  async function loadArp() {
    setError('');
    setBannerFor(null);
    try {
      const s = await api.startScan({ arpOnly: true });
      setJob({ ...s, total: 0, done: 0 });
      const poll = setInterval(async () => {
        try {
          const g = await api.getScan(s.id);
          setJob(g);
          if (TERMINAL.has(g.status)) {
            clearInterval(poll);
            if (g.status === 'done' && g.newCount > 0) setBannerFor(g.id);
            refreshInventory();
          }
        } catch { clearInterval(poll); }
      }, 800);
    } catch (e) {
      setError(e.message);
    }
  }

  async function pingGateway() {
    if (!net.gatewayIp) return;
    setGwPing('…');
    try {
      const r = await api.ping(net.gatewayIp, 1);
      setGwPing(r.alive ? `${r.ms} ms` : 'no reply');
    } catch { setGwPing('error'); }
  }

  async function toggleWatch() {
    if (watching) {
      try { await api.stopWatch(); } catch (e) { setError(e.message); }
      setWatching(false);
      return;
    }
    setError('');
    try {
      if ('Notification' in window && Notification.permission === 'default') {
        try { await Notification.requestPermission(); } catch { /* ignore */ }
      }
      await api.startWatch(15);
      shownIds.current = new Set();
      setWatchAlerts([]);
      setWatching(true);
    } catch (e) { setError(e.message); }
  }

  function notifyArrival(e) {
    try {
      if ('Notification' in window && Notification.permission === 'granted') {
        new Notification('New device joined your network', { body: `${e.vendor || 'Unknown device'} · ${e.ip}` });
      }
    } catch { /* notifications unavailable */ }
  }

  useEffect(() => {
    if (!watching) return;
    let stop = false;
    async function tick() {
      try {
        const w = await api.watch();
        if (!stop) setWatchInfo(w);
        const fresh = (w.newSince || []).filter((e) => !shownIds.current.has(`${e.ip}|${e.at}`));
        if (fresh.length && !stop) {
          for (const e of fresh) {
            shownIds.current.add(`${e.ip}|${e.at}`);
            notifyArrival(e);
          }
          setWatchAlerts((a) => [...fresh.map((e) => ({ key: `${e.ip}|${e.at}`, title: 'New device joined', desc: `${e.vendor || 'Unknown device'}`, ip: e.ip, at: e.at })), ...a].slice(0, 10));
          refreshInventory();
        }
        const th = await api.threats().catch(() => null);
        if (th && !stop) {
          setThreats(th);
          const suspectIp = (t) => (t.holders || []).find((h) => h.suspect)?.ip || (t.holders || [])[0]?.ip;
          const freshT = (th.threats || []).filter((t) => !shownIds.current.has(`threat:${t.id}`));
          if (freshT.length) {
            for (const t of freshT) {
              shownIds.current.add(`threat:${t.id}`);
              try {
                if ('Notification' in window && Notification.permission === 'granted') {
                  new Notification(`Watchdog: ${t.title}`, { body: t.desc });
                }
              } catch { /* ignore */ }
            }
            setWatchAlerts((a) => [...freshT.map((t) => ({ key: `threat:${t.id}`, title: t.title, desc: t.desc, ip: suspectIp(t), at: t.at })), ...a].slice(0, 10));
          }
        }
      } catch { /* keep watching */ }
    }
    tick();
    const t = setInterval(tick, 10000);
    return () => { stop = true; clearInterval(t); };
  }, [watching]); // eslint-disable-line react-hooks/exhaustive-deps

  const threatIps = useMemo(
    () => new Set((threats.threats || []).flatMap((t) => (t.holders || []).map((h) => h.ip))),
    [threats],
  );

  async function refreshTrusted() {
    try {
      setTrusted(await api.trusted());
      setThreats(await api.threats());
      setClones(await api.clones());
    } catch (e) { setError(e.message); }
  }

  async function addTrusted() {
    if (!tMac.trim()) { setError('Enter a MAC address to lock.'); return; }
    setError('');
    try {
      await api.addTrusted({ mac: tMac.trim(), name: tName.trim(), ip: tIp.trim() });
      setTMac(''); setTName(''); setTIp('');
      await refreshTrusted();
    } catch (e) { setError(e.message); }
  }

  async function removeTrusted(mac) {
    try {
      await api.removeTrusted(mac);
      await refreshTrusted();
    } catch (e) { setError(e.message); }
  }

  async function trustDevice(d) {
    try {
      await api.addTrusted({ mac: d.mac, name: displayName(d, notes[d.ip]), ip: d.ip });
      await refreshTrusted();
    } catch (e) { setError(e.message); }
  }

  async function toggleFlag(ip, key) {
    const cur = notes[ip] || {};
    try {
      const entry = await api.saveNote(ip, {
        name: cur.name || '', notes: cur.notes || '',
        favorite: key === 'favorite' ? !cur.favorite : !!cur.favorite,
        hidden: key === 'hidden' ? !cur.hidden : !!cur.hidden,
      });
      setNotes((n) => ({ ...n, [ip]: entry }));
    } catch (e) { setError(e.message); }
  }

  function exportInventory() {
    const head = ['name', 'ip', 'mac', 'vendor', 'type', 'hostname', 'online', 'firstSeen', 'lastSeen', 'sightings'];
    const rows = list.map((d) => {
      const n = notes[d.ip] || {};
      return [n.name || '', d.ip, d.mac || '', d.vendor || '', d.type || '', d.hostname || '',
        d.online ? 'yes' : 'no', d.firstSeen || '', d.lastSeen || '', d.sightings || 0];
    });
    const csv = [head, ...rows].map((r) => r.map((v) => `"${String(v).replace(/"/g, '""')}"`).join(',')).join('\n');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
    a.download = 'lan-inventory.csv';
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }

  const onlineCount = useMemo(() => devices.filter((d) => d.online).length, [devices]);
  const newCount = useMemo(() => devices.filter(isFresh).length, [devices]);

  /* Effective list: manual type tags from notes override auto-detection. */
  const list = useMemo(() => devices.map((d) => {
    const t = notes[d.ip]?.type;
    return t && TYPE_META[t] ? { ...d, type: t, typeManual: true } : d;
  }), [devices, notes]);

  const stats = useMemo(() => {
    const favs = list.filter((d) => notes[d.ip]?.favorite).length;
    const vendors = new Set(
      list.filter((d) => d.online).map((d) => d.vendor).filter((v) => v && v !== 'Unknown'),
    ).size;
    return [
      { label: 'Online now', value: onlineCount, icon: 'activity' },
      { label: 'All seen', value: list.length, icon: 'users' },
      { label: 'Vendors', value: vendors, icon: 'tag' },
      { label: 'Favorites', value: favs, icon: 'star' },
    ];
  }, [list, notes, onlineCount]);

  const typeOptions = useMemo(() => {
    const pool = presence === 'online' ? list.filter((d) => d.online) : list;
    const counts = {};
    for (const d of pool) counts[typeOf(d)] = (counts[typeOf(d)] || 0) + 1;
    return Object.entries(counts).sort((a, b) => b[1] - a[1]);
  }, [list, presence]);

  const visible = useMemo(() => {
    const f = filter.trim().toLowerCase();
    const rows = list.filter((d) => {
      const note = notes[d.ip];
      if (note?.hidden && !showHidden) return false;
      if (presence === 'online' && !d.online) return false;
      if (typeFilter !== 'all' && typeOf(d) !== typeFilter) return false;
      if (!f) return true;
      return `${displayName(d, note)} ${d.ip} ${d.mac} ${d.hostname} ${d.vendor} ${d.fp?.model || ''} ${d.upnp?.friendlyName || ''} ${d.upnp?.modelName || ''} ${d.os?.name || ''} ${d.os?.version || ''}`.toLowerCase().includes(f);
    });
    const byStatus = (a, b) => (b.online - a.online) || (ipKey(a.ip) - ipKey(b.ip));
    const byName = (a, b) => displayName(a, notes[a.ip]).localeCompare(displayName(b, notes[b.ip]));
    const byIp = (a, b) => ipKey(a.ip) - ipKey(b.ip);
    const bySeen = (a, b) => new Date(b.lastSeen || 0) - new Date(a.lastSeen || 0);
    rows.sort((a, b) => {
      const fa = notes[a.ip]?.favorite ? 0 : 1;
      const fb = notes[b.ip]?.favorite ? 0 : 1;
      if (fa !== fb) return fa - fb;
      if (sort === 'name') return byName(a, b);
      if (sort === 'ip') return byIp(a, b);
      if (sort === 'seen') return bySeen(a, b);
      return byStatus(a, b);
    });
    return rows;
  }, [list, filter, typeFilter, sort, presence, notes, showHidden]);

  const hiddenCount = useMemo(
    () => list.filter((d) => notes[d.ip]?.hidden).length,
    [list, notes],
  );

  const progress = job && job.total ? Math.round((job.done / job.total) * 100) : 0;
  const lastScan = history[0]?.finishedAt || history[0]?.startedAt;
  const ap = (net.wifi || [])[0];
  const freshOnline = useMemo(() => list.filter((d) => d.online && isFresh(d)).slice(0, 8), [list]);

  const NAV = [
    { id: 'overview', label: 'Overview', icon: 'home' },
    { id: 'devices', label: 'Devices', icon: 'users', badge: onlineCount },
    { id: 'map', label: 'Topology', icon: 'topo' },
    { id: 'watchdog', label: 'Watchdog', icon: 'shieldAlert', badge: threats.critical || null, badgeCrit: true },
    { id: 'activity', label: 'Activity', icon: 'clock' },
    { id: 'network', label: 'Network', icon: 'wifi' },
    { id: 'router', label: 'Router security', icon: 'shield' },
    { id: 'notifications', label: 'Notifications', icon: 'bell', badge: watchAlerts.length + (bannerFor ? 1 : 0) + (threats.count || 0), badgeCrit: !!threats.critical },
    { id: 'tools', label: 'Tools', icon: 'sliders' },
  ];

  const accentMap = {
    blue: { accent: '#0b9bd8', accentDark: '#0780b4', accentSoft: '#dff4ff' },
    teal: { accent: '#0ea5a4', accentDark: '#0f766e', accentSoft: '#dcfdf7' },
    violet: { accent: '#8b5cf6', accentDark: '#7c3aed', accentSoft: '#f1e8ff' },
    rose: { accent: '#ec4899', accentDark: '#db2777', accentSoft: '#ffe4f0' },
  };

  const activeAccent = accentMap[accent] || accentMap.blue;

  useEffect(() => {
    localStorage.setItem('lan-theme', theme);
    localStorage.setItem('lan-accent', accent);
    document.documentElement.setAttribute('data-theme', theme);
    document.documentElement.style.setProperty('--accent', activeAccent.accent);
    document.documentElement.style.setProperty('--accent-dark', activeAccent.accentDark);
    document.documentElement.style.setProperty('--accent-soft', activeAccent.accentSoft);
  }, [theme, accent, activeAccent]);

  function go(id) {
    setRoute(id);
    setNavOpen(false);
  }

  return (
    <div className="shell" data-theme={theme}>
      {navOpen && <div className="backdrop" onClick={() => setNavOpen(false)} />}
      <aside className={`side${navOpen ? ' open' : ''}`}>
        <div className="side-brand">
          <span className="logo sm"><Icon n="radar" s={20} /></span>
          <div><b>LAN-CAP</b><small>NETWORK INTELLIGENCE</small></div>
        </div>
        <nav>
          {NAV.map((r) => (
            <button key={r.id} className={route === r.id ? 'active' : ''} onClick={() => go(r.id)}>
              <Icon n={r.icon} s={18} /><span>{r.label}</span>
              {r.badge ? <em className={`badge${r.badgeCrit ? ' crit' : ''}`}>{r.badge}</em> : null}
            </button>
          ))}
        </nav>
        <div className="side-foot">
          <span className={`statusdot ${health?.ok ? 'on' : ''}`} />
          <small>{health?.ok ? `API · ${health.platform}` : 'API offline'}</small>
          {watching && <small className="watchmini"><span className="pulse on" /> Watching</small>}
        </div>
      </aside>
      <div className="main">
      <header className="cmdbar">
        <div className="cmdrow">
          <button className="menubtn" onClick={() => setNavOpen((v) => !v)} title="Menu"><Icon n="menu" s={20} /></button>
          <span className="searchwrap cmdsearch">
            <Icon n="search" s={16} />
            <input className="search" value={filter} aria-label="Filter devices" onChange={(e) => { setFilter(e.target.value); if (route !== 'devices') setRoute('devices'); }} placeholder="Search devices — IP, MAC, vendor, name…" />
            {filter && (
              <button className="clearbtn" onClick={() => setFilter('')} title="Clear search" aria-label="Clear search">
                <Icon n="x" s={14} />
              </button>
            )}
          </span>
          {ap && <span className="apchip" title={ap.bssid || ''}><Icon n="wifi" s={15} /> {ap.ssid} <SignalBars signal={ap.signal} /></span>}
          <div className="theme-switcher" aria-label="Theme controls">
            <label className="theme-select">
              <span className="sr-only">Theme</span>
              <select value={theme} onChange={(e) => setTheme(e.target.value)}>
                <option value="dark">Dark</option>
                <option value="light">Light</option>
              </select>
            </label>
            <label className="theme-select accent-select">
              <span className="sr-only">Accent</span>
              <select value={accent} onChange={(e) => setAccent(e.target.value)}>
                <option value="blue">Blue</option>
                <option value="teal">Teal</option>
                <option value="violet">Violet</option>
                <option value="rose">Rose</option>
              </select>
            </label>
          </div>
        </div>
        {health?.ok && (
          <div className="cmdsub">
            <LiveNetPill gatewayIp={net.gatewayIp} apiOk={!!health?.ok} />
          </div>
        )}
      </header>

      {error && <div className="alert" role="alert">{error} <button onClick={() => setError('')}><Icon n="x" s={16} /></button></div>}

      {route === 'overview' && (<>
      <section className="card hero">
        <div className="hero-top">
          <div className="hero-info">
            <h2>{net.network || 'Your network'}</h2>
            <p>
              {ap && <span className="apline"><Icon n="wifi" s={15} /> {ap.ssid} <SignalBars signal={ap.signal} /></span>}
              <span>{onlineCount} online · {list.length} seen</span>
              {newCount > 0 && <span className="pill new">{newCount} new</span>}
              {lastScan && <span className="muted"> · scanned {ago(lastScan)}</span>}
            </p>
          </div>
          {scanning
            ? <button className="scanbtn stop" onClick={stopScan} title="Stop scan"><Icon n="stop" s={26} /></button>
            : <button className="scanbtn" onClick={startScan} disabled={!health?.ok} title="Scan network"><Icon n="play" s={28} /></button>}
        </div>
        {job && (
          <div className="progress-wrap">
            <div className="progress-meta">
              <span>{job.status === 'running'
                ? (job.note && job.done >= job.total ? job.note : job.total ? `Scanning ${job.network || ''} — ${job.done}/${job.total} · ${job.aliveCount} up` : 'Reading ARP cache…')
                : `${job.status}${job.newCount ? ` · ${job.newCount} new` : ''} · ${job.rows?.length ?? 0} up`}</span>
              {job.total ? <span>{progress}%</span> : null}
            </div>
            {job.total ? <div className="progress"><div style={{ width: `${progress}%` }} /></div> : null}
          </div>
        )}
        <div className="hero-controls">
          <select value={cidr} onChange={(e) => setCidr(e.target.value)} title="Network to scan">
            {ifaces.filter((i) => !i.hotspot || ifaces.length === 1).map((i) => (
              <option key={i.cidr + i.name} value={i.cidr}>
                {i.cidr} · {i.ssid || i.name}
              </option>
            ))}
            {!ifaces.some((i) => i.cidr === cidr) && <option value={cidr}>{cidr || 'Auto'}</option>}
          </select>
          <button className="ghost btnicon" onClick={loadArp} title="Instant: read the ARP cache"><Icon n="zap" s={16} /> Quick scan</button>
          <button className={`ghost btnicon ${watching ? 'watching' : ''}`} onClick={toggleWatch} title="Background monitor — alerts the moment new devices join">
            <span className={`pulse ${watching ? 'on' : ''}`} />{watching ? 'Watching' : 'Watch'}
          </button>
          <button className="link" onClick={() => setShowAdvanced((s) => !s)}>
            Options <Icon n={showAdvanced ? 'chevU' : 'chevD'} s={14} />
          </button>
        </div>
        {showAdvanced && (
          <div className="adv">
            <label>Custom subnet
              <input value={cidr} onChange={(e) => setCidr(e.target.value)} placeholder="192.168.1.0/24" spellCheck={false} />
            </label>
            <label className="check"><input type="checkbox" checked={arpOnly} onChange={(e) => setArpOnly(e.target.checked)} /> ARP-only (instant, no ping)</label>
            <label className="check"><input type="checkbox" checked={resolveNames} onChange={(e) => setResolveNames(e.target.checked)} /> Resolve hostnames (slower)</label>
            <label className="check"><input type="checkbox" checked={serviceScan} onChange={(e) => setServiceScan(e.target.checked)} /> Detect services on every device (slower)</label>
            <label>Timeout <b>{timeout.toFixed(1)}s</b>
              <input type="range" min={0.2} max={2} step={0.1} value={timeout} onChange={(e) => setTimeout(Number(e.target.value))} />
            </label>
            <label>Workers <b>{workers}</b>
              <input type="range" min={16} max={512} step={16} value={workers} onChange={(e) => setWorkers(Number(e.target.value))} />
            </label>
          </div>
        )}
      </section>

      <section className="stats">
        {stats.map((s) => (
          <div className="stat" key={s.label}>
            <span className="stat-icon"><Icon n={s.icon} s={24} /></span>
            <div><b>{s.value}</b><span>{s.label}</span></div>
          </div>
        ))}
      </section>

      <section className="card">
        <div className="cardhead">
          <h2><Icon n="bell" s={18} /> New arrivals</h2>
          {newCount > 0 && <span className="pill new">{newCount} in 24h</span>}
        </div>
        {!freshOnline.length && <p className="muted small">No recently-joined online devices. Everything here has been around a while.</p>}
        <ul className="minirows">
          {freshOnline.map((d) => (
            <li key={d.ip} onClick={() => setSelected(d)}>
              <span className="dev-icon sm"><DeviceIcon type={typeOf(d)} s={20} /></span>
              <span className="cellname"><span className="devname">{displayName(d, notes[d.ip])}</span></span>
              <span className="mono dim">{d.ip}</span>
              <span className="muted small">{ago(d.firstSeen)}</span>
              <Icon n="chevR" s={18} />
            </li>
          ))}
        </ul>
      </section>
      </>)}

      {route === 'devices' && (
        <section className="card devices-card">
          <div className="cardhead">
            <h2><Icon n="users" s={18} /> Devices</h2>
          </div>
            <div className="seg">
              <button className={presence === 'online' ? 'active' : ''} onClick={() => setPresence('online')}>Online ({onlineCount})</button>
              <button className={presence === 'all' ? 'active' : ''} onClick={() => setPresence('all')}>All ({list.length})</button>
            </div>
            <div className="row tools">
              <span className="searchwrap">
                <Icon n="search" s={16} />
                <input className="search" value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Search devices…" />
              </span>
              <select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)} title="Filter by type">
                <option value="all">All types</option>
                {typeOptions.map(([t, n]) => (
                  <option key={t} value={t}>{TYPE_META[t].label} ({n})</option>
                ))}
              </select>
              <select value={sort} onChange={(e) => setSort(e.target.value)} title="Sort order">
                <option value="status">Status</option>
                <option value="name">Name</option>
                <option value="ip">IP address</option>
                <option value="seen">Recently seen</option>
              </select>
            </div>
            {hiddenCount > 0 && (
              <label className="check small showhidden">
                <input type="checkbox" checked={showHidden} onChange={(e) => setShowHidden(e.target.checked)} />
                Show {hiddenCount} hidden device{hiddenCount === 1 ? '' : 's'}
              </label>
            )}
            <div className="tablewrap">
            <table className="capture">
              <thead>
                <tr><th>Type</th><th>Model</th><th>Name</th><th className="c-status">Status</th><th>Last Update</th></tr>
              </thead>
              <tbody>
              {visible.map((d) => {
                const note = notes[d.ip];
                return (
                  <tr key={d.ip}
                    onClick={() => setSelected(d)}
                    className={`${selected?.ip === d.ip ? 'sel' : ''}${d.online ? '' : ' off'}${isFresh(d) && d.online ? ' row-new' : ''}${threatIps.has(d.ip) ? ' row-threat' : ''}${note?.hidden ? ' hidden-dev' : ''}`}>
                    <td><span className="typecell"><span className="dev-icon sm" title={TYPE_META[typeOf(d)].label}><DeviceIcon type={typeOf(d)} s={20} /></span>{TYPE_META[typeOf(d)].label}</span></td>
                    <td className="celltrim modelcell">
                      <span className="modelname">{deviceModel(d)}</span>
                      {d.os?.name && <span className="osline" title={osLabel(d)}>{osLabel(d)}</span>}
                    </td>
                    <td><span className="celldev">
                      <span className="cellname"><span className="devname">{deviceName(d, note)}</span>
                        {d.isSelf && <span className="tag self">YOU</span>}
                        {d.isGateway && <span className="tag gw">ROUTER</span>}
                        {isFresh(d) && <span className="tag new">NEW</span>}
                      </span>
                    </span></td>
                    <td>
                      <span className={`pill status-pill ${d.online ? 'online' : 'offline'}`}>
                        <span className={`statusdot ${d.online ? 'on' : ''}`} />
                        {d.online ? 'Online' : 'Offline'}
                      </span>
                    </td>
                    <td className="dim nowrap">{ago(d.lastSeen)}</td>
                  </tr>
                );
              })}
              {!visible.length && (
                <tr><td colSpan={5} className="emptycell">
                  <Icon n="search" s={28} />
                  {list.length ? (
                    <>
                      <p>No rows match the display filter.</p>
                      <button className="ghost btnicon" onClick={() => { setFilter(''); setTypeFilter('all'); setPresence('all'); setShowHidden(true); }}>
                        <Icon n="x" s={14} /> Clear search &amp; filters
                      </button>
                    </>
                  ) : (
                    <>
                      <p>Nothing captured yet — map your network to begin.</p>
                      <button className="primary btnicon" onClick={startScan} disabled={!health?.ok}>
                        <Icon n="play" s={15} /> Scan now
                      </button>
                    </>
                  )}
                </td></tr>
              )}
              </tbody>
            </table>
            </div>
          </section>
      )}

      {route === 'map' && (
        <section className="card">
          <div className="cardhead">
            <h2><Icon n="topo" s={18} /> Topology</h2>
            <span className="muted small">{visible.length} nodes · drag to orbit · click to inspect</span>
          </div>
          <TopoMap
            devices={visible}
            notes={notes}
            center={list.find((d) => d.isGateway) || list.find((d) => d.isSelf) || null}
            onSelect={setSelected}
            selectedIp={selected?.ip}
          />
        </section>
      )}

      {route === 'watchdog' && (<>
      <section className="card">
        <div className="cardhead">
          <h2><Icon n="eye" s={18} /> Background watch</h2>
          {watching && <span className="pill new"><span className="pulse on" /> active</span>}
        </div>
        <p className="muted small">
          {watching
            ? `Checking the ARP cache every ${watchInfo?.intervalSec || 15}s${watchInfo?.lastCheck ? ` · last check ${ago(watchInfo.lastCheck)}` : ''}. New arrivals and new threats raise alerts instantly.`
            : 'Idle. Start the watch to catch joiners and clones the moment they appear.'}
        </p>
        <div className="row">
          <button className={`ghost btnicon ${watching ? 'watching' : ''}`} onClick={toggleWatch}>
            <span className={`pulse ${watching ? 'on' : ''}`} />{watching ? 'Stop watch' : 'Start watch'}
          </button>
        </div>
      </section>
        <section className="card clones">
          <div className="cardhead">
            <h2><Icon n="shieldAlert" s={18} /> MAC Clone Detector</h2>
            {(clones.likely > 0 || clones.suspicious > 0)
              ? <span className={`pill ${clones.likely ? 'crit' : 'warnpill'}`}>{clones.likely ? `${clones.likely} likely` : `${clones.suspicious} suspicious`}</span>
              : <span className="pill new">all clear</span>}
          </div>
          <p className="muted small">
            One MAC seen twice proves nothing (DHCP, roaming, reconnects). Each MAC is scored on correlation:
            2+ IPs +20 · active at once +30 · rapid movement +10 · ARP conflict +30 · two APs +50 · trusted-device clone +40.
            0–30 normal · 31–60 suspicious · 61–100 likely clone. Privacy addresses are capped at suspicious.
          </p>
          <div className="tablewrap">
          <table className="clonetable">
            <thead><tr><th>MAC</th><th>IP(s)</th><th>First seen</th><th>Last seen</th><th>Score</th><th>Status</th></tr></thead>
            <tbody>
            {(clones.rows || []).slice(0, 30).map((r) => (
              <tr key={r.mac} className={`clone-${r.level}`}>
                <td className="mono" title={(r.signals || []).map((s) => `+${s.points} ${s.detail}`).join('\n')}>
                  {r.mac}{r.randomized ? ' ⓟ' : ''}
                </td>
                <td>{(r.ips || []).map((h) => (
                  <span key={h.ip} className={`mono mini${h.online ? '' : ' off'}`} title={h.online ? 'online now' : `last seen ${ago(h.lastSeen)}`}>
                    {h.ip}{h.online ? '' : ' ◦'}
                  </span>
                )).reduce((acc, el) => acc.length ? [...acc, ', ', el] : [el], [])}</td>
                <td className="muted small">{r.firstSeen ? ago(r.firstSeen) : '—'}</td>
                <td className="muted small">{r.lastSeen ? ago(r.lastSeen) : '—'}</td>
                <td>
                  <span className="scorebar" title={(r.signals || []).map((s) => `+${s.points} ${s.detail}`).join('\n')}>
                    <span className={`scorefill ${r.level}`} style={{ width: `${Math.min(100, r.score)}%` }} />
                  </span>
                  <span className="mono mini">{r.score}</span>
                </td>
                <td><span className={`pill ${r.level === 'likely' ? 'crit' : r.level === 'suspicious' ? 'warnpill' : 'new'}`}>{r.level}</span></td>
              </tr>
            ))}
            {!(clones.rows || []).length && (
              <tr><td colSpan={6} className="emptycell"><p className="muted">No sightings yet — run a scan or start the watch.</p></td></tr>
            )}
            </tbody>
          </table>
          </div>
          {(clones.rows || []).length > 30 && (
            <p className="muted small">Showing top 30 of {clones.rows.length} MACs by score.</p>
          )}
        </section>
        <section className={`card threats${threats.critical ? ' hascrit' : ''}`}>
          <h2><Icon n="shieldAlert" s={18} /> Watchdog{threats.count ? ` (${threats.count})` : ''}</h2>
          {!(threats.threats || []).length && (
            <p className="muted small">No clones, hijacks or identity flips. Lock your devices below so impostors trigger critical alerts.</p>
          )}
          <ul className="threatlist">
            {(threats.threats || []).map((t) => {
              const suspect = (t.holders || []).find((h) => h.suspect) || (t.holders || [])[0];
              return (
                <li key={t.id} className={`threat ${t.sev}`}>
                  <div><b>{t.title}</b><small>{t.desc}</small></div>
                  <div className="tholders">
                    {(t.holders || []).slice(0, 4).map((h) => (
                      <span key={h.ip} className={`mono mini${h.suspect ? ' susp' : ''}`} title={`${h.hostname || ''} ${h.vendor || ''}`.trim()}>
                        {h.suspect && <span className="suspmark">!</span>}{h.ip}
                      </span>
                    ))}
                  </div>
                  <div className="row">
                    <span className={`pill ${t.sev === 'critical' ? 'crit' : 'warnpill'}`}>{t.kind}</span>
                    <div className="spacer" />
                    {suspect && <button className="link" onClick={() => { const d = list.find((x) => x.ip === suspect.ip); if (d) setSelected(d); }}>Profile suspect</button>}
                  </div>
                </li>
              );
            })}
          </ul>
        </section>
        <section className="card">
          <h2><Icon n="shield" s={18} /> Trusted devices ({Object.keys(trusted).length})</h2>
          <p className="muted small">Lock your MACs — anything wearing them elsewhere raises a critical alert.</p>
          <div className="trustform">
            <input value={tMac} onChange={(e) => setTMac(e.target.value)} placeholder="MAC aa:bb:cc:dd:ee:ff" spellCheck={false} className="mono" />
            <input value={tName} onChange={(e) => setTName(e.target.value)} placeholder="Name, e.g. My iPhone" maxLength={80} />
            <input value={tIp} onChange={(e) => setTIp(e.target.value)} placeholder="IP (optional)" spellCheck={false} className="mono" />
            <button className="primary" onClick={addTrusted}>Lock</button>
          </div>
          <ul className="trustlist">
            {Object.entries(trusted).map(([mac, t]) => (
              <li key={mac}>
                <span className="mono">{mac}</span>
                <span>{t.name || '—'}{t.ip ? ` · ${t.ip}` : ''}</span>
                <div className="spacer" />
                <button className="link" onClick={() => removeTrusted(mac)}><Icon n="x" s={14} /></button>
              </li>
            ))}
            {!Object.keys(trusted).length && <li className="muted small">None locked yet.</li>}
          </ul>
        </section>
      </>)}

      {route === 'network' && (<>
        <section className="card netinfo">
          <div className="cardhead">
            <h2><Icon n="globe" s={18} /> Network</h2>
          </div>
          <dl>
            <div><dt>Subnet</dt><dd className="mono">{net.network || '—'}</dd></div>
            <div><dt>This device</dt><dd className="mono">{net.selfIp || '—'}</dd></div>
            <div><dt>Router</dt><dd className="mono">{net.gatewayIp || '—'}{' '}
              <button className="link" onClick={pingGateway}>Ping</button>
              {gwPing && <span className="muted"> · {gwPing}</span>}</dd></div>
            <div><dt>Online / seen</dt><dd>{onlineCount} / {list.length}</dd></div>
          </dl>
          <h2>Access point</h2>
          {ap ? (
            <dl>
              <div><dt>Wi-Fi name</dt><dd>{ap.ssid || '—'}</dd></div>
              <div><dt>AP (BSSID)</dt><dd className="mono">{ap.bssid || '—'}</dd></div>
              {(ap.band || ap.channel) && <div><dt>Radio</dt><dd>{[ap.band, ap.channel && `ch ${ap.channel}`].filter(Boolean).join(' · ')}</dd></div>}
              {ap.signal && <div><dt>Signal</dt><dd><SignalBars signal={ap.signal} /> {ap.signal}</dd></div>}
            </dl>
          ) : (
            <p className="muted">Access-point info unavailable on this machine.</p>
          )}
          <p className="muted small">
            Every access point in range bridges the same subnet here, so the list covers
            all of <span className="mono">{net.network}</span> — no scanner can tell which
            AP a neighbor uses; only the Wi-Fi controller knows that.
          </p>
        </section>
        <WanCard />
      </>)}

      {route === 'activity' && (
        <>
        <section className="card storage-card">
          <div className="cardhead">
            <h2><Icon n="database" s={18} /> Local history</h2>
            <span className="pill new">Local files</span>
          </div>
          <div className="storage-grid">
            <div><b>{storage?.devices ?? '—'}</b><span>known devices</span></div>
            <div><b>{storage?.scanHistory ?? '—'}</b><span>scan records</span></div>
            <div><b>{storage?.retentionDays ?? 4} days</b><span>automatic retention</span></div>
          </div>
          <p className="muted small">Devices, scan history, notes, and trusted MACs are kept as local JSON files in server/data/ for four days, then automatically pruned. No database server needed.</p>
        </section>
        <section className="card activity-card">
          <div className="cardhead">
            <h2><Icon n="clock" s={18} /> Activity</h2>
          </div>
          <ul className="history">
            {history.map((h, i) => (
              <li key={h.id || i}>
                <span className="mono">{h.cidr || 'arp cache'}</span>
                <span>{h.found ?? h.rows?.length ?? 0} up</span>
                <span className="muted small">{h.finishedAt ? ago(h.finishedAt) : ''}</span>
                <span className={`pill ${h.status || (h.arpOnly ? 'arp' : 'done')}`}>{h.status || 'done'}</span>
              </li>
            ))}
            {!history.length && <li className="muted">Nothing yet.</li>}
          </ul>
          <div className="exports">
            {job?.id && (
              <>
                <a href={api.exportUrl(job.id, 'json')} download><Icon n="download" s={15} /> Last scan JSON</a>
                <a href={api.exportUrl(job.id, 'csv')} download><Icon n="download" s={15} /> Last scan CSV</a>
              </>
            )}
            {list.length > 0 && (
              <button className="link" onClick={exportInventory}><Icon n="download" s={15} /> Full inventory CSV</button>
            )}
          </div>
          <p className="muted small">Tip: guest/public Wi-Fi with client isolation blocks discovery — home networks give the best results.</p>
        </section>
        </>
      )}

      {route === 'notifications' && (
        <section className="card notifications-page">
          <div className="cardhead">
            <h2><Icon n="bell" s={18} /> Notifications</h2>
            {(watchAlerts.length > 0 || bannerFor) && (
              <button className="link" onClick={() => { setWatchAlerts([]); setBannerFor(null); }}>Clear all</button>
            )}
          </div>
          <p className="muted small">All scan updates, device arrivals, warnings, and security alerts appear here.</p>
          <div className="notification-list">
            {bannerFor && job?.id === bannerFor && job.newCount > 0 && (
              <div className="banner notification-item" role="status">
                <Icon n="bell" s={20} />
                <span><b>{job.newCount} new device{job.newCount === 1 ? '' : 's'}</b> found in this scan.</span>
                <div className="spacer" />
                <button className="link" onClick={() => { setPresence('all'); setSort('seen'); setBannerFor(null); setRoute('devices'); }}>Review devices</button>
              </div>
            )}
            {watchAlerts.map((a) => (
              <div key={a.key} className="watchalert notification-item" role="alert">
                <Icon n="bell" s={20} />
                <div><b>{a.title || 'New device joined'}</b><small>{a.desc || `${a.vendor || 'Unknown device'}`} · <span className="mono">{a.ip}</span>{a.at ? ` · ${ago(a.at)}` : ''}</small></div>
                <div className="spacer" />
                <button className="link" onClick={() => { const d = list.find((x) => x.ip === a.ip); if (d) setSelected(d); }}>View</button>
                <button className="link" onClick={() => setWatchAlerts((items) => items.filter((x) => x.key !== a.key))}><Icon n="x" s={16} /></button>
              </div>
            ))}
            {threats.threats?.map((t) => (
              <div key={t.id} className={`notification-threat ${t.sev || 'warn'}`}>
                <Icon n="shieldAlert" s={20} />
                <div><b>{t.title}</b><small>{t.desc}</small></div>
                <span className={`pill ${t.sev === 'critical' ? 'crit' : 'warnpill'}`}>{t.kind}</span>
              </div>
            ))}
            {!watchAlerts.length && !bannerFor && !(threats.threats || []).length && (
              <div className="notification-empty"><Icon n="check" s={24} /><b>All clear</b><span className="muted small">There are no active notifications or warnings.</span></div>
            )}
          </div>
        </section>
      )}

      {route === 'tools' && (
        <ToolsView devices={list} gatewayIp={net.gatewayIp} onRouter={() => go('router')} />
      )}

      {route === 'router' && <RouterSecurityView onError={setError} />}

      {selected && (
        <DeviceSheet
          device={selected}
          note={notes[selected.ip]}
          onClose={() => setSelected(null)}
          onNotes={(ip, entry) => setNotes((n) => ({ ...n, [ip]: entry }))}
          onError={setError}
          onToggleFlag={toggleFlag}
          onTrust={trustDevice}
          onPorts={() => {}}
      onIdentified={(ip, fp, kind, os, upnp) => {
        setDevices((ds) => ds.map((d) => (d.ip === ip ? { ...d, fp, type: kind || d.type, os: os || d.os, upnp: upnp || d.upnp } : d)));
        setSelected((s) => (s && s.ip === ip ? { ...s, fp, type: kind || s.type, os: os || s.os, upnp: upnp || s.upnp } : s));
      }}
        />
      )}
      </div>
    </div>
  );
}

const ROUTER_CHECK_ICON = { pass: 'check', warn: 'shieldAlert', fail: 'x', info: 'info' };

function RouterSecurityView({ onError }) {
  const [data, setData] = useState(null);
  const [job, setJob] = useState(null);
  const [jobId, setJobId] = useState(null);
  const [busy, setBusy] = useState(false);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    let stopped = false;
    api.routerSecurity()
      .then((r) => { if (!stopped && r.latest) setData(r.latest); })
      .catch((e) => { if (!stopped) onError(e.message); })
      .finally(() => { if (!stopped) setLoaded(true); });
    return () => { stopped = true; };
  }, [onError]);

  useEffect(() => {
    if (!jobId) return undefined;
    let stopped = false;
    let timer = null;
    const tick = async () => {
      try {
        const next = await api.routerScan(jobId);
        if (stopped) return;
        setJob(next);
        if (next.status === 'done') {
          setData(next.result);
          setJobId(null);
          return;
        }
        if (next.status === 'error') {
          onError(next.error || 'Router scan failed.');
          setJobId(null);
          return;
        }
        timer = setTimeout(tick, 700);
      } catch (e) {
        if (!stopped) {
          onError(e.message);
          setJobId(null);
        }
      }
    };
    tick();
    return () => { stopped = true; if (timer) clearTimeout(timer); };
  }, [jobId, onError]);

  async function start() {
    setBusy(true);
    onError('');
    try {
      const next = await api.startRouterScan();
      setJob(next);
      setJobId(next.id);
    } catch (e) {
      onError(e.message);
    } finally {
      setBusy(false);
    }
  }

  const running = job?.status === 'running';
  const risk = data?.risk;
  const level = risk?.level || 'safe';
  const riskIcon = level === 'safe' ? 'shield' : 'shieldAlert';
  const score = risk?.score || 0;
  const findings = data?.findings || [];
  const checks = data?.checks || [];
  const ports = data?.ports || [];
  const openPorts = ports.filter((p) => p.open);

  return (
    <>
      <section className={`card router-hero risk-${level}`}>
        <div className="cardhead">
          <h2><Icon n="shield" s={18} /> Router security</h2>
          {data && <span className={`pill router-risk ${level}`}>{level}</span>}
        </div>
        <div className="router-hero-body">
          <span className="router-mark"><Icon n={riskIcon} s={32} /></span>
          <div className="router-hero-copy">
            <h3>{risk ? risk.headline : 'Check your router from the LAN'}</h3>
            <p className="muted">
              {risk
                ? risk.summary
                : 'Find the default gateway, check management services, UPnP and NAT-PMP, then match the fingerprint against known router risk patterns.'}
            </p>
            <div className="router-actions">
              <button className="primary btnicon" onClick={start} disabled={busy || running}>
                <Icon n={running ? 'radar' : 'refresh'} s={16} />
                {running ? 'Scanning…' : data ? 'Scan again' : 'Scan router'}
              </button>
              {data?.scannedAt && (
                <span className="muted small">
                  Last scan {fmtTime(data.scannedAt)} · {Math.max(1, Math.round((data.durationMs || 0) / 1000))}s
                </span>
              )}
            </div>
          </div>
          {data && (
            <div className={`risk-dial ${level}`} style={{ '--pct': score }} title={`Risk score ${score} of 100`}>
              <b>{score}</b><small>/ 100</small>
            </div>
          )}
        </div>

        {running && (
          <div className="progress-wrap">
            <div className="progress-meta">
              <span>{job?.phase || 'Scanning router…'}</span>
              <span>{Math.round((job?.progress || 0) * 100)}%</span>
            </div>
            <div className="progress"><div style={{ width: `${Math.round((job?.progress || 0) * 100)}%` }} /></div>
          </div>
        )}

        <div className="router-scope">
          <Icon n="info" s={16} />
          <span className="muted small">
            LAN-side checks only. External/WAN exposure and default admin credentials are not tested.
            {data?.gateway?.interface?.ssid ? ` Connected via ${data.gateway.interface.ssid}.` : ''}
          </span>
        </div>
      </section>

      {!data && !running && (
        <section className="card router-empty">
          <Icon n="radar" s={28} />
          <b>{loaded ? 'No router scan yet' : 'Checking for an earlier scan…'}</b>
          <p className="muted small">The scan is read-only: no router settings are changed and nothing is sent to the internet.</p>
        </section>
      )}

      {data && (
        <>
          <div className="router-dash">
            <section className="card">
              <div className="cardhead">
                <h2><Icon n="shield" s={17} /> Checks</h2>
                <span className="pill">{checks.filter((c) => c.status === 'pass').length}/{checks.length} passed</span>
              </div>
              <ul className="router-checks">
                {checks.map((c) => (
                  <li key={c.id} className={c.status}>
                    <span className="router-check-icon"><Icon n={ROUTER_CHECK_ICON[c.status] || 'info'} s={15} /></span>
                    <div><b>{c.label}</b><small>{c.detail}</small></div>
                  </li>
                ))}
              </ul>
            </section>

            <section className="card">
              <div className="cardhead">
                <h2><Icon n="radar" s={17} /> Gateway</h2>
                <span className="pill">{openPorts.length} open</span>
              </div>
              <dl className="router-info">
                <div><dt>Address</dt><dd className="mono">{data.gateway.ip || '—'}</dd></div>
                <div><dt>MAC</dt><dd className="mono">{data.gateway.mac || 'Not resolved'}</dd></div>
                <div><dt>Vendor</dt><dd>{data.gateway.vendor || 'Unknown'}</dd></div>
                <div><dt>Model</dt><dd>{data.fingerprint?.model || 'Not identified'}</dd></div>
                <div><dt>Interface</dt><dd>{data.gateway.interface?.name || '—'}{data.gateway.interface?.ssid ? ` · ${data.gateway.interface.ssid}` : ''}</dd></div>
                <div><dt>Discovered by</dt><dd>{data.gateway.source || '—'}</dd></div>
              </dl>
              <div className="router-ports">
                {ports.map((p) => (
                  <span key={p.port} className={`router-port ${p.open ? 'open' : ''}`} title={p.open ? `${p.label} is open` : `${p.label} did not answer`}>
                    <b>{p.port}</b><small>{p.label}</small>
                  </span>
                ))}
              </div>
              <div className="router-subgrid">
                <div><small className="muted">UPnP</small><b>{data.upnp?.igd ? 'IGD exposed' : data.upnp?.discovered ? 'Discovery only' : 'Not detected'}</b></div>
                <div><small className="muted">NAT-PMP / PCP</small><b>{data.natpmp?.supported ? data.natpmp.protocol || 'Enabled' : 'Not detected'}</b></div>
              </div>
            </section>
          </div>

          <section className="card">
            <div className="cardhead">
              <h2><Icon n="shieldAlert" s={17} /> Findings</h2>
              <span className={`pill ${findings.length ? 'warnpill' : 'new'}`}>{findings.length || 'None'}</span>
            </div>
            {!findings.length && (
              <div className="router-clear"><Icon n="check" s={22} /><b>No obvious weaknesses found</b><span className="muted small">Keep firmware updated and re-scan after router changes.</span></div>
            )}
            <div className="router-findings">
              {findings.map((f) => (
                <article key={f.id} className={`router-finding ${f.severity}`}>
                  <div className="router-finding-head">
                    <span className={`pill router-sev ${f.severity}`}>{f.severity}</span>
                    <b>{f.title}</b>
                    {f.port ? <span className="pill">{f.port}</span> : null}
                  </div>
                  <p>{f.detail}</p>
                  {f.cves?.length > 0 && (
                    <div className="router-cves">
                      {f.cves.map((cve) => <span key={cve} className="mono mini">{cve}</span>)}
                      <span className="muted small">Fingerprint match · {f.confidence}</span>
                    </div>
                  )}
                  <small className="router-fix"><b>Fix:</b> {f.action}</small>
                </article>
              ))}
            </div>
          </section>

          <div className="router-dash">
            <section className="card">
              <h2><Icon n="wifi" s={17} /> Fingerprint evidence</h2>
              {data.fingerprint?.evidence?.length ? (
                <ul className="evidence mono">{data.fingerprint.evidence.map((e, i) => <li key={i}>{e}</li>)}</ul>
              ) : <p className="muted small">No fingerprint evidence was collected.</p>}
              <div className="router-subgrid">
                <div><small className="muted">HTTP</small><b>{data.fingerprint?.http?.server || 'No server header'}</b></div>
                <div><small className="muted">TLS certificate</small><b>{data.fingerprint?.cert?.subject || 'Not available'}</b></div>
              </div>
            </section>

            <section className="card">
              <h2><Icon n="check" s={17} /> Recommendations</h2>
              <ol className="router-recs">
                {(data.recommendations || []).map((r) => <li key={r}>{r}</li>)}
              </ol>
            </section>
          </div>
        </>
      )}
    </>
  );
}

function fmtBytes(b) {
  if (b === null || b === undefined) return '—';
  if (b < 1024) return `${b} B`;
  if (b < 1048576) return `${(b / 1024).toFixed(1)} KB`;
  if (b < 1073741824) return `${(b / 1048576).toFixed(1)} MB`;
  return `${(b / 1073741824).toFixed(2)} GB`;
}

function fmtRate(bps) {
  if (bps === null || bps === undefined) return '—';
  if (bps < 1000) return `${bps} bps`;
  if (bps < 1000000) return `${(bps / 1000).toFixed(1)} Kbps`;
  return `${(bps / 1000000).toFixed(2)} Mbps`;
}

/* Live top-bar network graph: real router throughput (UPnP IGD) when the
 * router shares it, otherwise live gateway ping latency as a link-quality
 * fallback. Polls every 1.5s; the trace scrolls continuously across a 2-min window. */
/* ECG-style live monitor: a glowing pen sweeps left→right writing the trace,
 * with a blank gap ahead of it like a heart-rate monitor. Canvas + rAF; the
 * trace persists on screen until the sweep wraps. Honors reduced-motion with
 * a static trace. */
const ECG_WINDOW_MS = 120000;
const ECG_POLL_MS = 1500;
const ECG_BASE = '#07131c';

function EcgStatic({ samples, peak, color }) {
  const W = 300;
  const H = 80;
  const P = 6;
  const sp = Math.max(1, peak);
  const pts = samples.map((s, i) => {
    const v = s.v < 0 ? sp : Math.min(Math.max(0, s.v), sp);
    const x = (i / Math.max(1, samples.length - 1)) * W;
    const y = P + (1 - v / sp) * (H - P * 2);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="ecg-static" preserveAspectRatio="none" aria-hidden="true">
      <polyline points={pts} fill="none" stroke={color} strokeWidth="2" />
    </svg>
  );
}

/* Interpolated sample value at time `t` (samples are [{t, v}]). */
function sampleAt(samples, t) {
  if (!samples.length) return 0;
  if (t <= samples[0].t) return samples[0].v;
  for (let i = 1; i < samples.length; i++) {
    if (t <= samples[i].t) {
      const a = samples[i - 1];
      const b = samples[i];
      const f = (t - a.t) / Math.max(1, b.t - a.t);
      return a.v + (b.v - a.v) * f;
    }
  }
  return samples[samples.length - 1].v;
}

function EcgCanvas({ traces, peak }) {
  const canvasRef = useRef(null);
  const liveRef = useRef({ traces, peak });
  useEffect(() => {
    liveRef.current = { traces, peak };
  });

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return undefined;
    const ctx = canvas.getContext('2d');
    let raf = 0;
    let head = null;
    let readerStart = performance.now();
    let lastPhys = performance.now();
    let lastPeak = 0;

    function paintBase(W, H) {
      ctx.save();
      ctx.globalCompositeOperation = 'source-over';
      ctx.fillStyle = ECG_BASE;
      ctx.fillRect(0, 0, W, H);
      ctx.restore();
    }
    function fit() {
      const dpr = window.devicePixelRatio || 1;
      const w = canvas.clientWidth;
      const h = canvas.clientHeight;
      canvas.width = Math.max(1, Math.round(w * dpr));
      canvas.height = Math.max(1, Math.round(h * dpr));
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      paintBase(w, h);
      head = null;
      readerStart = performance.now();
    }
    fit();
    const ro = new ResizeObserver(fit);
    ro.observe(canvas);

    function frame(now) {
      const W = canvas.clientWidth;
      const H = canvas.clientHeight;
      if (!W || !H) {
        raf = requestAnimationFrame(frame);
        return;
      }
      const { traces: trs, peak: pk } = liveRef.current;
      const safePeak = Math.max(1, pk);
      if (Math.abs(safePeak - lastPeak) / Math.max(1, lastPeak) > 0.3) {
        lastPeak = safePeak;
        head = null;
      }
      // Opaque dark base every frame (never white) + crisp grid.
      paintBase(W, H);
      ctx.save();
      ctx.strokeStyle = 'rgba(56,189,248,0.10)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      [20, 40, 60, 80].forEach((pct) => {
        const gy = (H * pct) / 100;
        ctx.moveTo(0, gy);
        ctx.lineTo(W, gy);
      });
      for (let gx = 0; gx <= W; gx += 24) {
        ctx.moveTo(gx, 0);
        ctx.lineTo(gx, H);
      }
      ctx.stroke();
      ctx.restore();
      const yOf = (v) => {
        const eff = v < 0 ? safePeak : Math.min(Math.max(0, v), safePeak);
        return 8 + (1 - eff / safePeak) * (H - 16);
      };
      // Continuous scrolling trace: the last ECG_WINDOW_MS fills the width,
      // newest at the right edge, scrolling left in real time.
      const nowMs = Date.now();
      const from = nowMs - ECG_WINDOW_MS;
      trs.forEach((tr) => {
        const pts = tr.samples.filter((s) => s.t >= from);
        if (!pts.length) return;
        ctx.save();
        ctx.strokeStyle = tr.color;
        ctx.lineWidth = tr.width;
        ctx.lineCap = 'round';
        ctx.lineJoin = 'round';
        ctx.shadowColor = tr.color;
        ctx.shadowBlur = tr.glow;
        ctx.beginPath();
        pts.forEach((s, i) => {
          const px = W - ((nowMs - s.t) / ECG_WINDOW_MS) * W;
          const py = yOf(s.v);
          if (i === 0) ctx.moveTo(px, py);
          else ctx.lineTo(px, py);
        });
        ctx.lineTo(W, yOf(pts[pts.length - 1].v));
        ctx.stroke();
        ctx.restore();
      });
      // Writer nib: loops left→right riding the trace, so the leading end is
      // always moving up-down with the values as it writes across the screen.
      const READER_MS = 9000;
      if (trs[0] && trs[0].samples.length) {
        const rx = (((now - readerStart) / READER_MS) * W) % W;
        const rt = nowMs - ((W - rx) / W) * ECG_WINDOW_MS;
        if (rt >= trs[0].samples[0].t) {
          const target = yOf(sampleAt(trs[0].samples, rt));
          if (!head) head = { y: target, v: 0 };
          const dt = Math.min(0.05, Math.max(0.001, (now - lastPhys) / 1000));
          lastPhys = now;
          const force = (target - head.y) * 170 - head.v * 13;
          head.v += force * dt;
          head.y += head.v * dt;
          ctx.save();
          // Re-ink a short window around the nib: brighter + thicker.
          ctx.strokeStyle = trs[0].color;
          ctx.lineWidth = trs[0].width + 1.2;
          ctx.lineCap = 'round';
          ctx.shadowColor = trs[0].color;
          ctx.shadowBlur = 14;
          ctx.beginPath();
          let started = false;
          trs[0].samples.forEach((s) => {
            if (s.t < from) return;
            const px = W - ((nowMs - s.t) / ECG_WINDOW_MS) * W;
            if (px < rx - 18 || px > rx + 2) return;
            const py = yOf(s.v);
            if (!started) {
              ctx.moveTo(px, py);
              started = true;
            } else {
              ctx.lineTo(px, py);
            }
          });
          ctx.stroke();
          // Nib tick + pulsing glowing dot.
          ctx.strokeStyle = 'rgba(148,197,255,0.25)';
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.moveTo(rx, Math.max(0, head.y - 14));
          ctx.lineTo(rx, Math.min(H, head.y + 14));
          ctx.stroke();
          ctx.fillStyle = trs[0].color;
          ctx.shadowColor = trs[0].color;
          ctx.shadowBlur = 12;
          ctx.beginPath();
          ctx.arc(rx, head.y, 2.2 + Math.sin(now / 320) * 0.6, 0, Math.PI * 2);
          ctx.fill();
          ctx.restore();
        }
      }
      raf = requestAnimationFrame(frame);
    }
    raf = requestAnimationFrame(frame);
    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
    };
  }, []);

  return <canvas ref={canvasRef} className="ecg-canvas" aria-hidden="true" />;
}

function LiveNetPill({ gatewayIp, apiOk }) {
  const [wan, setWan] = useState(null);
  const [downHist, setDownHist] = useState([]);
  const [upHist, setUpHist] = useState([]);
  const [pingMs, setPingMs] = useState(null);
  const [pingHist, setPingHist] = useState([]);
  const [reducedMotion] = useState(
    () => typeof window !== 'undefined' && !!window.matchMedia?.('(prefers-reduced-motion: reduce)').matches,
  );

  useEffect(() => {
    if (!apiOk) return undefined;
    let stop = false;
    async function tick() {
      try {
        const w = await api.wan();
        if (stop) return;
        if (w && w.supported) {
          const t = Date.now();
          setWan(w);
          setDownHist((h) => [...h, { t, v: w.rateDownBps || 0 }].slice(-120));
          setUpHist((h) => [...h, { t, v: w.rateUpBps || 0 }].slice(-120));
          return;
        }
        setWan({ supported: false });
      } catch {
        if (!stop) setWan({ supported: false });
      }
      if (stop || !gatewayIp) return;
      try {
        const r = await api.ping(gatewayIp, 1);
        if (stop) return;
        const ms = r.alive ? r.ms : -1;
        setPingMs(ms);
        setPingHist((h) => [...h, { t: Date.now(), v: ms }].slice(-120));
      } catch { /* keep last reading */ }
    }
    tick();
    const t = setInterval(tick, ECG_POLL_MS);
    return () => { stop = true; clearInterval(t); };
  }, [gatewayIp, apiOk]);

  if (!apiOk) return null;

  if (wan && wan.supported) {
    const peak = Math.max(1, ...downHist.map((s) => s.v), ...upHist.map((s) => s.v));
    const traces = [
      { samples: downHist, color: '#22d3ee', width: 1.5, glow: 6 },
      { samples: upHist, color: '#4ade80', width: 1.25, glow: 4 },
    ];
    return (
      <div className="netgraph ecg" title="Live router throughput via UPnP — updates every 1.5s. See Network tab for totals.">
        <div className="netgraph-head">
          <span className="pulse on" />
          <b>Live throughput</b>
          <span className="legend down">↓ {fmtRate(wan.rateDownBps)}</span>
          <span className="legend up">↑ {fmtRate(wan.rateUpBps)}</span>
          <span className="spacer" />
          <span className="muted small mono">peak {fmtRate(peak)}</span>
        </div>
        <div className="ecg-screen">
          {reducedMotion
            ? <EcgStatic samples={downHist} peak={peak} color="#22d3ee" />
            : <EcgCanvas key="wan" traces={traces} peak={peak} />}
        </div>
      </div>
    );
  }
  if (pingHist.length || pingMs !== null) {
    const lost = pingMs === -1;
    const pos = pingHist.map((s) => s.v).filter((v) => v >= 0);
    const peak = Math.max(1, ...pos, ...(pingHist.some((s) => s.v < 0) ? [Math.max(...pos, 1) * 1.25] : []));
    return (
      <div className="netgraph ecg lat" title={gatewayIp ? `Router hides throughput stats (UPnP off) — showing live ping to router ${gatewayIp} instead, every 1.5s.` : 'Router hides throughput stats (UPnP off) — showing link latency instead.'}>
        <div className="netgraph-head">
          <span className={`pulse ${!lost && pingMs !== null ? 'on' : ''}`} />
          <b>Link latency{gatewayIp ? ` · ${gatewayIp}` : ''}</b>
          <span className="legend lat mono">{lost ? 'no reply' : pingMs === null ? 'ping…' : `${pingMs} ms`}</span>
          <span className="spacer" />
          <span className="muted small mono">peak {Math.round(peak)} ms</span>
        </div>
        <div className="ecg-screen">
          {reducedMotion
            ? <EcgStatic samples={pingHist} peak={peak} color="#fb923c" />
            : <EcgCanvas key="ping" traces={[{ samples: pingHist, color: '#fb923c', width: 1.5, glow: 6 }]} peak={peak} />}
        </div>
      </div>
    );
  }
  return <div className="netgraph dim mono">Checking network…</div>;
}

function WanCard() {
  const [wan, setWan] = useState(null);
  const [hist, setHist] = useState([]);
  useEffect(() => {
    let stop = false;
    async function tick() {
      try {
        const w = await api.wan();
        if (stop) return;
        setWan(w);
        if (w.supported) setHist((h) => [...h, w.rateDownBps || 0].slice(-36));
      } catch { /* router silent */ }
    }
    tick();
    const t = setInterval(tick, 5000);
    return () => { stop = true; clearInterval(t); };
  }, []);

  const max = Math.max(1, ...hist);
  const pts = hist.map((v, i) => `${(i / Math.max(1, hist.length - 1)) * 100},${28 - (v / max) * 26}`).join(' ');

  return (
    <section className="card">
      <h2><Icon n="activity" s={18} /> Internet activity</h2>
      {!wan && <p className="muted">Checking router stats…</p>}
      {wan && !wan.supported && (
        <p className="muted small">Router doesn't share traffic stats (UPnP is off or unsupported). Per-device usage isn't exposed by home routers at all — only managed gear reports that.</p>
      )}
      {wan && wan.supported && (
        <>
          <div className="wanrates">
            <div><small className="muted">DOWN</small><b>↓ {fmtRate(wan.rateDownBps)}</b></div>
            <div><small className="muted">UP</small><b>↑ {fmtRate(wan.rateUpBps)}</b></div>
          </div>
          <svg viewBox="0 0 100 30" className="spark" preserveAspectRatio="none" aria-hidden="true">
            <polyline points={pts} />
          </svg>
          <p className="muted small">Total this session: ↓ {fmtBytes(wan.downBytes)} · ↑ {fmtBytes(wan.upBytes)}</p>
        </>
      )}
    </section>
  );
}

function DeviceSheet({ device, note, onClose, onNotes, onError, onToggleFlag, onPorts, onIdentified, onTrust }) {
  const [ping, setPing] = useState(null);
  const [ports, setPorts] = useState(null);
  const [busy, setBusy] = useState('');
  const [name, setName] = useState(note?.name || '');
  const [text, setText] = useState(note?.notes || '');
  const [selType, setSelType] = useState(note?.type || '');
  const [fpBusy, setFpBusy] = useState('');
  const [ai, setAi] = useState(null);
  const [stab, setStab] = useState(null);

  useEffect(() => {
    setPing(null);
    setPorts(null);
    setName(note?.name || '');
    setText(note?.notes || '');
    setSelType(note?.type || '');
    setFpBusy('');
    setAi(null);
    setStab(null);
  }, [device.ip]); // eslint-disable-line react-hooks/exhaustive-deps

  const meta = TYPE_META[typeOf(device)];

  async function doPing() {
    setBusy('ping');
    try { setPing(await api.ping(device.ip, 1)); }
    catch (e) { onError(e.message); }
    finally { setBusy(''); }
  }

  async function doPorts() {
    setBusy('ports');
    try {
      const r = await api.portScan(device.ip);
      setPorts(r);
      onPorts(device.ip, r);
    } catch (e) { onError(e.message); }
    finally { setBusy(''); }
  }

  async function doStability() {
    setBusy('stab');
    try { setStab(await api.stability(device.ip, 6)); }
    catch (e) { onError(e.message); }
    finally { setBusy(''); }
  }

  async function save() {
    try {
      const entry = await api.saveNote(device.ip, {
        name, notes: text, type: selType || null,
        favorite: !!note?.favorite, hidden: !!note?.hidden,
      });
      onNotes(device.ip, entry);
    } catch (e) { onError(e.message); }
  }

  async function doIdentify() {
    setFpBusy('fp');
    setAi(null);
    try {
      const r = await api.identify(device.ip);
      onIdentified(device.ip, { model: r.verdict.model, kind: r.verdict.kind, confidence: r.verdict.confidence, evidence: r.verdict.evidence, at: new Date().toISOString() }, r.verdict.kind, r.os || null, r.upnp || null);
    } catch (e) { onError(e.message); }
    finally { setFpBusy(''); }
  }

  async function doAiGuess() {
    setFpBusy('ai');
    try {
      const r = await api.aiGuess(device.ip);
      setAi({ ok: true, guess: r.ai.guess, source: r.ai.source });
    } catch (e) {
      setAi({ ok: false, hint: e.data?.hint || e.message });
    } finally { setFpBusy(''); }
  }

  function copy(v) {
    try { navigator.clipboard.writeText(v); } catch { /* clipboard unavailable */ }
  }

  return (
    <div className="sheet-backdrop" onClick={onClose}>
      <div className="sheet" onClick={(e) => e.stopPropagation()}>
        <button className="sheet-close" onClick={onClose}><Icon n="x" s={16} /></button>
        <div className="sheet-head">
          <span className="dev-icon big"><DeviceIcon type={typeOf(device)} s={34} /></span>
          <div>
            <h2>{displayName(device, note)}</h2>
            <p className="muted">
              <span className={`statusdot inline ${device.online ? 'on' : ''}`} /> {device.online ? 'Online' : `Offline · seen ${ago(device.lastSeen)}`}
            </p>
          </div>
        </div>
        <div className="tagrow">
          <span className="pill type">{meta.label}</span>
          {device.isSelf && <span className="tag self">THIS DEVICE</span>}
          {device.isGateway && <span className="tag gw">ROUTER</span>}
          {isFresh(device) && <span className="tag new">NEW</span>}
          {device.mac && isRandomizedMac(device.mac) && <span className="tag rand">PRIVATE MAC</span>}
          {note?.type && <span className="tag manual">TAGGED</span>}
        </div>
        <dl className="sheet-info">
          <div><dt>IP address</dt><dd className="mono">{device.ip} <button className="link iconlink" onClick={() => copy(device.ip)} title="Copy IP"><Icon n="copy" s={14} /></button></dd></div>
          <div><dt>MAC address</dt><dd className="mono">{device.mac || <span className="muted">Not resolved — rescan to retry</span>} {device.mac && <button className="link iconlink" onClick={() => copy(device.mac)} title="Copy MAC"><Icon n="copy" s={14} /></button>}</dd></div>
          <div><dt>Vendor</dt><dd>{device.vendor || 'Unknown'}</dd></div>
          <div><dt>Hostname</dt><dd>{cleanName(device.hostname) || device.hostname || '—'}</dd></div>
          <div><dt>First seen</dt><dd>{fmtTime(device.firstSeen)}</dd></div>
          <div><dt>Last seen</dt><dd>{fmtTime(device.lastSeen)} ({ago(device.lastSeen)})</dd></div>
          <div><dt>Services</dt><dd>
            {(device.services || []).length
              ? (device.services || []).map((s) => <span key={s.port} className="pill type svc">{s.label} :{s.port}</span>)
              : <span className="muted">None detected — scan with service detection on.</span>}
          </dd></div>
          <div><dt>Operating system</dt><dd>
            {device.os?.name
              ? <span>
                  <b>{device.os.name}</b>{device.os.version ? ` · ${device.os.version}` : ''}
                  {device.os.confidence && <span className={`pill conf ${device.os.confidence}`}>{device.os.confidence} confidence</span>}
                </span>
              : <span className="muted">Not detected — try Identify</span>}
          </dd></div>
          <div><dt>Model/Name</dt><dd>
            {device.upnp?.friendlyName || device.upnp?.modelName || device.fp?.model
              ? <span>
                  {device.upnp?.friendlyName && <><b>{device.upnp.friendlyName}</b><br/></>}
                  {device.upnp?.modelName && <span className="muted small">{device.upnp.modelName}</span>}
                  {!device.upnp?.friendlyName && !device.upnp?.modelName && device.fp?.model && <span>{device.fp.model}</span>}
                </span>
              : <span className="muted">Not fingerprinted yet</span>}
          </dd></div>
        </dl>
        {device.mac && isRandomizedMac(device.mac) && (
          <div className="filterwarn">
            <b><Icon n="shieldAlert" s={15} /> Private address — no internet on MAC-filtered Wi-Fi</b>
            <p className="muted small">
              This device is using a rotating private MAC, which is not on the network's
              allowlist. Turn the random MAC <b>off</b> so it joins with its real hardware address:
            </p>
            <ul className="muted small">
              <li><b>iPhone/iPad:</b> Settings → Wi-Fi → ⓘ next to the network → turn <b>off</b> Private Wi-Fi Address (rejoin afterwards).</li>
              <li><b>Android:</b> Settings → Network &amp; internet → Wi-Fi → ⚙ on the network → Privacy → <b>Use device MAC</b>.</li>
              <li><b>Windows:</b> Settings → Network &amp; internet → Wi-Fi → turn <b>off</b> Random hardware addresses for this network.</li>
            </ul>
            <p className="muted small">After that, rescan — the real MAC appears and can be added to the allowlist / locked under Trust MAC.</p>
          </div>
        )}
        <div className="fpbox">
          <div className="row">
            <button className="ghost btnicon" disabled={fpBusy === 'fp'} onClick={doIdentify}>
              <Icon n="radar" s={16} /> {fpBusy === 'fp' ? 'Identifying…' : device.fp ? 'Re-identify' : 'Identify device'}
            </button>
            <button className="ghost btnicon" disabled={fpBusy === 'ai'} onClick={doAiGuess} title="Ask a local/cloud LLM for a second opinion">
              <Icon n="info" s={16} /> {fpBusy === 'ai' ? 'Asking…' : 'AI guess'}
            </button>
            {device.fp && <span className={`pill conf ${device.fp.confidence}`}>{device.fp.confidence} confidence</span>}
          </div>
          {(device.os?.evidence || []).length > 0 && (
            <ul className="evidence mono os-evidence">
              {(device.os.evidence || []).map((e, i) => <li key={i}>{e}</li>)}
            </ul>
          )}
          {device.fp && (device.fp.evidence || []).length > 0 && (
            <ul className="evidence mono">
              {(device.fp.evidence || []).map((e, i) => <li key={i}>{e}</li>)}
            </ul>
          )}
          {ai && ai.ok && <p className="airesult">AI ({ai.source}): <b>{ai.guess}</b></p>}
          {ai && !ai.ok && <p className="muted small">{ai.hint}</p>}
        </div>
        <div className="actions">
          <button className="ghost btnicon" disabled={busy === 'ping'} onClick={doPing}><Icon n="activity" s={16} /> {busy === 'ping' ? 'Pinging…' : 'Ping'}</button>
          <button className="ghost btnicon" disabled={busy === 'ports'} onClick={doPorts}><Icon n="search" s={16} /> {busy === 'ports' ? 'Scanning…' : 'Ports'}</button>
          <button className="ghost btnicon" disabled={busy === 'stab'} onClick={doStability}><Icon n="clock" s={16} /> {busy === 'stab' ? 'Probing…' : 'Stability'}</button>
          <button className="ghost btnicon" onClick={() => onTrust(device)}><Icon n="shield" s={16} /> Trust MAC</button>
          <button className={`ghost btnicon ${note?.favorite ? 'is-fav' : ''}`} onClick={() => onToggleFlag(device.ip, 'favorite')}><Icon n="star" s={16} /> {note?.favorite ? 'Favorited' : 'Favorite'}</button>
          <button className="ghost btnicon" onClick={() => onToggleFlag(device.ip, 'hidden')}><Icon n={note?.hidden ? 'eye' : 'eyeOff'} s={16} /> {note?.hidden ? 'Unhide' : 'Hide'}</button>
        </div>
        {ping && <p className={`result ${ping.alive ? 'up' : 'down'}`}><span className={`statusdot inline ${ping.alive ? 'on' : ''}`} />{ping.alive ? ` alive · ${ping.ms} ms` : ' no reply right now'}</p>}
        {stab && (
          <div className="ports">
            <b>Stability — {stab.sent} probes</b>
            <p className={stab.unstable ? 'result down' : 'result up'}>
              {stab.unstable ? 'Unstable link — possible contention' : 'Link looks stable'}
            </p>
            <p className="mono small">loss {stab.lossPct}% · min {stab.minMs ?? '—'}ms · avg {stab.avgMs ?? '—'}ms · max {stab.maxMs ?? '—'}ms · jitter {stab.jitterMs}ms</p>
          </div>
        )}
        {ports && (
          <div className="ports nmap">
            <b>PORT&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;STATE&nbsp;&nbsp;SERVICE</b>
            <table>
              <tbody>
                {ports.open.map((p) => (
                  <tr key={p.port}>
                    <td className="mono">{p.port}/tcp</td>
                    <td className="open">open</td>
                    <td>{portName(p.port).replace(/^\d+\s+/, '')}</td>
                    <td className="muted">{p.ms}ms</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {ports.all && <p className="muted small">{ports.all.length - ports.open.length} closed ports not shown</p>}
            {!ports.open.length && <p className="muted">No open ports among the common set.</p>}
          </div>
        )}
        <div className="notes">
          <label>Display name<input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Living-room TV" maxLength={80} /></label>
          <label>Device type (tag)
            <select value={selType} onChange={(e) => setSelType(e.target.value)}>
              <option value="">Auto-detect ({TYPE_META[typeOf(device)]?.label || 'Device'})</option>
              {Object.entries(TYPE_META).filter(([k]) => k !== 'unknown').map(([k, m]) => (
                <option key={k} value={k}>{m.label}</option>
              ))}
            </select>
          </label>
          <label>Notes<textarea value={text} onChange={(e) => setText(e.target.value)} placeholder="Anything worth remembering…" rows={3} maxLength={1000} /></label>
          <button className="primary" onClick={save}>Save</button>
        </div>
      </div>
    </div>
  );
}

function portName(port) {
  const known = { 21: '21 FTP', 22: '22 SSH', 23: '23 Telnet', 25: '25 SMTP', 53: '53 DNS', 80: '80 HTTP', 110: '110 POP3', 135: '135 RPC', 139: '139 NetBIOS', 143: '143 IMAP', 443: '443 HTTPS', 445: '445 SMB', 993: '993 IMAPS', 995: '995 POP3S', 1723: '1723 PPTP', 3306: '3306 MySQL', 3389: '3389 RDP', 5900: '5900 VNC', 8080: '8080 HTTP-alt', 8443: '8443 HTTPS-alt' };
  return known[port] || `Port ${port}`;
}
