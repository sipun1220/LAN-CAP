/* Tiny fetch wrapper for the scanner API. Same-origin: Vite proxies
 * /api -> localhost:5174 in dev; Express serves ../client/dist in prod. */
async function req(path, options = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.error || `Request failed (${res.status})`);
    err.data = data;
    throw err;
  }
  return data;
}

export const api = {
  health: () => req('/api/health'),
  interfaces: () => req('/api/interfaces'),
  arp: () => req('/api/arp'),
  startScan: (body) => req('/api/scans', { method: 'POST', body: JSON.stringify(body) }),
  getScan: (id) => req(`/api/scans/${id}`),
  cancelScan: (id) => req(`/api/scans/${id}`, { method: 'DELETE' }),
  listScans: () => req('/api/scans'),
  storage: () => req('/api/storage'),
  ping: (ip, timeout) => req('/api/ping', { method: 'POST', body: JSON.stringify({ ip, timeout }) }),
  portScan: (ip, ports) => req('/api/ports', { method: 'POST', body: JSON.stringify({ ip, ports }) }),
  vendor: (mac) => req(`/api/vendor/${encodeURIComponent(mac)}`),
  notes: () => req('/api/notes'),
  devices: () => req('/api/devices'),
  watch: () => req('/api/watch'),
  startWatch: (intervalSec) => req('/api/watch', { method: 'POST', body: JSON.stringify({ intervalSec }) }),
  stopWatch: () => req('/api/watch', { method: 'DELETE' }),
  identify: (ip) => req('/api/identify', { method: 'POST', body: JSON.stringify({ ip }) }),
  aiGuess: (ip) => req('/api/ai-guess', { method: 'POST', body: JSON.stringify({ ip }) }),
  aiStatus: () => req('/api/ai-status'),
  wan: () => req('/api/wan'),
  threats: () => req('/api/threats'),
  clones: () => req('/api/clones'),
  trusted: () => req('/api/trusted'),
  addTrusted: (body) => req('/api/trusted', { method: 'POST', body: JSON.stringify(body) }),
  removeTrusted: (mac) => req(`/api/trusted/${encodeURIComponent(mac)}`, { method: 'DELETE' }),
  stability: (ip, count) => req('/api/stability', { method: 'POST', body: JSON.stringify({ ip, count }) }),
  routerSecurity: () => req('/api/router-security'),
  startRouterScan: (ip) => req('/api/router-security/scan', { method: 'POST', body: JSON.stringify({ ip: ip || null }) }),
  routerScan: (id) => req(`/api/router-security/scan/${encodeURIComponent(id)}`),
  toolsHealth: () => req('/api/tools/health'),
  toolsPing: (host, count, timeoutMs) => req('/api/tools/ping', { method: 'POST', body: JSON.stringify({ host, count, timeoutMs }) }),
  toolsTraceroute: (host, maxHops) => req('/api/tools/traceroute', { method: 'POST', body: JSON.stringify({ host, maxHops }) }),
  dnsBenchmark: (domain) => req('/api/tools/dns-benchmark', { method: 'POST', body: JSON.stringify({ domain }) }),
  dnsLookup: (host) => req('/api/tools/dns-lookup', { method: 'POST', body: JSON.stringify({ host }) }),
  toolsWifi: () => req('/api/tools/wifi'),
  toolsDhcp: () => req('/api/tools/dhcp'),
  hiddenCameras: () => req('/api/tools/hidden-cameras'),
  startSpeedTest: () => req('/api/speedtest', { method: 'POST' }),
  getSpeedTest: (id) => req(`/api/speedtest/${encodeURIComponent(id)}`),
  cancelSpeedTest: (id) => req(`/api/speedtest/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  saveNote: (ip, body) => req(`/api/notes/${ip}`, { method: 'PUT', body: JSON.stringify(body) }),
  exportUrl: (id, format) => `/api/scans/${id}/export?format=${format}`,
};

/* Subscribe to a scan via SSE with polling fallback. Returns an unsubscribe fn. */
export function subscribeScan(id, onUpdate) {
  let stopped = false;
  let es = null;
  let timer = null;
  const poll = async () => {
    if (stopped) return;
    try {
      onUpdate(await api.getScan(id));
    } catch { /* keep polling until terminal or unsub */ }
  };
  try {
    es = new EventSource(`/api/scans/${id}/events`);
    es.onmessage = (e) => {
      try {
        onUpdate(JSON.parse(e.data));
      } catch { /* ignore */ }
    };
    es.onerror = () => {
      // SSE failed (proxy hiccup?) — fall back to polling.
      try { es.close(); } catch { /* noop */ }
      es = null;
      if (!stopped && !timer) timer = setInterval(poll, 1000);
    };
  } catch {
    timer = setInterval(poll, 1000);
  }
  return () => {
    stopped = true;
    try { es?.close(); } catch { /* noop */ }
    if (timer) clearInterval(timer);
  };
}
