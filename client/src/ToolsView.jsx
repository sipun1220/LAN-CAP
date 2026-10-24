import { useEffect, useRef, useState } from 'react';
import { api } from './api.js';
import { Icon, SignalBars } from './icons.jsx';

const PORT_LABELS = {
  21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
  110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS',
  445: 'SMB', 554: 'RTSP', 631: 'IPP', 993: 'IMAPS', 995: 'POP3S',
  1723: 'PPTP', 3306: 'MySQL', 3389: 'RDP', 5900: 'VNC', 7547: 'TR-069',
  8000: 'HTTP alt', 8080: 'HTTP alt', 8081: 'HTTP alt', 8291: 'MikroTik',
  8443: 'HTTPS alt', 8554: 'RTSP alt', 8888: 'HTTP alt', 9100: 'JetDirect',
};

const PORT_PRESETS = {
  quick: [21, 22, 23, 53, 80, 443, 445, 3389, 8080, 8443],
  common: [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 554, 631, 993, 995, 1723, 3306, 3389, 5900, 7547, 8000, 8080, 8081, 8291, 8443, 8554, 8888, 9100],
  web: [80, 443, 8000, 8008, 8080, 8081, 8088, 8443, 8888],
  cameras: [80, 443, 554, 8000, 8080, 8081, 8443, 8554, 9000, 34567],
};

const TOOL_CARDS = [
  ['health', 'Run health check', 'API, LAN, gateway, DNS, and storage readiness', 'activity'],
  ['speed', 'Run speed test', 'Measure latency, download, and upload performance', 'zap'],
  ['dns-benchmark', 'DNS benchmark', 'Compare resolver response times', 'globe'],
  ['ping', 'Ping a target', 'Check reachability, packet loss, and jitter', 'radar'],
  ['traceroute', 'Start traceroute', 'Trace every network hop to a target', 'topo'],
  ['dns-lookup', 'DNS lookup', 'Resolve addresses and common DNS records', 'search'],
  ['dhcp', 'DHCP recovery', 'Review leases and copy recovery commands', 'refresh'],
  ['wifi', 'Wi-Fi scanner', 'List nearby wireless networks and signal strength', 'wifi'],
];

const TOOL_TITLES = {
  health: 'Network health',
  speed: 'Speed test',
  'dns-benchmark': 'DNS benchmark',
  ping: 'Ping',
  traceroute: 'Traceroute',
  'dns-lookup': 'DNS lookup',
  dhcp: 'DHCP recovery',
  wifi: 'Wi-Fi scanner',
  'open-ports': 'Open port scan',
  'hidden-cameras': 'Camera discovery',
};

function fmtRate(bps) {
  if (bps === null || bps === undefined || !Number.isFinite(Number(bps))) return '-';
  const value = Number(bps);
  if (value >= 1e9) return `${(value / 1e9).toFixed(2)} Gbps`;
  if (value >= 1e6) return `${(value / 1e6).toFixed(1)} Mbps`;
  if (value >= 1e3) return `${(value / 1e3).toFixed(1)} Kbps`;
  return `${value.toFixed(0)} bps`;
}

function fmtMs(value) {
  return value === null || value === undefined ? '-' : `${Number(value).toFixed(1)} ms`;
}

function fmtDate(value) {
  if (!value) return '-';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

function errorText(error) {
  return error && error.message ? error.message : 'Request failed';
}

function useAutoRun(run) {
  const ref = useRef(run);
  useEffect(() => {
    ref.current = run;
  });
  useEffect(() => {
    const timer = setTimeout(() => ref.current(), 0);
    return () => clearTimeout(timer);
  }, []);
}

function Loading({ label = 'Working...' }) {
  return <div className="tool-loading"><span className="spinner" /><span>{label}</span></div>;
}

function ToolError({ error }) {
  if (!error) return null;
  return <div className="tool-error" role="alert"><Icon n="shieldAlert" s={18} /><span>{error}</span></div>;
}

function Metric({ label, value, hint }) {
  return (
    <div className="tool-metric">
      <span>{label}</span>
      <b>{value}</b>
      {hint ? <small>{hint}</small> : null}
    </div>
  );
}

function Empty({ children }) {
  return <div className="tool-empty"><Icon n="info" s={20} /><span>{children}</span></div>;
}

function HealthTool() {
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const run = async () => {
    setBusy(true);
    setError('');
    try {
      setData(await api.toolsHealth());
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };
  useAutoRun(run);
  return (
    <div className="tool-body">
      <div className="tool-actions">
        <button className="btn primary" onClick={run} disabled={busy}>
          <Icon n="refresh" s={16} /> {busy ? 'Checking...' : 'Run again'}
        </button>
        {data ? <span className={`pill ${data.ok ? 'new' : 'warnpill'}`}>{data.ok ? 'All checks passed' : 'Attention needed'}</span> : null}
      </div>
      <ToolError error={error} />
      {busy && !data ? <Loading label="Checking the local network..." /> : null}
      {data ? (
        <>
          <div className="tool-metrics">
            <Metric label="Gateway" value={data.gateway || '-'} />
            <Metric label="Checks" value={`${data.counts.pass || 0} pass`} hint={`${data.counts.warn || 0} warn, ${data.counts.fail || 0} fail`} />
            <Metric label="Elapsed" value={`${data.elapsedMs} ms`} />
          </div>
          <div className="check-list">
            {data.checks.map((check) => (
              <div key={check.id} className={`check-row ${check.status}`}>
                <span className="check-mark"><Icon n={check.status === 'pass' ? 'check' : check.status === 'fail' ? 'x' : 'info'} s={16} /></span>
                <div><b>{check.label}</b><small>{check.detail}</small></div>
                <span className="muted small">{check.ms ? `${check.ms} ms` : ''}</span>
              </div>
            ))}
          </div>
        </>
      ) : null}
    </div>
  );
}

function niceGaugeMax(bps) {
  const steps = [10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 25000, 50000, 100000];
  const mbps = Math.max(0, Number(bps) || 0) / 1e6;
  return steps.find((step) => step >= Math.max(10, mbps * 1.15)) || 100000;
}

function speedReadout(bps) {
  const value = Math.max(0, Number(bps) || 0);
  if (value >= 1e9) return { value: (value / 1e9).toFixed(2), unit: 'Gbps' };
  if (value >= 1e6) return { value: (value / 1e6).toFixed(value < 1e7 ? 2 : 1), unit: 'Mbps' };
  if (value >= 1e3) return { value: (value / 1e3).toFixed(1), unit: 'Kbps' };
  return { value: value.toFixed(0), unit: 'bps' };
}

function gaugePoint(angle, radius) {
  const rad = (angle * Math.PI) / 180;
  return [130 + Math.cos(rad) * radius, 100 + Math.sin(rad) * radius];
}

function gaugeTickLabel(value) {
  if (value >= 1000) return `${(value / 1000).toFixed(value >= 10000 ? 0 : 1)}G`;
  if (value < 1) return value.toFixed(1);
  return String(Math.round(value));
}

function SpeedGauge({ bps, peakBps, label, phase }) {
  const max = niceGaugeMax(peakBps);
  const mbps = Math.max(0, Number(bps) || 0) / 1e6;
  const fraction = Math.min(1, mbps / max);
  const angle = 135 + fraction * 270;
  const [sx, sy] = gaugePoint(135, 88);
  const [ex, ey] = gaugePoint(405, 88);
  const arc = `M ${sx} ${sy} A 88 88 0 1 1 ${ex} ${ey}`;
  const readout = speedReadout(bps);
  const ticks = Array.from({ length: 41 }, (_, i) => {
    const tickAngle = 135 + (i / 40) * 270;
    const major = i % 5 === 0;
    const [x1, y1] = gaugePoint(tickAngle, 88);
    const [x2, y2] = gaugePoint(tickAngle, major ? 76 : 81);
    return { i, major, x1, y1, x2, y2 };
  });
  const labels = [0, 10, 20, 30, 40].map((i) => {
    const value = (max * i) / 40;
    const [x, y] = gaugePoint(135 + (i / 40) * 270, 62);
    return { i, value, x, y };
  });
  return (
    <div className="speedometer">
      <svg className="speed-gauge-svg" viewBox="0 0 260 182" role="img" aria-label={`${label}: ${readout.value} ${readout.unit}`}>
        <defs>
          <linearGradient id="gaugeGlow" x1="0" y1="1" x2="1" y2="0">
            <stop offset="0%" stopColor="#22d3ee" />
            <stop offset="62%" stopColor="#0b9bd8" />
            <stop offset="100%" stopColor="#8b5cf6" />
          </linearGradient>
        </defs>
        <path d={arc} pathLength="100" className="speed-gauge-arc" />
        <path d={arc} pathLength="100" className="speed-gauge-arc-progress" strokeDasharray={`${fraction * 100} 100`} />
        {ticks.map((tick) => (
          <line
            key={tick.i}
            x1={tick.x1}
            y1={tick.y1}
            x2={tick.x2}
            y2={tick.y2}
            className={`speed-gauge-tick${tick.major ? ' major' : ''}`}
          />
        ))}
        {labels.map((item) => (
          <text key={item.i} x={item.x} y={item.y} className="speed-gauge-label" textAnchor="middle" dominantBaseline="middle">
            {gaugeTickLabel(item.value)}
          </text>
        ))}
        <g className="speed-gauge-needle" transform={`rotate(${angle} 130 100)`}>
          <line x1="130" y1="100" x2="202" y2="100" stroke="url(#gaugeGlow)" strokeWidth="4" strokeLinecap="round" />
        </g>
        <circle cx="130" cy="100" r="7" className="speed-gauge-needle-pivot" />
        <circle cx="130" cy="100" r="2.5" fill="#fff" opacity="0.8" />
      </svg>
      <div className="speed-gauge-center">
        <div className="speed-gauge-readout">{readout.value}</div>
        <div className="speed-gauge-unit">{readout.unit}</div>
        <div className="speed-gauge-sub">{label}</div>
      </div>
      <div className="speed-gauge-head">
        <span>{phase}</span>
        <span className="speed-gauge-phase">0 - {gaugeTickLabel(max)}</span>
      </div>
    </div>
  );
}

function SpeedTool() {
  const [job, setJob] = useState(null);
  const [jobId, setJobId] = useState(null);
  const [error, setError] = useState('');
  const [mode, setMode] = useState('download');
  useEffect(() => {
    if (!jobId) return undefined;
    let stopped = false;
    let timer = null;
    const poll = async () => {
      try {
        const next = await api.getSpeedTest(jobId);
        if (stopped) return;
        setJob(next);
        if (next.status !== 'running' && timer) {
          clearInterval(timer);
          timer = null;
        }
      } catch (e) {
        if (!stopped) setError(errorText(e));
      }
    };
    poll();
    timer = setInterval(poll, 700);
    return () => {
      stopped = true;
      if (timer) clearInterval(timer);
    };
  }, [jobId]);
  const start = async () => {
    setError('');
    setJob(null);
    try {
      const created = await api.startSpeedTest();
      setJob(created);
      setJobId(created.id);
    } catch (e) {
      setError(errorText(e));
    }
  };
  const cancel = async () => {
    if (!jobId) return;
    try {
      await api.cancelSpeedTest(jobId);
    } catch (e) {
      setError(errorText(e));
    }
  };
  const running = job && job.status === 'running';
  const done = job && job.status === 'done';
  const phaseLabel = running
    ? job.phase === 'download' ? 'Live download'
      : job.phase === 'upload' ? 'Live upload'
        : job.phase === 'latency' ? 'Measuring latency'
          : job.phase === 'meta' ? 'Finishing'
            : 'Starting...'
    : done ? (mode === 'upload' ? 'Upload result' : 'Download result') : 'Ready';
  const gaugeBps = running
    ? (job.phase === 'upload' ? job.liveBps : job.phase === 'download' ? job.liveBps : job.phase === 'meta' ? job.upload?.bps || 0 : 0)
    : done ? (mode === 'upload' ? job.upload?.bps : job.download?.bps) : 0;
  const peakBps = [
    done ? job.download?.bps : null,
    done ? job.upload?.bps : null,
    running ? job.liveBps : null,
  ].filter((v) => v && Number.isFinite(v) && v > 0);
  const gaugeMaxBase = peakBps.length ? Math.max(...peakBps) : 1;
  const downloadValue = job?.download?.bps ?? (running && job.phase === 'download' ? job.liveBps : null);
  const uploadValue = job?.upload?.bps ?? (running && job.phase === 'upload' ? job.liveBps : null);
  return (
    <div className="tool-body">
      <div className="tool-actions">
        <button className="btn primary" onClick={start} disabled={running}>
          <Icon n="zap" s={16} /> {running ? 'Test running' : job ? 'Test again' : 'Start speed test'}
        </button>
        {running ? <button className="btn ghost" onClick={cancel}><Icon n="stop" s={16} /> Cancel</button> : null}
        <span className="muted small">Measures latency, download, and upload in sequence.</span>
      </div>
      <ToolError error={error || job?.error} />
      <div className="speed-board">
        <div className="speed-gauge-card">
          <div className="speed-gauge-head">
            <span>Ookla-style meter</span>
            <span className="speed-gauge-phase">{phaseLabel}</span>
          </div>
          <SpeedGauge bps={gaugeBps} peakBps={gaugeMaxBase} label={running ? (job.phase === 'upload' ? 'Upload (live)' : job.phase === 'download' ? 'Download (live)' : 'Stabilizing') : mode === 'upload' ? 'Upload' : 'Download'} phase={running ? `${Math.round((job.progress || 0) * 100)}% complete` : done ? 'Complete' : 'Idle'} />
          {running ? (
            <div className="speed-progress">
              <div className="speed-progress-head"><b>{phaseLabel}</b><span>{Math.round((job.progress || 0) * 100)}%</span></div>
              <div className="progress-track"><span style={{ width: `${Math.round((job.progress || 0) * 100)}%` }} /></div>
            </div>
          ) : null}
          {done ? (
            <div className="gauge-mode-tabs">
              <button className={`btn ${mode === 'download' ? 'primary' : 'ghost'}`} onClick={() => setMode('download')} disabled={!job.download?.bps && job.download?.bps !== 0}>
                <Icon n="arrow-down" s={16} /> Download
              </button>
              <button className={`btn ${mode === 'upload' ? 'primary' : 'ghost'}`} onClick={() => setMode('upload')} disabled={!job.upload?.bps && job.upload?.bps !== 0}>
                <Icon n="arrow-up" s={16} /> Upload
              </button>
            </div>
          ) : null}
        </div>
        <div className="speed-side">
          <div className="tool-metrics speed-metrics">
            <Metric label="Download" value={fmtRate(downloadValue)} hint={done && job.download?.seconds ? `${job.download.seconds}s sample` : running && job.phase === 'download' ? 'Live' : ''} />
            <Metric label="Upload" value={fmtRate(uploadValue)} hint={done && job.upload?.seconds ? `${job.upload.seconds}s sample` : running && job.phase === 'upload' ? 'Live' : ''} />
            <Metric label="Latency" value={fmtMs(job?.latency?.avgMs)} hint={job?.latency ? `jitter ${job.latency.jitterMs} ms` : ''} />
          </div>
          <div className="tool-metrics">
            <Metric label="Gateway" value={fmtMs(job?.gatewayMs)} />
            <Metric label="Link rate" value={job?.link?.adapter?.linkMbps ? `${job.link.adapter.linkMbps} Mbps` : job?.link?.wifi?.rxMbps ? `${job.link.wifi.rxMbps} Mbps` : '-'} hint={job?.link?.interface?.name || job?.link?.wifi?.ssid || ''} />
            <Metric label="Test server" value={job?.meta?.city || job?.meta?.colo || '-'} hint={job?.meta?.asOrganization || ''} />
          </div>
          {job?.download?.error ? <div className="tool-note">Download note: {job.download.error}</div> : null}
          {job?.upload?.error ? <div className="tool-note">Upload note: {job.upload.error}</div> : null}
          {!job ? <div className="tool-note">The test uses Cloudflare and public mirrors. Live values update as bytes stream through.</div> : null}
        </div>
      </div>
    </div>
  );
}

function DnsBenchmarkTool() {
  const [domain, setDomain] = useState('example.com');
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const run = async (event) => {
    event?.preventDefault();
    setBusy(true);
    setError('');
    try {
      setData(await api.dnsBenchmark(domain.trim()));
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };
  useAutoRun(run);
  return (
    <div className="tool-body">
      <form className="tool-form" onSubmit={run}>
        <label>Domain<input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="example.com" /></label>
        <button className="btn primary" disabled={busy}><Icon n="globe" s={16} /> {busy ? 'Testing...' : 'Benchmark'}</button>
      </form>
      <ToolError error={error} />
      {busy && !data ? <Loading label="Querying resolvers..." /> : null}
      {data ? (
        <>
          <div className="tool-metrics">
            <Metric label="Best resolver" value={data.best ? data.best.label : 'None'} hint={data.best ? `${data.best.avg} ms average` : 'No resolver answered'} />
            <Metric label="Resolvers tested" value={data.servers.length} />
            <Metric label="Queries per resolver" value={data.domains.length} />
          </div>
          <div className="table-wrap">
            <table className="tool-table">
              <thead><tr><th>Resolver</th><th>Average</th><th>Min</th><th>Max</th><th>Failures</th><th>Status</th></tr></thead>
              <tbody>
                {data.servers.map((server) => (
                  <tr key={server.server}>
                    <td><b>{server.label}</b><small className="mono">{server.server}</small></td>
                    <td>{server.avg === null ? '-' : `${server.avg} ms`}</td>
                    <td>{server.min === null ? '-' : `${server.min} ms`}</td>
                    <td>{server.max === null ? '-' : `${server.max} ms`}</td>
                    <td>{server.failures}</td>
                    <td><span className={`pill ${server.ok ? 'new' : 'warnpill'}`}>{server.ok ? 'Responding' : 'No response'}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      ) : null}
    </div>
  );
}

function PingTool({ defaultTarget }) {
  const [host, setHost] = useState(defaultTarget || '1.1.1.1');
  const [count, setCount] = useState(4);
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const run = async (event) => {
    event?.preventDefault();
    setBusy(true);
    setError('');
    try {
      setData(await api.toolsPing(host.trim(), count));
    } catch (e) {
      setError(errorText(e));
      setData(null);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="tool-body">
      <form className="tool-form" onSubmit={run}>
        <label>Host or IP<input value={host} onChange={(e) => setHost(e.target.value)} placeholder="8.8.8.8" /></label>
        <label>Packets<select value={count} onChange={(e) => setCount(Number(e.target.value))}><option value={4}>4</option><option value={6}>6</option><option value={10}>10</option></select></label>
        <button className="btn primary" disabled={busy}><Icon n="radar" s={16} /> {busy ? 'Pinging...' : 'Ping'}</button>
      </form>
      <ToolError error={error} />
      {busy ? <Loading label={`Pinging ${host}...`} /> : null}
      {data ? (
        <>
          <div className="tool-metrics">
            <Metric label="Received" value={`${data.received} / ${data.sent}`} hint={`${data.lossPct}% loss`} />
            <Metric label="Average" value={fmtMs(data.avg)} />
            <Metric label="Range" value={data.min === null ? '-' : `${data.min} - ${data.max} ms`} hint={data.jitter === null ? '' : `${data.jitter} ms jitter`} />
          </div>
          <div className="sample-list">
            {data.samples.map((sample) => (
              <div key={sample.n} className={`sample ${sample.alive ? 'ok' : 'bad'}`}>
                <span>#{sample.n}</span><b>{sample.alive ? fmtMs(sample.ms) : 'No reply'}</b>
              </div>
            ))}
          </div>
        </>
      ) : null}
    </div>
  );
}

function TracerouteTool({ defaultTarget }) {
  const [host, setHost] = useState(defaultTarget || '1.1.1.1');
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const run = async (event) => {
    event?.preventDefault();
    setBusy(true);
    setError('');
    try {
      const result = await api.toolsTraceroute(host.trim(), 20);
      setData(result);
    } catch (e) {
      setError(errorText(e));
      setData(null);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="tool-body">
      <form className="tool-form" onSubmit={run}>
        <label>Host or IP<input value={host} onChange={(e) => setHost(e.target.value)} placeholder="1.1.1.1" /></label>
        <button className="btn primary" disabled={busy}><Icon n="topo" s={16} /> {busy ? 'Tracing...' : 'Trace route'}</button>
      </form>
      <ToolError error={error} />
      {busy ? <Loading label="Tracing up to 20 hops. This can take a minute." /> : null}
      {data ? (
        <>
          <div className="tool-actions">
            <span className={`pill ${data.reached ? 'new' : 'warnpill'}`}>{data.reached ? 'Destination reached' : 'Trace incomplete'}</span>
            <span className="muted small">{data.command} / {data.hops.length} hops</span>
          </div>
          <div className="table-wrap">
            <table className="tool-table">
              <thead><tr><th>Hop</th><th>Address</th><th>Round trips</th><th>Status</th></tr></thead>
              <tbody>
                {data.hops.map((hop) => (
                  <tr key={hop.hop}>
                    <td>{hop.hop}</td>
                    <td className="mono">{hop.ip || '*'}</td>
                    <td>{hop.ms.length ? hop.ms.map((ms) => `${ms} ms`).join(', ') : '-'}</td>
                    <td>{hop.timeout ? <span className="pill warnpill">Timeout</span> : <span className="pill new">Reply</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {!data.hops.length ? <Empty>No hops were parsed from the traceroute output.</Empty> : null}
          {data.output ? <details className="tool-details"><summary>Raw output</summary><pre>{data.output}</pre></details> : null}
        </>
      ) : null}
    </div>
  );
}

function DnsLookupTool() {
  const [host, setHost] = useState('example.com');
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const run = async (event) => {
    event?.preventDefault();
    setBusy(true);
    setError('');
    try {
      setData(await api.dnsLookup(host.trim()));
    } catch (e) {
      setError(errorText(e));
      setData(null);
    } finally {
      setBusy(false);
    }
  };
  const renderRecord = (label, record) => {
    if (!record || !record.ok || !record.records) return null;
    const values = Array.isArray(record.records) ? record.records : [record.records];
    if (!values.length) return null;
    return (
      <div className="dns-record" key={label}>
        <b>{label}</b>
        <div>{values.map((value, index) => <code key={index}>{typeof value === 'string' ? value : JSON.stringify(value)}</code>)}</div>
      </div>
    );
  };
  return (
    <div className="tool-body">
      <form className="tool-form" onSubmit={run}>
        <label>Hostname or IP<input value={host} onChange={(e) => setHost(e.target.value)} placeholder="example.com" /></label>
        <button className="btn primary" disabled={busy}><Icon n="search" s={16} /> {busy ? 'Resolving...' : 'Look up'}</button>
      </form>
      <ToolError error={error} />
      {busy ? <Loading label="Querying DNS records..." /> : null}
      {data ? (
        <div className="dns-results">
          <div className="tool-metrics">
            <Metric label="Query" value={data.host} />
            <Metric label="Resolver" value={data.servers?.[0] || 'System'} />
            <Metric label="Type" value={data.isIp ? 'Reverse lookup' : 'Hostname'} />
          </div>
          {data.isIp ? (
            data.names?.length ? <div className="dns-record"><b>PTR</b><div>{data.names.map((name) => <code key={name}>{name}</code>)}</div></div>
              : <Empty>No reverse DNS name was found.</Empty>
          ) : (
            data.records ? (
              <>
                {renderRecord('A', data.records.a)}
                {renderRecord('AAAA', data.records.aaaa)}
                {renderRecord('CNAME', data.records.cname)}
                {renderRecord('MX', data.records.mx)}
                {renderRecord('TXT', data.records.txt)}
                {renderRecord('NS', data.records.ns)}
                {renderRecord('SOA', data.records.soa)}
                {!data.ok ? <Empty>No DNS records were returned for this name.</Empty> : null}
              </>
            ) : null
          )}
        </div>
      ) : null}
    </div>
  );
}

function WifiTool() {
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const run = async () => {
    setBusy(true);
    setError('');
    try {
      setData(await api.toolsWifi());
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };
  useAutoRun(run);
  return (
    <div className="tool-body">
      <div className="tool-actions">
        <button className="btn primary" onClick={run} disabled={busy}><Icon n="refresh" s={16} /> {busy ? 'Scanning...' : 'Scan again'}</button>
        {data ? <span className="pill">{data.count} networks</span> : null}
        <span className="muted small">Nearby scan; results depend on adapter support and location permissions.</span>
      </div>
      <ToolError error={error || data?.error} />
      {busy && !data ? <Loading label="Scanning wireless networks..." /> : null}
      {data?.connected?.length ? (
        <div className="connected-wifi">
          <Icon n="wifi" s={18} />
          <div>
            <b>Connected</b>
            <small>{data.connected.map((item) => `${item.ssid || item.name || 'Wireless'} ${item.signal || ''}`).join(' / ')}</small>
          </div>
        </div>
      ) : null}
      {data ? (
        data.networks.length ? (
          <div className="wifi-list">
            {data.networks.map((network, index) => (
              <div className="wifi-row" key={`${network.bssid}-${index}`}>
                <span className="wifi-signal"><SignalBars signal={`${network.signalPct ?? 0}%`} /><b>{network.signalPct ?? '-'}%</b></span>
                <div className="wifi-main">
                  <b>{network.ssid || '(hidden SSID)'}</b>
                  <small className="mono">{network.bssid}{network.channel ? ` / ch ${network.channel}` : ''}{network.band ? ` / ${network.band}` : ''}</small>
                </div>
                <span className="wifi-security">{network.auth || network.encryption || 'Open'}</span>
              </div>
            ))}
          </div>
        ) : <Empty>No wireless networks were returned.</Empty>
      ) : null}
    </div>
  );
}

function DhcpTool() {
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(-1);
  const run = async () => {
    setBusy(true);
    setError('');
    try {
      setData(await api.toolsDhcp());
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };
  useAutoRun(run);
  const copy = async (command, index) => {
    try {
      await navigator.clipboard.writeText(command);
      setCopied(index);
      setTimeout(() => setCopied(-1), 1500);
    } catch {
      setError('Clipboard is not available. Select the command and copy it manually.');
    }
  };
  return (
    <div className="tool-body">
      <div className="tool-actions">
        <button className="btn primary" onClick={run} disabled={busy}><Icon n="refresh" s={16} /> {busy ? 'Reading leases...' : 'Refresh'}</button>
        <span className="pill">Read-only</span>
      </div>
      <ToolError error={error} />
      {busy && !data ? <Loading label="Reading DHCP configuration..." /> : null}
      {data ? (
        <>
          <div className="tool-metrics">
            <Metric label="Gateway" value={data.gateway || '-'} />
            <Metric label="DHCP server" value={data.dhcpServer || '-'} />
            <Metric label="Lease expires" value={fmtDate(data.leaseExpires)} />
          </div>
          <div className="adapter-list">
            {data.adapters.map((adapter) => (
              <div className="adapter-row" key={`${adapter.name}-${adapter.ip}`}>
                <div><b>{adapter.name}</b><small className="mono">{adapter.ip} / {adapter.cidr}</small></div>
                <div className="adapter-meta">
                  <span>{adapter.dhcpEnabled === null ? 'DHCP unknown' : adapter.dhcpEnabled ? 'DHCP enabled' : 'Static address'}</span>
                  <span className="mono">{adapter.dhcpServer || adapter.gateway || '-'}</span>
                </div>
              </div>
            ))}
          </div>
          <div className="recovery-list">
            <h3>Recovery steps</h3>
            <p className="muted small">{data.note}</p>
            {data.recovery.map((step, index) => (
              <div className="recovery-step" key={step.title}>
                <span className="recovery-number">{index + 1}</span>
                <div><b>{step.title}</b><code>{step.command}</code></div>
                <button className="btn ghost small-btn" onClick={() => copy(step.command, index)}>{copied === index ? 'Copied' : 'Copy'}</button>
              </div>
            ))}
          </div>
        </>
      ) : null}
    </div>
  );
}

function OpenPortsTool({ devices, defaultTarget }) {
  const [target, setTarget] = useState(defaultTarget || '192.168.1.1');
  const [preset, setPreset] = useState('common');
  const [custom, setCustom] = useState('');
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const run = async (event) => {
    event?.preventDefault();
    const clean = target.trim();
    if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(clean) || clean.split('.').some((part) => Number(part) > 255)) {
      setError('Enter a valid IPv4 address.');
      return;
    }
    let ports = PORT_PRESETS[preset] || PORT_PRESETS.common;
    if (custom.trim()) {
      ports = custom.split(',').map((value) => Number(value.trim())).filter((value) => value >= 1 && value <= 65535);
      if (!ports.length) {
        setError('Custom ports must be numbers between 1 and 65535.');
        return;
      }
    }
    setBusy(true);
    setError('');
    try {
      setData(await api.portScan(clean, [...new Set(ports)].slice(0, 100)));
    } catch (e) {
      setError(errorText(e));
      setData(null);
    } finally {
      setBusy(false);
    }
  };
  const open = data ? data.open || [] : [];
  return (
    <div className="tool-body">
      <form className="tool-form port-form" onSubmit={run}>
        <label>IPv4 target<input value={target} onChange={(e) => setTarget(e.target.value)} list="tool-device-ips" placeholder="192.168.1.1" /></label>
        <label>Port set<select value={preset} onChange={(e) => setPreset(e.target.value)} disabled={Boolean(custom.trim())}><option value="common">Common services</option><option value="quick">Quick scan</option><option value="web">Web ports</option><option value="cameras">Camera ports</option></select></label>
        <button className="btn primary" disabled={busy}><Icon n="search" s={16} /> {busy ? 'Scanning...' : 'Scan ports'}</button>
      </form>
      <datalist id="tool-device-ips">
        {(devices || []).filter((device) => device.ip).map((device) => <option key={device.ip} value={device.ip}>{device.hostname || device.vendor || device.ip}</option>)}
      </datalist>
      <div className="tool-inline-field">
        <label>Custom ports (optional)<input value={custom} onChange={(e) => setCustom(e.target.value)} placeholder="22, 80, 443, 554" /></label>
        <span className="muted small">Overrides the preset. Up to 100 ports.</span>
      </div>
      <ToolError error={error} />
      {busy ? <Loading label={`Scanning ${target}...`} /> : null}
      {data ? (
        <>
          <div className="tool-metrics">
            <Metric label="Open ports" value={open.length} />
            <Metric label="Ports scanned" value={data.all?.length || 0} />
            <Metric label="Target" value={data.ip} />
          </div>
          {open.length ? (
            <div className="table-wrap">
              <table className="tool-table">
                <thead><tr><th>Port</th><th>Service</th><th>Connect time</th></tr></thead>
                <tbody>
                  {open.map((entry) => (
                    <tr key={entry.port}>
                      <td className="mono">{entry.port}</td>
                      <td>{PORT_LABELS[entry.port] || 'Unknown service'}</td>
                      <td>{entry.ms === null ? '-' : `${entry.ms} ms`}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : <Empty>No open ports were found in this set. This does not prove the device is closed; firewalls can hide services.</Empty>}
        </>
      ) : null}
    </div>
  );
}

function CamerasTool() {
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const run = async () => {
    setBusy(true);
    setError('');
    try {
      setData(await api.hiddenCameras());
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };
  useAutoRun(run);
  return (
    <div className="tool-body">
      <div className="tool-actions">
        <button className="btn primary" onClick={run} disabled={busy}><Icon n="refresh" s={16} /> {busy ? 'Checking...' : 'Check inventory'}</button>
        {data ? <span className="pill">{data.likely} likely / {data.possible} possible</span> : null}
      </div>
      <ToolError error={error} />
      {busy && !data ? <Loading label="Analyzing the current inventory..." /> : null}
      {data ? (
        <>
          <div className="tool-metrics">
            <Metric label="Likely cameras" value={data.likely} />
            <Metric label="Possible cameras" value={data.possible} />
            <Metric label="Candidates" value={data.candidates.length} />
          </div>
          {data.candidates.length ? (
            <div className="camera-list">
              {data.candidates.map((candidate) => (
                <div className="camera-row" key={candidate.ip}>
                  <span className={`camera-score ${candidate.confidence}`}>{candidate.confidence}</span>
                  <div className="camera-main">
                    <b>{candidate.name}</b>
                    <small><span className="mono">{candidate.ip}</span> / {candidate.vendor}</small>
                    <div className="camera-reasons">{candidate.reasons.map((reason) => <span className="pill" key={reason}>{reason}</span>)}</div>
                  </div>
                  <div className="camera-ports">{candidate.ports.slice(0, 6).map((port) => <span key={port}>{port}</span>)}</div>
                </div>
              ))}
            </div>
          ) : <Empty>No camera-like devices were found in the current inventory.</Empty>}
          <div className="tool-note">{data.note}</div>
        </>
      ) : null}
    </div>
  );
}

function Landing({ onOpen, onRouter }) {
  return (
    <>
      <p className="muted small">Run network diagnostics and local security checks from one place. Results stay on this machine.</p>
      <div className="tool-grid">
        {TOOL_CARDS.map(([id, label, description, icon]) => (
          <button className="tool-card" key={id} onClick={() => onOpen(id)}>
            <span className="tool-icon"><Icon n={icon} s={20} /></span>
            <span><b>{label}</b><small>{description}</small></span>
            <span className="pill new">Open</span>
          </button>
        ))}
      </div>
      <div className="security-tools">
        <div className="security-heading">
          <Icon n="shield" s={20} />
          <div><h3>Improve your security</h3><p className="muted small">Review services and devices exposed on the local network.</p></div>
        </div>
        <div className="tool-grid security-grid">
          <button className="tool-card security-tool" onClick={() => onOpen('open-ports')}>
            <span className="tool-icon"><Icon n="search" s={20} /></span>
            <span><b>Find open ports</b><small>Identify exposed services on selected devices</small></span>
            <span className="pill new">Open</span>
          </button>
          <button className="tool-card security-tool" onClick={onRouter}>
            <span className="tool-icon"><Icon n="shield" s={20} /></span>
            <span><b>Test router vulnerabilities</b><small>Check management ports, UPnP, and risk patterns</small></span>
            <span className="pill new">LAN scan</span>
          </button>
          <button className="tool-card security-tool" onClick={() => onOpen('hidden-cameras')}>
            <span className="tool-icon"><Icon n="eye" s={20} /></span>
            <span><b>Find hidden cameras</b><small>Look for camera-like devices and video services</small></span>
            <span className="pill new">Open</span>
          </button>
        </div>
      </div>
    </>
  );
}

export default function ToolsView({ devices = [], gatewayIp, onRouter }) {
  const [active, setActive] = useState(null);
  const defaultTarget = gatewayIp || devices.find((device) => device.online && !device.isSelf)?.ip || '192.168.1.1';
  let body = null;
  if (active === 'health') body = <HealthTool />;
  if (active === 'speed') body = <SpeedTool />;
  if (active === 'dns-benchmark') body = <DnsBenchmarkTool />;
  if (active === 'ping') body = <PingTool defaultTarget={gatewayIp || '1.1.1.1'} />;
  if (active === 'traceroute') body = <TracerouteTool defaultTarget={gatewayIp || '1.1.1.1'} />;
  if (active === 'dns-lookup') body = <DnsLookupTool />;
  if (active === 'dhcp') body = <DhcpTool />;
  if (active === 'wifi') body = <WifiTool />;
  if (active === 'open-ports') body = <OpenPortsTool devices={devices} defaultTarget={defaultTarget} />;
  if (active === 'hidden-cameras') body = <CamerasTool />;
  return (
    <section className="card tools-page">
      <div className="cardhead">
        <h2><Icon n="sliders" s={18} /> Tools</h2>
        {active ? <button className="btn ghost small-btn" onClick={() => setActive(null)}><Icon n="chevR" s={15} /> All tools</button> : <span className="pill">Local diagnostics</span>}
      </div>
      {active ? (
        <div className="tool-panel">
          <div className="tool-panel-head">
            <div><h3>{TOOL_TITLES[active]}</h3><p className="muted small">Results are collected on demand. No changes are made unless you run a listed recovery command yourself.</p></div>
          </div>
          {body}
        </div>
      ) : <Landing onOpen={setActive} onRouter={onRouter} />}
    </section>
  );
}
