/* LAN-CAP topology — interactive 3D orbital map, dependency-free SVG.
 *
 * Devices are grouped into families (personal, media, smart home, network,
 * other) and placed on separate tilted orbits around the gateway/self core.
 * The scene rotates in software: drag to orbit, scroll to zoom, click to
 * inspect. Depth is used for perspective scale, opacity, and draw order, so
 * the result reads as a real 3D constellation rather than a flat ring. */
import React, { useEffect, useMemo, useRef, useState } from 'react';
import { DeviceIcon, Icon } from './icons.jsx';

const W = 980;
const H = 660;
const CAMERA = 900;
const SPIN_SPEED = 0.00011;
const MIN_ZOOM = 0.6;
const MAX_ZOOM = 2.2;

const GROUPS = [
  {
    key: 'personal', label: 'Personal', color: '#38bdf8',
    types: ['phone', 'tablet', 'computer'],
    radius: 168, tiltX: 0.38, tiltY: 0, tiltZ: 0.16, phase: 0.25,
  },
  {
    key: 'media', label: 'Media', color: '#a78bfa',
    types: ['tv', 'speaker', 'console'],
    radius: 226, tiltX: -0.58, tiltY: 0.3, tiltZ: 0.42, phase: 1.15,
  },
  {
    key: 'home', label: 'Smart home', color: '#34d399',
    types: ['camera', 'printer', 'iot'],
    radius: 282, tiltX: 0.98, tiltY: -0.2, tiltZ: -0.34, phase: 2.1,
  },
  {
    key: 'network', label: 'Network', color: '#fbbf24',
    types: ['router'],
    radius: 118, tiltX: 0.12, tiltY: 0, tiltZ: 0, phase: 0.85,
  },
  {
    key: 'other', label: 'Other', color: '#94a3b8',
    types: ['unknown'],
    radius: 312, tiltX: -0.28, tiltY: 0.22, tiltZ: 0.88, phase: 2.9,
  },
];

const GROUP_BY_TYPE = Object.fromEntries(
  GROUPS.flatMap((g) => g.types.map((t) => [t, g.key])),
);

const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));

function hash(str) {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return Math.abs(h) >>> 0;
}

function rotateY(p, a) {
  const c = Math.cos(a); const s = Math.sin(a);
  return { x: p.x * c + p.z * s, y: p.y, z: -p.x * s + p.z * c };
}
function rotateX(p, a) {
  const c = Math.cos(a); const s = Math.sin(a);
  return { x: p.x, y: p.y * c - p.z * s, z: p.y * s + p.z * c };
}
function rotateZ(p, a) {
  const c = Math.cos(a); const s = Math.sin(a);
  return { x: p.x * c - p.y * s, y: p.x * s + p.y * c, z: p.z };
}

function tilt(p, g) {
  return rotateY(rotateX(rotateZ(p, g.tiltZ), g.tiltX), g.tiltY);
}

function cameraPoint(p, yaw, pitch) {
  const y = rotateY(p, yaw);
  return rotateX(y, pitch);
}

function project(p, zoom) {
  const scale = CAMERA / (CAMERA + p.z);
  return {
    x: W / 2 + p.x * scale * zoom,
    y: H / 2 + p.y * scale * zoom,
    scale: scale * zoom,
    depth: p.z,
  };
}

function orbitPoint(g, angle, radius = g.radius) {
  return tilt({ x: Math.cos(angle) * radius, y: Math.sin(angle) * radius, z: 0 }, g);
}

function devicePoint(g, index, count, seed) {
  const j = (hash(seed) % 1000) / 1000;
  const angle = g.phase + (index / Math.max(1, count)) * Math.PI * 2 + (j - 0.5) * 0.3;
  const radius = g.radius + (j - 0.5) * 18;
  return orbitPoint(g, angle, radius);
}

function shortName(d, note) {
  if (note?.name) return note.name;
  if (d.fp?.model) return d.fp.model;
  if (d.hostname) return d.hostname;
  if (d.vendor && d.vendor !== 'Unknown') return d.vendor;
  return d.ip;
}

export function TopoMap({ devices, notes, center, onSelect, selectedIp }) {
  const wrapRef = useRef(null);
  const dragRef = useRef(null);
  const movedRef = useRef(false);

  const [yaw, setYaw] = useState(0.62);
  const [pitch, setPitch] = useState(-0.16);
  const [zoom, setZoom] = useState(1);
  const [dragging, setDragging] = useState(false);
  const [hover, setHover] = useState(null);
  const [autoSpin, setAutoSpin] = useState(() => {
    if (typeof window === 'undefined') return true;
    return !window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
  });

  const { nodes, present } = useMemo(() => {
    const buckets = new Map(GROUPS.map((g) => [g.key, []]));
    for (const d of devices) {
      if (center && d.ip === center.ip) continue;
      const key = GROUP_BY_TYPE[d.type] || 'other';
      buckets.get(key).push(d);
    }
    const out = [];
    const seen = [];
    for (const g of GROUPS) {
      const list = buckets.get(g.key)
        .slice()
        .sort((a, b) => Number(b.online) - Number(a.online) || String(a.ip).localeCompare(String(b.ip)));
      if (!list.length) continue;
      seen.push({ ...g, count: list.length, online: list.filter((d) => d.online).length });
      list.forEach((d, i) => out.push({ d, group: g, world: devicePoint(g, i, list.length, d.ip) }));
    }
    return { nodes: out, present: seen };
  }, [devices, center]);

  const projected = useMemo(() => nodes
    .map((n) => {
      const p = project(cameraPoint(n.world, yaw, pitch), zoom);
      return { ...n, ...p };
    })
    .sort((a, b) => b.depth - a.depth), [nodes, yaw, pitch, zoom]);

  const orbits = useMemo(() => present.map((g) => {
    const pts = [];
    for (let i = 0; i <= 96; i++) {
      const p = project(cameraPoint(orbitPoint(g, (i / 96) * Math.PI * 2), yaw, pitch), zoom);
      pts.push(`${i ? 'L' : 'M'}${p.x.toFixed(1)} ${p.y.toFixed(1)}`);
    }
    return { ...g, path: `${pts.join(' ')} Z` };
  }), [present, yaw, pitch, zoom]);

  const maxNodes = projected.length;
  const hovered = hover ? projected.find((n) => n.d.ip === hover) : null;

  useEffect(() => {
    if (!autoSpin || dragging) return undefined;
    let raf = 0;
    let last = performance.now();
    const tick = (now) => {
      const dt = Math.min(64, now - last);
      last = now;
      setYaw((v) => v + dt * SPIN_SPEED);
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [autoSpin, dragging]);

  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return undefined;
    const onWheel = (e) => {
      e.preventDefault();
      setZoom((z) => clamp(z - e.deltaY * 0.0012, MIN_ZOOM, MAX_ZOOM));
    };
    el.addEventListener('wheel', onWheel, { passive: false });
    return () => el.removeEventListener('wheel', onWheel);
  }, []);

  function onPointerDown(e) {
    if (e.button !== 0) return;
    dragRef.current = { x: e.clientX, y: e.clientY, yaw, pitch, captured: false };
    movedRef.current = false;
    setDragging(true);
  }

  function onPointerMove(e) {
    const start = dragRef.current;
    if (!start) return;
    const dx = e.clientX - start.x;
    const dy = e.clientY - start.y;
    if (Math.abs(dx) + Math.abs(dy) > 4) {
      movedRef.current = true;
      /* Capture only after a real drag starts: capturing on pointerdown
       * would retarget pointerup and stop click events reaching the nodes. */
      if (!start.captured) {
        start.captured = true;
        try { e.currentTarget.setPointerCapture(e.pointerId); } catch { /* ignore */ }
      }
    }
    setYaw(start.yaw + dx * 0.006);
    setPitch(clamp(start.pitch + dy * 0.005, -1.1, 1.1));
  }

  function onPointerUp(e) {
    const start = dragRef.current;
    dragRef.current = null;
    setDragging(false);
    if (start?.captured) {
      try { e.currentTarget.releasePointerCapture(e.pointerId); } catch { /* ignore */ }
    }
  }

  function choose(d) {
    if (movedRef.current) return;
    onSelect(d);
  }

  function resetView() {
    setYaw(0.62);
    setPitch(-0.16);
    setZoom(1);
  }

  if (!nodes.length && !center) {
    return (
      <div className="topo3d empty">
        <div className="topo-empty">
          <Icon n="topo" s={34} />
          <p>Nothing to orbit yet — scan your network to build the topology.</p>
        </div>
      </div>
    );
  }

  const centerLabel = center ? `${center.isGateway ? 'Router' : 'You'} · ${center.ip}` : 'Network core';

  return (
    <div className={`topo3d${dragging ? ' dragging' : ''}`} ref={wrapRef}>
      <div className="topo-toolbar">
        <span className="topo-count">
          <span className="statusdot on inline" />
          {devices.filter((d) => d.online).length} online · {maxNodes} mapped
        </span>
        <div className="spacer" />
        <button
          className={`ghost sm${autoSpin ? ' active' : ''}`}
          onClick={() => setAutoSpin((v) => !v)}
          title={autoSpin ? 'Pause rotation' : 'Resume rotation'}
        >
          <Icon n={autoSpin ? 'stop' : 'play'} s={13} /> {autoSpin ? 'Orbit' : 'Still'}
        </button>
        <button className="ghost sm" onClick={resetView} title="Reset view">
          <Icon n="refresh" s={13} /> Reset
        </button>
        <button className="ghost sm" onClick={() => setZoom((z) => clamp(z - 0.2, MIN_ZOOM, MAX_ZOOM))} title="Zoom out">−</button>
        <button className="ghost sm zoomlevel" onClick={resetView} title="Reset zoom">{Math.round(zoom * 100)}%</button>
        <button className="ghost sm" onClick={() => setZoom((z) => clamp(z + 0.2, MIN_ZOOM, MAX_ZOOM))} title="Zoom in">+</button>
      </div>

      <svg
        viewBox={`0 0 ${W} ${H}`}
        className="topo-svg"
        role="img"
        aria-label="Interactive 3D network topology"
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onPointerCancel={onPointerUp}
        onPointerLeave={(e) => { if (dragRef.current) onPointerUp(e); }}
      >
        <defs>
          <radialGradient id="topo-core-grad">
            <stop offset="0%" className="topo-core-stop" />
            <stop offset="70%" className="topo-core-stop-mid" />
            <stop offset="100%" stopColor="transparent" stopOpacity="0" />
          </radialGradient>
          <radialGradient id="topo-vignette">
            <stop offset="55%" stopColor="#000" stopOpacity="0" />
            <stop offset="100%" stopColor="#000" stopOpacity="0.28" />
          </radialGradient>
        </defs>

        <rect width={W} height={H} className="topo-bg" />
        <rect width={W} height={H} className="topo-vignette" fill="url(#topo-vignette)" />

        {orbits.map((g) => (
          <path key={g.key} d={g.path} className="topo-orbit" style={{ stroke: g.color }} />
        ))}

        {projected.map((n) => (
          <line
            key={`e-${n.d.ip}`}
            x1={W / 2}
            y1={H / 2}
            x2={n.x}
            y2={n.y}
            className={`topo-edge${n.d.online ? '' : ' off'}`}
            style={{
              stroke: n.group.color,
              opacity: clamp(0.05 + (1 - (n.depth + 330) / 660) * 0.24, 0.05, 0.32),
            }}
          />
        ))}

        <g className="topo-core" transform={`translate(${W / 2} ${H / 2})`}>
          <circle r="86" className="topo-core-glow" fill="url(#topo-core-grad)" />
          <circle r="42" className="topo-core-ring outer" />
          <circle r="30" className="topo-core-ring" />
          <circle r="24" className="topo-core-disc" />
          <foreignObject x="-17" y="-17" width="34" height="34">
            <div className="micon core" xmlns="http://www.w3.org/1999/xhtml">
              <Icon n={center?.isGateway ? 'wifi' : 'laptop'} s={22} />
            </div>
          </foreignObject>
          <text y="56" textAnchor="middle" className="topo-core-label">{centerLabel}</text>
        </g>

        {projected.map((n) => {
          const note = notes[n.d.ip];
          const name = shortName(n.d, note);
          const r = clamp(15 * n.scale, 8, 25);
          const depthFade = clamp(0.56 + (1 - (n.depth + 330) / 660) * 0.44, 0.56, 1);
          const opacity = n.d.online ? depthFade : depthFade * 0.5;
          const showLabel = maxNodes <= 28 || n.depth < 80 || hover === n.d.ip;
          const active = selectedIp === n.d.ip || hover === n.d.ip;
          return (
            <g
              key={n.d.ip}
              transform={`translate(${n.x.toFixed(1)} ${n.y.toFixed(1)})`}
              className={`topo-node${n.d.online ? ' on' : ''}${selectedIp === n.d.ip ? ' sel' : ''}${hover === n.d.ip ? ' hover' : ''}`}
              style={{ opacity }}
              role="button"
              tabIndex={0}
              aria-label={`${name}, ${n.d.ip}${n.d.online ? ', online' : ', offline'}`}
              onPointerEnter={() => setHover(n.d.ip)}
              onPointerLeave={() => setHover((h) => (h === n.d.ip ? null : h))}
              onClick={() => choose(n.d)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect(n.d); }
              }}
            >
              <circle r={r * (active ? 2.2 : 1.85)} className="topo-halo" style={{ fill: n.group.color }} />
              <circle r={r} className="topo-disc" style={{ stroke: n.group.color }} />
              <foreignObject x={-r * 0.62} y={-r * 0.62} width={r * 1.24} height={r * 1.24}>
                <div className="micon" style={{ color: n.group.color }} xmlns="http://www.w3.org/1999/xhtml">
                  <DeviceIcon type={n.d.type || 'unknown'} s={Math.round(r * 1.12)} />
                </div>
              </foreignObject>
              {showLabel && (
                <text y={r + 15} textAnchor="middle" className={`topo-label${active ? ' strong' : ''}`}>
                  {name.length > 22 ? `${name.slice(0, 21)}…` : name}
                </text>
              )}
              <title>{name} · {n.d.ip}{n.d.online ? '' : ' (offline)'}</title>
            </g>
          );
        })}

        {hovered && (() => {
          const note = notes[hovered.d.ip];
          const name = shortName(hovered.d, note);
          const tx = clamp(hovered.x + 20, 10, W - 220);
          const ty = clamp(hovered.y - 66, 10, H - 78);
          return (
            <foreignObject x={tx} y={ty} width="210" height="68" className="topo-tip-wrap">
              <div className="topo-tip" xmlns="http://www.w3.org/1999/xhtml">
                <b>{name.length > 26 ? `${name.slice(0, 25)}…` : name}</b>
                <span className="mono">{hovered.d.ip}</span>
                <small>{hovered.d.vendor && hovered.d.vendor !== 'Unknown' ? hovered.d.vendor : hovered.group.label}</small>
                <em className={hovered.d.online ? 'on' : 'off'}>
                  <span className={`statusdot ${hovered.d.online ? 'on' : ''}`} />
                  {hovered.d.online ? 'Online' : 'Offline'}
                </em>
              </div>
            </foreignObject>
          );
        })()}
      </svg>

      <div className="topo-legend">
        {present.map((g) => (
          <span key={g.key} className="topo-chip">
            <i style={{ background: g.color }} />
            {g.label}
            <b>{g.online}/{g.count}</b>
          </span>
        ))}
        <span className="topo-hint"><Icon n="info" s={13} /> Drag to orbit · scroll to zoom · click a device</span>
      </div>
    </div>
  );
}
