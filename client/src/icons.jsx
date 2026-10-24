/* Inline SVG icon set (stroke style) — no emoji anywhere in the UI. */
import React from 'react';

const P = {
  phone: (<><rect width="10" height="20" x="7" y="2" rx="2" /><path d="M12 18h.01" /></>),
  tablet: (<><rect width="16" height="20" x="4" y="2" rx="2" /><path d="M12 18h.01" /></>),
  laptop: (<><path d="M20 16V7a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v9m16 0H4m16 0 1.28 2.55a1 1 0 0 1-.9 1.45H3.62a1 1 0 0 1-.9-1.45L4 16" /></>),
  tv: (<><rect width="20" height="14" x="2" y="7" rx="2" /><path d="m17 2-5 5-5-5" /></>),
  speaker: (<><rect width="16" height="20" x="4" y="2" rx="2" /><circle cx="12" cy="14" r="4" /><path d="M12 6h.01" /></>),
  camera: (<><path d="M14.5 4h-5L7 7H4a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2h-3l-2.5-3z" /><circle cx="12" cy="13" r="3" /></>),
  printer: (<><path d="M6 9V3h12v6" /><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2" /><rect width="12" height="8" x="6" y="14" /></>),
  gamepad: (<><path d="M6 12h4m-2-2v4m7-3h.01M18 13h.01M17.32 5H6.68a4 4 0 0 0-3.98 3.59C2.6 9.42 2 16 2 16.5A1.5 1.5 0 0 0 3.5 18c1.56 0 2.7-1.2 3.6-1.6a4 4 0 0 1 1.65-.37c.6 0 1.2.13 1.75.28 1.25.35 1.75.35 3 0 .55-.15 1.15-.28 1.75-.28.62 0 1.17.15 1.65.37.9.4 2.04 1.6 3.6 1.6a1.5 1.5 0 0 0 1.5-1.5c0-.5-.6-7.08-.7-7.91A4 4 0 0 0 17.32 5Z" /></>),
  wifi: (<><path d="M2 8.82a15 15 0 0 1 20 0" /><path d="M5 12.55a11 11 0 0 1 14.08 0" /><path d="M8.53 16.11a6 6 0 0 1 6.95 0" /><path d="M12 20h.01" /></>),
  home: (<><path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" /><path d="M9 22V12h6v10" /></>),
  help: (<><circle cx="12" cy="12" r="10" /><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3" /><path d="M12 17h.01" /></>),
  search: (<><circle cx="11" cy="11" r="7" /><path d="m21 21-4.35-4.35" /></>),
  star: (<><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2" /></>),
  x: (<><path d="M18 6 6 18M6 6l12 12" /></>),
  chevR: (<><path d="m9 18 6-6-6-6" /></>),
  chevD: (<><path d="m6 9 6 6 6-6" /></>),
  chevU: (<><path d="m18 15-6-6-6 6" /></>),
  globe: (<><circle cx="12" cy="12" r="10" /><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20" /><path d="M2 12h20" /></>),
  tag: (<><path d="M12.586 2.586A2 2 0 0 0 11.172 2H4a2 2 0 0 0-2 2v7.172a2 2 0 0 0 .586 1.414l8.704 8.704a2.426 2.426 0 0 0 3.42 0l6.58-6.58a2.426 2.426 0 0 0 0-3.42z" /><circle cx="7.5" cy="7.5" r=".5" /></>),
  pencil: (<><path d="M21.174 6.812a1 1 0 0 0-3.986-3.987L3.842 16.174a2 2 0 0 0-.5.83l-1.321 4.352a.5.5 0 0 0 .623.622l4.353-1.32a2 2 0 0 0 .83-.497z" /><path d="m15 5 4 4" /></>),
  activity: (<><path d="M22 12h-4l-3 9L9 3l-3 9H2" /></>),
  zap: (<><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" /></>),
  eye: (<><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z" /><circle cx="12" cy="12" r="3" /></>),
  eyeOff: (<><path d="M9.88 9.88a3 3 0 1 0 4.24 4.24" /><path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68" /><path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61" /><path d="m2 2 20 20" /></>),
  download: (<><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><path d="m7 10 5 5 5-5" /><path d="M12 15V3" /></>),
  copy: (<><rect width="14" height="14" x="8" y="8" rx="2" /><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2" /></>),
  'arrow-down': (<><path d="M12 5v14M19 12l-7 7-7-7" /></>),
  'arrow-up': (<><path d="M12 19V5M5 12l7-7 7 7" /></>),
  clock: (<><circle cx="12" cy="12" r="10" /><path d="M12 6v6l4 2" /></>),
  shield: (<><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z" /><path d="m9 12 2 2 4-4" /></>),
  shieldAlert: (<><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z" /><path d="M12 8v4" /><path d="M12 16h.01" /></>),
  play: (<><polygon points="6 3 20 12 6 21 6 3" /></>),
  stop: (<><rect width="14" height="14" x="5" y="5" rx="2" /></>),
  sliders: (<><path d="M21 4h-7M10 4H3M21 12h-9M8 12H3M21 20h-5M12 20H3" /><path d="M14 2v4M8 10v4M16 18v4" /></>),
  radar: (<><circle cx="12" cy="12" r="9" /><circle cx="12" cy="12" r="5" /><circle cx="12" cy="12" r="1" /><path d="M12 12 17 7" /></>),
  bell: (<><path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9" /><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0" /></>),
  check: (<><path d="M20 6 9 17l-5-5" /></>),
  refresh: (<><path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8" /><path d="M21 3v5h-5" /><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16" /><path d="M3 21v-5h5" /></>),
  info: (<><circle cx="12" cy="12" r="10" /><path d="M12 16v-4" /><path d="M12 8h.01" /></>),
  users: (<><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" /><circle cx="9" cy="7" r="4" /><path d="M22 21v-2a4 4 0 0 0-3-3.87" /><path d="M16 3.13a4 4 0 0 1 0 7.75" /></>),
  topo: (<><circle cx="18" cy="5" r="3" /><circle cx="6" cy="12" r="3" /><circle cx="18" cy="19" r="3" /><path d="m8.59 13.51 6.83 3.98m-.01-10.98-6.82 3.98" /></>),
  menu: (<><path d="M4 6h16M4 12h16M4 18h16" /></>),
  database: (<><ellipse cx="12" cy="5" rx="8" ry="3" /><path d="M4 5v7c0 1.66 3.58 3 8 3s8-1.34 8-3V5" /><path d="M4 12v7c0 1.66 3.58 3 8 3s8-1.34 8-3v-7" /></>),
};

export function Icon({ n, s = 20, sw = 1.8 }) {
  return (
    <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth={sw} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      {P[n] || P.help}
    </svg>
  );
}

const TYPE_ICON = {
  phone: 'phone', tablet: 'tablet', computer: 'laptop', tv: 'tv',
  speaker: 'speaker', camera: 'camera', printer: 'printer', console: 'gamepad',
  router: 'wifi', iot: 'home', unknown: 'help',
};

export function DeviceIcon({ type, s = 26 }) {
  return <Icon n={TYPE_ICON[type] || 'help'} s={s} />;
}

/* Wi-Fi signal bars from a "83%" string. */
export function SignalBars({ signal }) {
  const pct = parseInt(String(signal || ''), 10);
  const level = Number.isNaN(pct) ? 0 : pct >= 75 ? 4 : pct >= 50 ? 3 : pct >= 25 ? 2 : 1;
  return (
    <span className="sigbars" title={signal || ''}>
      {[1, 2, 3, 4].map((i) => (
        <span key={i} className={i <= level ? 'on' : ''} style={{ height: 4 + i * 3 }} />
      ))}
    </span>
  );
}
