'use strict';
// One-off: build server/oui.json from the IEEE oui.txt registry.
const fs = require('fs');
const path = require('path');

const SRC = 'C:/Users/dsipu/AppData/Local/Temp/opencode/oui.txt';
const DST = path.join(__dirname, 'oui.json');

function clean(s) {
  let v = s.trim().replace(/\s+/g, ' ');
  v = v.replace(/,?\s*(Corp|Inc|Incorporated)\.?,?\s*Ltd\.?$/i, '');
  v = v.replace(/,?\s*Ind\.?,?\s*Co\.?,?\s*Ltd\.?$/i, '');
  for (let i = 0; i < 3; i++) {
    const p = v;
    v = v.replace(/,?\s+Co\.?,?\s+Ltd\.?$/i, '')
      .replace(/,?\s+(Pvt|Pte)\.?\s+Ltd\.?$/i, '')
      .replace(/,?\s+(Inc|Incorporated|Corporation|Corp|Company|Incorporation)\.?$/i, '')
      .replace(/,?\s+(Ltd|Limited|LLC|L\.L\.C|GmbH|AG|AB|SA|S\.A\.S?|SRL|BV|NV|OY|SpA|SL)\.?$/i, '')
      .replace(/\s+(Holdings|Group|International|Industries|Industrial|Enterprises|Laboratories)\.?$/i, '');
    if (v === p) break;
  }
  v = v.replace(/\s+LLC,?\s+a\s+.+$/i, '')
    .replace(/\s+Mobility$/i, '')
    .replace(/\s+Mobile\s+Communications?$/i, '')
    .replace(/\s+(Mobile\s+)?Telecommunications?$/i, '');
  v = v.trim().replace(/[\.,]+$/, '');
  if (v && v === v.toUpperCase() && /[A-Z]/.test(v)) {
    v = v.toLowerCase().replace(/\b\w/g, (c) => c.toUpperCase());
  }
  return v;
}

const lines = fs.readFileSync(SRC, 'utf8').split(/\r?\n/);
const hexRe = /^([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.*)$/;
const contRe = /^\s+\S/;
const skipRe = /\(hex\)|\(base 16\)/;

const map = {};
for (let i = 0; i < lines.length; i++) {
  const m = hexRe.exec(lines[i]);
  if (!m) continue;
  let org = m[2];
  while (i + 1 < lines.length && contRe.test(lines[i + 1]) && !skipRe.test(lines[i + 1])) {
    org += ' ' + lines[++i].trim();
  }
  const oui = m[1].toLowerCase().replace(/-/g, ':');
  const v = clean(org);
  if (v && !map[oui]) map[oui] = v;
}

fs.writeFileSync(DST, JSON.stringify(map));
const n = Object.keys(map).length;
console.log('entries:' + n + ' bytes:' + fs.statSync(DST).size);
if (n < 30000) { console.error('REFUSING: too few entries, not writing garbage'); process.exit(1); }
for (const o of ['f4:d7:e4', '40:fa:fe', '44:fb:76', '88:54:8e', '10:bd:3a', '6c:5a:b0', 'b8:27:eb']) {
  console.log(o, '=>', map[o]);
}
