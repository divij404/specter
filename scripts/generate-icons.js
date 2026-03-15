/**
 * Generate placeholder PNG icons for the extension (Phase 1).
 * Run: node scripts/generate-icons.js
 */

const fs = require('fs');
const path = require('path');
const PNG = require('pngjs').PNG;

const ICONS_DIR = path.join(__dirname, '..', 'extension', 'icons');
// Design doc muted grey for placeholder
const R = 0x3d, G = 0x52, B = 0x68, A = 255;

function createPng(size) {
  const png = new PNG({ width: size, height: size });
  for (let i = 0; i < png.data.length; i += 4) {
    png.data[i] = R;
    png.data[i + 1] = G;
    png.data[i + 2] = B;
    png.data[i + 3] = A;
  }
  return PNG.sync.write(png);
}

if (!fs.existsSync(ICONS_DIR)) fs.mkdirSync(ICONS_DIR, { recursive: true });

for (const size of [16, 48, 128]) {
  const buf = createPng(size);
  const out = path.join(ICONS_DIR, `icon${size}.png`);
  fs.writeFileSync(out, buf);
  console.log('Created', out);
}
