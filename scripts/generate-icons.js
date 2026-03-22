/**
 * Generate extension PNG icons from the SVG logo.
 * Run: node scripts/generate-icons.js
 * Requires: npm install (sharp is used for SVG → PNG)
 */

const fs = require('fs');
const path = require('path');
const sharp = require('sharp');

const ICONS_DIR = path.join(__dirname, '..', 'extension', 'icons');
const BRAND_DIR = path.join(ICONS_DIR, 'brand');
const EXTENSION_ICONS_DIR = path.join(ICONS_DIR, 'extension');
const LOGO_SVG = path.join(BRAND_DIR, 'logo.svg');
const SIZES = [16, 32, 48, 128, 256, 512];

async function main() {
  if (!fs.existsSync(LOGO_SVG)) {
    console.error('Logo not found:', LOGO_SVG);
    process.exit(1);
  }
  fs.mkdirSync(EXTENSION_ICONS_DIR, { recursive: true });

  const svg = fs.readFileSync(LOGO_SVG);
  for (const size of SIZES) {
    const out = path.join(EXTENSION_ICONS_DIR, `icon${size}.png`);
    await sharp(svg)
      .resize(size, size)
      .png()
      .toFile(out);
    console.log('Created', out);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
