/**
 * Copy npm packages into extension/lib/ for the dashboard.
 * Run: npm install && npm run bundle-libs
 */

const fs = require('fs');
const path = require('path');
const https = require('https');

const EXT_LIB = path.join(__dirname, '..', 'extension', 'lib');
const NODE_MODULES = path.join(__dirname, '..', 'node_modules');
const D3_DEST = path.join(EXT_LIB, 'd3.min.js');

function mkdirp(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function copyDir(src, dest) {
  mkdirp(dest);
  for (const name of fs.readdirSync(src)) {
    const s = path.join(src, name);
    const d = path.join(dest, name);
    if (fs.statSync(s).isDirectory()) copyDir(s, d);
    else fs.copyFileSync(s, d);
  }
}

function downloadLucide() {
  return new Promise((resolve, reject) => {
    const url = 'https://unpkg.com/lucide@0.460.0/dist/umd/lucide.min.js';
    const dest = path.join(EXT_LIB, 'lucide.min.js');
    mkdirp(path.dirname(dest));
    https.get(url, (res) => {
      if (res.statusCode !== 200) {
        reject(new Error('Lucide UMD download failed: ' + res.statusCode));
        return;
      }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        fs.writeFileSync(dest, Buffer.concat(chunks));
        console.log('Bundled lucide.min.js -> extension/lib/lucide.min.js');
        resolve();
      });
    }).on('error', reject);
  });
}

async function main() {
  mkdirp(EXT_LIB);

  const ortSrc = path.join(NODE_MODULES, 'onnxruntime-web', 'dist');
  const ortDest = path.join(EXT_LIB, 'onnxruntime-web');
  if (fs.existsSync(ortSrc)) {
    copyDir(ortSrc, ortDest);
    console.log('Bundled onnxruntime-web -> extension/lib/onnxruntime-web/');
  } else {
    console.warn('onnxruntime-web not found. Run: npm install');
  }

  const d3Src = path.join(NODE_MODULES, 'd3', 'dist', 'd3.min.js');
  if (fs.existsSync(d3Src)) {
    fs.copyFileSync(d3Src, D3_DEST);
    console.log('Bundled d3.min.js -> extension/lib/d3.min.js');
  } else {
    console.error('d3 not found. Run: npm install');
    process.exit(1);
  }

  try {
    await downloadLucide();
  } catch (e) {
    console.warn('Lucide download error:', e.message);
  }

  if (!fs.existsSync(D3_DEST)) {
    console.error('Missing required: extension/lib/d3.min.js');
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
