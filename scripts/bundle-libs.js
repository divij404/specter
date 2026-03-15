/**
 * Copy npm packages into extension/lib/ for Phase 1.
 * Run: npm install && node scripts/bundle-libs.js
 */

const fs = require('fs');
const path = require('path');
const https = require('https');

const EXT_LIB = path.join(__dirname, '..', 'extension', 'lib');
const NODE_MODULES = path.join(__dirname, '..', 'node_modules');

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

// 1. onnxruntime-web (full dist including .wasm)
const ortSrc = path.join(NODE_MODULES, 'onnxruntime-web', 'dist');
const ortDest = path.join(EXT_LIB, 'onnxruntime-web');
if (fs.existsSync(ortSrc)) {
  mkdirp(path.dirname(ortDest));
  copyDir(ortSrc, ortDest);
  console.log('Bundled onnxruntime-web -> extension/lib/onnxruntime-web/');
} else {
  console.warn('onnxruntime-web not found. Run: npm install');
}

// 2. D3 v7 min
const d3Src = path.join(NODE_MODULES, 'd3', 'dist', 'd3.min.js');
const d3Dest = path.join(EXT_LIB, 'd3.min.js');
if (fs.existsSync(d3Src)) {
  mkdirp(path.dirname(d3Dest));
  fs.copyFileSync(d3Src, d3Dest);
  console.log('Bundled d3.min.js -> extension/lib/d3.min.js');
} else {
  console.warn('d3 not found. Run: npm install');
}

// 3. Lucide UMD (download from unpkg)
function downloadLucide() {
  return new Promise((resolve, reject) => {
    const LUCIDE_UMD = 'https://unpkg.com/lucide@0.460.0/dist/umd/lucide.min.js';
    const lucideDest = path.join(EXT_LIB, 'lucide.min.js');
    mkdirp(path.dirname(lucideDest));
    https.get(LUCIDE_UMD, (res) => {
      if (res.statusCode !== 200) {
        reject(new Error('Lucide UMD download failed: ' + res.statusCode));
        return;
      }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        fs.writeFileSync(lucideDest, Buffer.concat(chunks));
        console.log('Bundled lucide.min.js -> extension/lib/lucide.min.js');
        resolve();
      });
    }).on('error', reject);
  });
}
downloadLucide().catch((e) => console.warn('Lucide download error:', e.message));
