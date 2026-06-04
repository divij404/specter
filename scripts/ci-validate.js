/**
 * CI validation checks (also runnable locally: node scripts/ci-validate.js)
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const EXT = path.join(ROOT, 'extension');

function fail(msg) {
  console.error('CI validate:', msg);
  process.exit(1);
}

function requireFile(rel) {
  const p = path.join(EXT, rel);
  if (!fs.existsSync(p)) fail('Missing file: extension/' + rel);
}

const manifestPath = path.join(EXT, 'manifest.json');
let manifest;
try {
  manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
} catch (e) {
  fail('extension/manifest.json is not valid JSON: ' + e.message);
}

for (const key of ['name', 'version', 'manifest_version']) {
  if (!manifest[key]) fail('manifest.json missing required field: ' + key);
}
if (manifest.manifest_version !== 3) fail('manifest_version must be 3');
if (!manifest.background?.service_worker) fail('manifest.json missing background.service_worker');

requireFile(manifest.background.service_worker);
requireFile('blocking.js');
requireFile('blocking-ui.js');
requireFile('data/model.json');
requireFile('data/blocking_rules.json');

const rulesPath = manifest.declarative_net_request?.rule_resources?.[0]?.path;
if (rulesPath !== 'data/blocking_rules.json') {
  fail('declarative_net_request rule path must be data/blocking_rules.json');
}

try {
  JSON.parse(fs.readFileSync(path.join(EXT, 'data/blocking_rules.json'), 'utf8'));
} catch (e) {
  fail('data/blocking_rules.json is not valid JSON: ' + e.message);
}

if (!fs.existsSync(path.join(EXT, 'lib', 'd3.min.js'))) {
  fail('Missing extension/lib/d3.min.js — run npm run bundle-libs');
}

const jsFiles = [];
function walk(dir) {
  for (const name of fs.readdirSync(dir)) {
    const p = path.join(dir, name);
    if (fs.statSync(p).isDirectory()) walk(p);
    else if (name.endsWith('.js')) jsFiles.push(p);
  }
}
walk(EXT);

for (const file of jsFiles) {
  try {
    execSync(`node --check "${file}"`, { stdio: 'pipe' });
  } catch {
    fail('Syntax error in ' + path.relative(ROOT, file));
  }
}

console.log('CI validate: OK (' + jsFiles.length + ' JS files, manifest v' + manifest.version + ')');
