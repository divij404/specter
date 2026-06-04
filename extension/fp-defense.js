/* Specter — Fingerprinting Defense (v1.3)
 * Runs at document_start in the MAIN world (see manifest.json).
 * Config + seed are injected into sessionStorage by the service worker before navigation.
 */

(function () {
  'use strict';

  function readCfg() {
    try {
      const raw = sessionStorage.getItem('__specter_fp_cfg__');
      return raw ? JSON.parse(raw) : null;
    } catch {
      return null;
    }
  }

  function install(cfg) {
  if (!cfg || !cfg.e) return;

  const rawSeed = sessionStorage.getItem('__specter_fp_seed__');
  const SEED = rawSeed ? parseInt(rawSeed, 36) : (Math.random() * 0xffffffff) | 0;

  function prng(seed) {
    let s = seed;
    return function () {
      s |= 0;
      s = (s + 0x6d2b79f5) | 0;
      let t = Math.imul(s ^ (s >>> 15), 1 | s);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }
  const rand = prng(SEED);

  // ── Canvas ────────────────────────────────────────────────────────────────
  if (cfg.c && typeof HTMLCanvasElement !== 'undefined') {
    const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
    const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;

    HTMLCanvasElement.prototype.toDataURL = function (...args) {
      if (this.width >= 16 && this.height >= 16) {
        const ctx = this.getContext('2d');
        if (ctx) {
          const x = Math.floor(rand() * this.width);
          const y = Math.floor(rand() * this.height);
          const alpha = Math.floor(rand() * 3);
          ctx.fillStyle =
            'rgba(' +
            Math.floor(rand() * 256) +
            ',' +
            Math.floor(rand() * 256) +
            ',' +
            Math.floor(rand() * 256) +
            ',' +
            alpha / 255 +
            ')';
          ctx.fillRect(x, y, 1, 1);
        }
      }
      return origToDataURL.apply(this, args);
    };

    CanvasRenderingContext2D.prototype.getImageData = function (sx, sy, sw, sh, ...rest) {
      const data = origGetImageData.apply(this, [sx, sy, sw, sh, ...rest]);
      for (let i = 0; i < data.data.length; i += 512) {
        const offset = Math.floor(rand() * 4);
        data.data[i + offset] ^= 1;
      }
      return data;
    };
  }

  // ── WebGL ─────────────────────────────────────────────────────────────────
  if (cfg.w) {
    const spoofedParams = new Map();
    const VENDOR = 0x1f00;
    const RENDERER = 0x1f01;

    function patchWebGLGetParameter(proto) {
      if (!proto || !proto.getParameter) return;
      const origGetParameter = proto.getParameter;
      proto.getParameter = function (param) {
        if (param === RENDERER || param === VENDOR) {
          if (!spoofedParams.has(param)) {
            const vendors = ['Intel Inc.', 'NVIDIA Corporation', 'AMD', 'Apple Inc.'];
            const renderers = [
              'Intel Iris OpenGL Engine',
              'GeForce GTX 1060',
              'Radeon RX 580',
              'Apple M2',
            ];
            spoofedParams.set(VENDOR, vendors[Math.floor(rand() * vendors.length)]);
            spoofedParams.set(RENDERER, renderers[Math.floor(rand() * renderers.length)]);
          }
          return spoofedParams.get(param);
        }
        return origGetParameter.apply(this, [param]);
      };
    }

    if (typeof WebGLRenderingContext !== 'undefined') {
      patchWebGLGetParameter(WebGLRenderingContext.prototype);
    }
    if (typeof WebGL2RenderingContext !== 'undefined') {
      patchWebGLGetParameter(WebGL2RenderingContext.prototype);
    }
  }

  // ── AudioContext ──────────────────────────────────────────────────────────
  if (cfg.a && typeof AudioBuffer !== 'undefined' && AudioBuffer.prototype.getChannelData) {
    const origGetChannelData = AudioBuffer.prototype.getChannelData;
    AudioBuffer.prototype.getChannelData = function (channel) {
      const data = origGetChannelData.apply(this, [channel]);
      const noiseLen = Math.min(8, data.length);
      for (let i = data.length - noiseLen; i < data.length; i++) {
        data[i] += (rand() - 0.5) * 1e-7;
      }
      return data;
    };
  }

  // ── Navigator ─────────────────────────────────────────────────────────────
  if (cfg.n) {
    const HC_OPTIONS = [2, 4, 8];
    const DM_OPTIONS = [2, 4, 8];
    const spoofedHC = HC_OPTIONS[Math.floor(rand() * HC_OPTIONS.length)];
    const spoofedDM = DM_OPTIONS[Math.floor(rand() * DM_OPTIONS.length)];
    try {
      Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => spoofedHC });
      Object.defineProperty(navigator, 'deviceMemory', { get: () => spoofedDM });
    } catch {
      /* non-fatal — some pages lock navigator */
    }
  }

  // ── Font enumeration ──────────────────────────────────────────────────────
  if (cfg.f && typeof FontFaceSet !== 'undefined' && FontFaceSet.prototype.check) {
    const COMMON_FONTS = new Set([
      'Arial', 'Arial Black', 'Comic Sans MS', 'Courier New', 'Georgia',
      'Impact', 'Times New Roman', 'Trebuchet MS', 'Verdana',
      '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto',
      'Helvetica Neue', 'Helvetica', 'sans-serif', 'serif', 'monospace',
    ]);
    const origFontsCheck = FontFaceSet.prototype.check;
    FontFaceSet.prototype.check = function (font, text) {
      const match = font.match(/(?:^|\s)(["']?)(.+?)\1(?:\s*,|$)/);
      const name = match ? match[2].trim() : font;
      if (!COMMON_FONTS.has(name)) return false;
      return origFontsCheck.apply(this, [font, text]);
    };
  }
  }

  const cfg = readCfg();
  if (cfg) {
    install(cfg);
    return;
  }
  let attempts = 0;
  const poll = setInterval(() => {
    const next = readCfg();
    if (next || ++attempts > 50) {
      clearInterval(poll);
      if (next) install(next);
    }
  }, 0);
})();
