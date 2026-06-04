/* Specter — Fingerprinting Defense UI (v1.3)
 *
 * Imported by dashboard.html before dashboard.js.
 *   renderFpDefenseSettingsSection(settings)
 *   bindFpDefenseSettingsEvents(saveSettingFieldFn)
 */

function renderFpDefenseSettingsSection(s) {
  const enabled = !!s.fp_defense_enabled;
  const disAttr = enabled ? '' : ' disabled';
  const disClass = enabled ? '' : ' settings-row--disabled';

  return `
<div class="settings-section settings-section--fp-defense${enabled ? ' settings-section--fp-defense-armed' : ''}" id="settings-fp-defense">

  <div class="settings-section-header">
    <span class="settings-section-title">FINGERPRINT DEFENSE</span>
  </div>

  <div class="settings-row settings-row--fp-defense-master">
    <div class="settings-row-label">
      <div class="settings-row-title">Enable fingerprint defense</div>
      <div class="settings-row-hint">
        Injects subtle noise into canvas, WebGL, audio, and other fingerprint APIs before page scripts run.
        Off by default — some sites may behave differently.
      </div>
    </div>
    <label class="settings-toggle" aria-label="Enable fingerprint defense">
      <input type="checkbox" id="setting-fp-defense-enabled"${enabled ? ' checked' : ''}>
      <span class="settings-toggle-track"></span>
    </label>
  </div>

  <div class="settings-row settings-row--nested${disClass}">
    <div class="settings-row-label">
      <div class="settings-row-title">Canvas</div>
      <div class="settings-row-hint">Noise on toDataURL / getImageData exports</div>
    </div>
    <label class="settings-toggle" aria-label="Canvas fingerprint defense">
      <input type="checkbox" id="setting-fp-defense-canvas"${s.fp_defense_canvas !== false ? ' checked' : ''}${disAttr}>
      <span class="settings-toggle-track"></span>
    </label>
  </div>

  <div class="settings-row settings-row--nested${disClass}">
    <div class="settings-row-label">
      <div class="settings-row-title">WebGL</div>
      <div class="settings-row-hint">Normalize GPU vendor / renderer strings</div>
    </div>
    <label class="settings-toggle" aria-label="WebGL fingerprint defense">
      <input type="checkbox" id="setting-fp-defense-webgl"${s.fp_defense_webgl !== false ? ' checked' : ''}${disAttr}>
      <span class="settings-toggle-track"></span>
    </label>
  </div>

  <div class="settings-row settings-row--nested${disClass}">
    <div class="settings-row-label">
      <div class="settings-row-title">Audio</div>
      <div class="settings-row-hint">Imperceptible noise on AudioBuffer samples</div>
    </div>
    <label class="settings-toggle" aria-label="Audio fingerprint defense">
      <input type="checkbox" id="setting-fp-defense-audio"${s.fp_defense_audio !== false ? ' checked' : ''}${disAttr}>
      <span class="settings-toggle-track"></span>
    </label>
  </div>

  <div class="settings-row settings-row--nested${disClass}">
    <div class="settings-row-label">
      <div class="settings-row-title">Navigator</div>
      <div class="settings-row-hint">hardwareConcurrency and deviceMemory</div>
    </div>
    <label class="settings-toggle" aria-label="Navigator fingerprint defense">
      <input type="checkbox" id="setting-fp-defense-navigator"${s.fp_defense_navigator !== false ? ' checked' : ''}${disAttr}>
      <span class="settings-toggle-track"></span>
    </label>
  </div>

  <div class="settings-row settings-row--nested${disClass}">
    <div class="settings-row-label">
      <div class="settings-row-title">Fonts</div>
      <div class="settings-row-hint">Deny uncommon fonts in document.fonts.check()</div>
    </div>
    <label class="settings-toggle" aria-label="Font enumeration defense">
      <input type="checkbox" id="setting-fp-defense-fonts"${s.fp_defense_fonts !== false ? ' checked' : ''}${disAttr}>
      <span class="settings-toggle-track"></span>
    </label>
  </div>

</div>`;
}

function bindFpDefenseSettingsEvents(saveSettingFieldFn) {
  const enabledToggle = document.getElementById('setting-fp-defense-enabled');
  if (!enabledToggle) return;

  const optionIds = [
    'setting-fp-defense-canvas',
    'setting-fp-defense-webgl',
    'setting-fp-defense-audio',
    'setting-fp-defense-navigator',
    'setting-fp-defense-fonts',
  ];

  function setFpDefenseArmed(armed) {
    for (const id of optionIds) {
      const el = document.getElementById(id);
      if (el) el.disabled = !armed;
    }
    document.querySelectorAll('#settings-fp-defense .settings-row--disabled').forEach((el) => {
      el.classList.remove('settings-row--disabled');
    });
    if (!armed) {
      document.querySelectorAll('#settings-fp-defense .settings-row--nested').forEach((el) => {
        el.classList.add('settings-row--disabled');
      });
    }
    const section = document.getElementById('settings-fp-defense');
    if (section) section.classList.toggle('settings-section--fp-defense-armed', armed);
  }

  enabledToggle.addEventListener('change', (e) => {
    saveSettingFieldFn('fp_defense_enabled', e.target.checked);
    setFpDefenseArmed(e.target.checked);
  });

  const toggleMap = {
    'setting-fp-defense-canvas': 'fp_defense_canvas',
    'setting-fp-defense-webgl': 'fp_defense_webgl',
    'setting-fp-defense-audio': 'fp_defense_audio',
    'setting-fp-defense-navigator': 'fp_defense_navigator',
    'setting-fp-defense-fonts': 'fp_defense_fonts',
  };
  for (const [id, key] of Object.entries(toggleMap)) {
    document.getElementById(id)?.addEventListener('change', (e) => {
      saveSettingFieldFn(key, e.target.checked);
    });
  }

  setFpDefenseArmed(enabledToggle.checked);
}
