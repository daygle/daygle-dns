<script>
  import { api, formatApiError } from '../api.js';
  import SettingsForm from './SettingsForm.svelte';

  // AI -> Settings: when and how the scanner runs and when its detections
  // block. Saved on its own (a partial `ai` update), so the switches on the
  // Scanner tab and the threat labels on the Threats tab are left alone.
  // `onSaved` lets the page refresh what depends on these values.
  let { onSaved = () => {} } = $props();

  // The fields this form edits, and the units it shows them in (minutes,
  // days, percent); turned back into seconds and fractions on save.
  const KEYS = ['enabled', 'mode', 'workers', 'max_domains_per_scan', 'scan_interval_secs', 'expire_check_secs',
    'block_threshold', 'confidence_floor', 'category_ttl_secs', 'threat_ttl_secs'];

  let ai_ = $state(null);
  let aiForm = $state({});
  // Whether a scanner is running now (it is only built at startup).
  let aiRunning = $state(false);
  let savedBody = $state('');
  let busy = $state(false);
  let notice = $state(null);
  let error = $state(null);
  const dirty = $derived(ai_ != null && savedBody !== '' && JSON.stringify(buildBody()) !== savedBody);

  // 4.999999 -> 5 (unit conversions).
  function round2(n) {
    return Math.round(Number(n || 0) * 100) / 100;
  }

  function fill(src) {
    ai_ = { ...Object.fromEntries(KEYS.map((k) => [k, src[k]])), mode: src.mode || 'train' };
    aiForm = {
      scanMinutes: round2(src.scan_interval_secs / 60),
      expireMinutes: round2(src.expire_check_secs / 60),
      threatDays: round2(src.threat_ttl_secs / 86400),
      categoryDays: round2(src.category_ttl_secs / 86400),
      thresholdPct: round2(src.block_threshold * 100),
      floorPct: round2(src.confidence_floor * 100),
    };
  }

  function buildBody() {
    return {
      enabled: !!ai_.enabled,
      mode: ai_.mode || 'train',
      workers: Number(ai_.workers),
      max_domains_per_scan: Number(ai_.max_domains_per_scan),
      scan_interval_secs: Math.round(Number(aiForm.scanMinutes) * 60),
      expire_check_secs: Math.round(Number(aiForm.expireMinutes) * 60),
      block_threshold: Number(aiForm.thresholdPct) / 100,
      confidence_floor: Number(aiForm.floorPct) / 100,
      category_ttl_secs: Math.round(Number(aiForm.categoryDays) * 86400),
      threat_ttl_secs: Math.round(Number(aiForm.threatDays) * 86400),
    };
  }

  async function load() {
    error = null;
    try {
      const config = await api.config();
      fill(config.ai || {});
      savedBody = JSON.stringify(buildBody());
    } catch (e) {
      error = formatApiError(e);
    }
    api.aiStatus().then(() => { aiRunning = true; }).catch(() => { aiRunning = false; });
  }

  function reload() {
    if (dirty && !confirm('Discard your unsaved changes?')) return;
    notice = null;
    load();
  }

  async function save() {
    busy = true;
    notice = null;
    error = null;
    try {
      await api.updateSettings({ ai: buildBody() });
      notice = 'AI settings saved and applied.';
      await load();
      onSaved();
    } catch (e) {
      error = formatApiError(e);
    } finally {
      busy = false;
    }
  }

  // Fill the form with the built-in defaults; nothing is saved until Save.
  async function reset() {
    if (!confirm('Reset the AI settings to their defaults? Nothing is saved until you click Save Changes.')) return;
    notice = null;
    error = null;
    try {
      const d = await api.configDefaults();
      fill(d.ai || {});
      notice = 'AI settings reset to their defaults. Click Save Changes to apply them.';
    } catch (e) {
      error = formatApiError(e);
    }
  }

  $effect(() => {
    load();
  });
</script>

<SettingsForm loaded={ai_ != null} {dirty} {busy} {notice} {error} onSave={save} onReload={reload} onReset={reset}>
  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">AI Safety Scanner</h3>
    <div class="form-grid">
      <label class="check"><input type="checkbox" bind:checked={ai_.enabled} /> <span>Enable AI Scanner</span></label>
      <label>
        <span>Mode</span>
        <select bind:value={ai_.mode}>
          <option value="train">Train - Record Only</option>
          <option value="enforce">Enforce - Auto-Block Qualifying Domains</option>
        </select>
      </label>
    </div>
    {#if ai_.enabled && !aiRunning}
      <p class="help restart">The scanner starts after the next restart.</p>
    {/if}
    <p class="muted help">
      Classifies the domains seen in your DNS traffic in the background, never
      on the query path. Start in Train mode and review the Classifications
      and Threats tabs before switching to Enforce. Custom Allow
      entries and domains on the Exemptions tab are never blocked.
    </p>

    <h4>Scanning</h4>
    <div class="form-grid">
      <label><span>Scan Every (Minutes)</span><input type="number" min="0.17" step="any" bind:value={aiForm.scanMinutes} /></label>
      <label><span>Domains Classified Per Scan</span><input type="number" min="1" bind:value={ai_.max_domains_per_scan} /></label>
      <label><span>Classification Workers</span><input type="number" min="1" max="32" bind:value={ai_.workers} /></label>
    </div>
    <p class="muted help">
      Each scan picks up the domains queried since the previous one and
      classifies up to the per-scan limit (the rest wait for the next scan),
      on this many background threads.
    </p>

    <h4>Enforcement</h4>
    <div class="form-grid">
      <label><span>Block Threshold (%)</span><input type="number" min="50" max="100" step="any" bind:value={aiForm.thresholdPct} /></label>
      <label><span>Confidence Floor (%)</span><input type="number" min="0" max="99" step="any" bind:value={aiForm.floorPct} /></label>
    </div>
    <p class="muted help">
      Which labels count as threats is chosen on the Threats tab, next to
      the list it produces. This tab keeps the thresholds and lifetimes that
      decide when a detected threat blocks.
    </p>
    <p class="muted help">
      In Enforce mode a domain is blocked when a detected threat reaches the
      block threshold (50 to 100%) and the verifier does not dispute it. With
      the shared classifier it must also carry a label treated as a threat (set
      on the Threats tab); a dedicated threat model reports its own threats, so
      every label it produces blocks. Detections below the confidence floor are
      recorded as skipped.
      Content classifications never auto-block on their own: blocking a
      category is a filtering-group rule.
    </p>

    <h4>Lifetime</h4>
    <div class="form-grid">
      <label><span>Re-Check Threats After (Days)</span><input type="number" min="0.01" step="any" bind:value={aiForm.threatDays} /></label>
      <label><span>Re-Check Classifications After (Days)</span><input type="number" min="0.01" step="any" bind:value={aiForm.categoryDays} /></label>
      <label><span>Look for Expired Entries Every (Minutes)</span><input type="number" min="0.17" step="any" bind:value={aiForm.expireMinutes} /></label>
    </div>
    <p class="muted help">
      Each channel keeps its own lifetime: an expired threat stops blocking,
      and an expired classification stops matching blocked categories, until
      the domain is scanned again. Threats (malware, phishing) age out faster
      than classifications, which rarely change.
    </p>
  </div>
</SettingsForm>
