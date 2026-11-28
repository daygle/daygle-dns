<script>
  import { api, formatApiError } from '../api.js';
  import { changedAiSettings } from './aiSettingsPatch.js';
  import SettingsForm from './SettingsForm.svelte';

  // AI -> Settings: when and how the scanner runs and when its detections
  // block. Saved on its own (a partial `ai` update), so the switches on the
  // Scanner tab and the threat labels on the Threats tab are left alone.
  // `onSaved` lets the page refresh what depends on these values.
  let { onSaved = () => {} } = $props();

  // The fields this form edits, and the units it shows them in (minutes,
  // days, percent); turned back into seconds and fractions on save.
  const KEYS = ['enabled', 'mode', 'workers', 'max_domains_per_scan', 'scan_interval_secs', 'expire_check_secs',
    'block_threshold', 'confidence_floor', 'category_ttl_secs', 'threat_ttl_secs',
    'autonomy', 'threshold_fpr_target', 'fusion', 'authority'];

  // The built-in authority stages, so the section works on an install whose
  // saved settings predate it (and after a reset).
  const AUTHORITY_DEFAULTS = {
    enabled: false,
    feed_stage: 'enforce',
    model_stage: 'propose',
    operator_stage: 'enforce',
    max_new_blocks_per_refresh: 500,
    demote_fp_rate: 0.05,
    demote_min_samples: 20,
    advancement: false,
    advance_min_reviews: 20,
    advance_fp_rate: 0.05,
  };
  const STAGES = [
    ['monitor', 'Monitor - Record Only'],
    ['propose', 'Propose - List, Never Block'],
    ['enforce', 'Enforce - May Block'],
  ];

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
    ai_ = {
      ...Object.fromEntries(KEYS.map((k) => [k, src[k]])),
      mode: src.mode || 'train',
      fusion: src.fusion || 'monitor',
      authority: { ...AUTHORITY_DEFAULTS, ...(src.authority || {}) },
    };
    aiForm = {
      scanMinutes: round2(src.scan_interval_secs / 60),
      expireMinutes: round2(src.expire_check_secs / 60),
      threatDays: round2(src.threat_ttl_secs / 86400),
      categoryDays: round2(src.category_ttl_secs / 86400),
      thresholdPct: round2(src.block_threshold * 100),
      floorPct: round2(src.confidence_floor * 100),
      fprPct: round2((src.threshold_fpr_target ?? 0.01) * 100),
      demotePct: round2((src.authority?.demote_fp_rate ?? AUTHORITY_DEFAULTS.demote_fp_rate) * 100),
      advancePct: round2((src.authority?.advance_fp_rate ?? AUTHORITY_DEFAULTS.advance_fp_rate) * 100),
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
      threshold_fpr_target: Number(aiForm.fprPct) / 100,
      // Explicit, not `undefined`: an absent field keeps the saved value, and
      // an unticked box has to send false.
      autonomy: !!ai_.autonomy,
      category_ttl_secs: Math.round(Number(aiForm.categoryDays) * 86400),
      threat_ttl_secs: Math.round(Number(aiForm.threatDays) * 86400),
      fusion: ai_.fusion || 'monitor',
      authority: {
        enabled: !!ai_.authority.enabled,
        feed_stage: ai_.authority.feed_stage,
        model_stage: ai_.authority.model_stage,
        // Preserve the saved value when the console updates the other stages.
        operator_stage: ai_.authority.operator_stage,
        max_new_blocks_per_refresh: Number(ai_.authority.max_new_blocks_per_refresh),
        demote_fp_rate: Number(aiForm.demotePct) / 100,
        demote_min_samples: Number(ai_.authority.demote_min_samples),
        advancement: !!ai_.authority.advancement,
        advance_min_reviews: Number(ai_.authority.advance_min_reviews),
        advance_fp_rate: Number(aiForm.advancePct) / 100,
      },
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

  // What the server would refuse, said in the form's own units before the
  // round trip (an empty box reads as 0 and failed with a server message
  // about seconds and fractions).
  function problem(body) {
    const blank = Object.entries(aiForm).some(([, v]) => v === '' || v == null)
      || ai_.workers === '' || ai_.workers == null
      || ai_.max_domains_per_scan === '' || ai_.max_domains_per_scan == null
      || ai_.authority.max_new_blocks_per_refresh === '' || ai_.authority.max_new_blocks_per_refresh == null
      || ai_.authority.demote_min_samples === '' || ai_.authority.demote_min_samples == null;
    if (blank) return 'Fill in every field before saving.';
    if (!(body.block_threshold >= 0.5 && body.block_threshold <= 1)) {
      return 'Block Threshold must be between 50 and 100%.';
    }
    if (!(body.confidence_floor >= 0 && body.confidence_floor < body.block_threshold)) {
      return 'Confidence Floor must be at least 0% and below the Block Threshold.';
    }
    if (!(body.threshold_fpr_target >= 0 && body.threshold_fpr_target <= 0.5)) {
      return 'False-Positive Target must be between 0 and 50%.';
    }
    if (!(body.workers >= 1 && body.workers <= 32)) return 'Classification Workers must be between 1 and 32.';
    if (!(body.max_domains_per_scan >= 1)) return 'Domains Classified Per Scan must be at least 1.';
    if (!(body.authority.max_new_blocks_per_refresh >= 1 && body.authority.max_new_blocks_per_refresh <= 500)) {
      return 'New Blocks Per Refresh must be between 1 and 500.';
    }
    if (!(body.authority.demote_fp_rate >= 0 && body.authority.demote_fp_rate <= 1)) {
      return 'The Auto-Demote False-Positive Share must be between 0 and 100%.';
    }
    if (!(body.authority.demote_min_samples >= 1)) {
      return 'Auto-Demote needs at least one measured finding.';
    }
    if (!Number.isInteger(body.authority.advance_min_reviews) || body.authority.advance_min_reviews < 1) {
      return 'Auto-Advance needs at least one reviewed finding per stage.';
    }
    if (!(body.authority.advance_fp_rate >= 0 && body.authority.advance_fp_rate <= 1)) {
      return 'The Auto-Advance Correction Share must be between 0 and 100%.';
    }
    if (body.enabled && (body.scan_interval_secs < 10 || body.expire_check_secs < 10)) {
      return 'Scan and expiry intervals must be at least 10 seconds (0.17 minutes).';
    }
    if (body.threat_ttl_secs < 60 || body.category_ttl_secs < 60) {
      return 'Re-check periods must be at least a minute (0.01 days is about 14 minutes).';
    }
    return null;
  }

  async function save() {
    if (busy) return;
    notice = null;
    const body = buildBody();
    error = problem(body);
    if (error) return;
    busy = true;
    try {
      const patch = changedAiSettings(JSON.parse(savedBody), body);
      if (Object.keys(patch).length === 0) return;
      await api.updateSettings({ ai: patch });
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
    if (busy) return;
    if (!confirm('Reset the AI settings to their defaults? Nothing is saved until you click Save Changes.')) return;
    notice = null;
    error = null;
    busy = true;
    try {
      const d = await api.configDefaults();
      fill(d.ai || {});
      notice = 'AI settings reset to their defaults. Click Save Changes to apply them.';
    } catch (e) {
      error = formatApiError(e);
    } finally {
      busy = false;
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
      <label class="check"><input type="checkbox" bind:checked={ai_.autonomy} /> <span>Let The Scanner Work On Its Own</span></label>
      <label>
        <span>Mode</span>
        <select bind:value={ai_.mode}>
          <option value="train">Train - Record Only</option>
          <option value="enforce">Enforce - Auto-Block Threats</option>
        </select>
      </label>
    </div>
    {#if ai_.enabled && !aiRunning}
      <p class="help restart">The scanner starts after the next restart.</p>
    {/if}
    <p class="muted help">
      Start in Train mode and check the Threats tab before switching to
      Enforce. Exempt domains are never blocked.
    </p>
    <p class="muted help">
      With autonomy off, the scanner still expires old entries and keeps its
      block snapshot current, but it stops harvesting domains, classifying,
      reading pages and retraining itself. Enforcement and Mode are unchanged:
      a threat already found can still block.
    </p>

    <h4>Scanning</h4>
    <div class="form-grid">
      <label><span>Scan Every (Minutes)</span><input type="number" min="0.17" step="any" bind:value={aiForm.scanMinutes} /></label>
      <label><span>Domains Classified Per Scan</span><input type="number" min="1" bind:value={ai_.max_domains_per_scan} /></label>
      <label><span>Classification Workers</span><input type="number" min="1" max="32" bind:value={ai_.workers} /></label>
    </div>
    <p class="muted help">
      Domains over the per-scan limit wait for the next scan.
    </p>

    <h4>Enforcement</h4>
    <div class="form-grid">
      <label><span>Block Threshold (%)</span><input type="number" min="50" max="100" step="any" bind:value={aiForm.thresholdPct} /></label>
      <label><span>Confidence Floor (%)</span><input type="number" min="0" max="99" step="any" bind:value={aiForm.floorPct} /></label>
      <label><span>False-Positive Target (%)</span><input type="number" min="0" max="50" step="any" bind:value={aiForm.fprPct} /></label>
    </div>
    <p class="muted help">
      In Enforce mode a threat blocks once its confidence reaches the block
      threshold, unless it is disputed. Detections below the confidence floor
      are ignored. Which labels count as threats is set on the Threats tab.
    </p>
    <p class="muted help">
      The false-positive target is what a threshold trial aims for on
      established and unseen domains: run one on the Threats tab. A trial never
      changes the threshold by itself.
    </p>

    <h4>Lifetime</h4>
    <div class="form-grid">
      <label><span>Re-Check Threats After (Days)</span><input type="number" min="0.01" step="any" bind:value={aiForm.threatDays} /></label>
      <label><span>Re-Check Classifications After (Days)</span><input type="number" min="0.01" step="any" bind:value={aiForm.categoryDays} /></label>
      <label><span>Look for Expired Entries Every (Minutes)</span><input type="number" min="0.17" step="any" bind:value={aiForm.expireMinutes} /></label>
    </div>
    <p class="muted help">
      Domains are re-checked after this long (14 and 90 days by default). An
      expired threat stops blocking until it is checked again, so keep the
      expiry check frequent: it is cheap.
    </p>
  </div>

  <div class="card">
    <h3 style="margin: 0 0 6px">Scoring</h3>
    <p class="muted help">
      How the inputs behind a threat verdict become the score the block
      threshold compares. The defaults record everything and change nothing.
    </p>
    <div class="form-grid">
      <label>
        <span>Signal Fusion</span>
        <select bind:value={ai_.fusion}>
          <option value="monitor">Monitor - Record the Fused Score</option>
          <option value="decide">Decide - The Fused Score Sets the Gate</option>
          <option value="off">Off - Observations Only</option>
        </select>
      </label>
    </div>
    <p class="muted help">
      Monitor records the fused score beside each verdict and keeps comparing
      the model confidence. Decide makes the fused score the assessment, so
      the block threshold and any threshold trial measure that instead; stored
      verdicts are re-scored when you save. Off records the observations only.
    </p>

    <h4>Enforcement Authority</h4>
    <label class="check"><input type="checkbox" bind:checked={ai_.authority.enabled} /> <span>Grade Authority per Evidence Source</span></label>
    <label class="check"><input type="checkbox" bind:checked={ai_.authority.advancement} disabled={!ai_.authority.enabled} /> <span>Advance Authority From Reviewed Findings</span></label>
    <div class="form-grid">
      <label>
        <span>Feed-Confirmed Findings</span>
        <select bind:value={ai_.authority.feed_stage}>
          {#each STAGES as [value, label] (value)}<option value={value}>{label}</option>{/each}
        </select>
      </label>
      <label>
        <span>Model-Only Findings</span>
        <select bind:value={ai_.authority.model_stage}>
          {#each STAGES as [value, label] (value)}<option value={value}>{label}</option>{/each}
        </select>
      </label>
      <label><span>New Blocks Per Refresh (Max 500)</span><input type="number" min="1" max="500" bind:value={ai_.authority.max_new_blocks_per_refresh} /></label>
      <label><span>Auto-Demote Above (% False Positives)</span><input type="number" min="0" max="100" step="any" bind:value={aiForm.demotePct} /></label>
      <label><span>Auto-Demote After (Measured Findings)</span><input type="number" min="1" bind:value={ai_.authority.demote_min_samples} /></label>
      {#if ai_.authority.advancement}
        <label><span>Reviews Required per Advancement Stage</span><input type="number" min="1" bind:value={ai_.authority.advance_min_reviews} /></label>
        <label><span>Maximum Auto-Advance Correction Share (%)</span><input type="number" min="0" max="100" step="any" bind:value={aiForm.advancePct} /></label>
      {/if}
    </div>
    <p class="muted help">
      Off leaves the Mode setting alone deciding what may block. When on, a
      source at Monitor or Propose is recorded and listed but never blocks,
      and a source whose measured false-positive share passes the auto-demote
      share is demoted to Monitor on its own. Your labels and overrides are
      never filtered or demoted. New Blocks Per Refresh can tighten the
      built-in 500 ceiling, never raise it.
      With advancement enabled, the selected stages are ceilings. Sources
      begin in Monitor and advance using confirmed and corrected reviews.
    </p>
  </div>
</SettingsForm>
