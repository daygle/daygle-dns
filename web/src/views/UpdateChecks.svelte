<script>
  import { api, formatApiError } from '../api.js';

  // The `[updates]` settings: background release checks, automatic AI model
  // updates and scheduled stable-release installation. Saved on their own;
  // the API replaces the section as a unit, so every field is sent.
  let form = $state(null);
  let loaded = $state(null);
  let saving = $state(false);
  let notice = $state(null);
  let error = $state(null);

  const dirty = $derived(form !== null && JSON.stringify(form) !== loaded);

  async function load() {
    error = null;
    try {
      const updates = (await api.config()).updates || {};
      form = {
        enabled: updates.enabled ?? true,
        check_interval_secs: updates.check_interval_secs ?? 3600,
        auto_refresh_models: !!updates.auto_refresh_models,
        auto_install: !!updates.auto_install,
        auto_install_hour: updates.auto_install_hour ?? 3,
      };
      loaded = JSON.stringify(form);
    } catch (e) {
      error = formatApiError(e);
    }
  }

  async function save() {
    saving = true;
    notice = null;
    error = null;
    try {
      await api.updateSettings({
        updates: {
          enabled: !!form.enabled,
          check_interval_secs: Number(form.check_interval_secs) || 3600,
          auto_refresh_models: !!form.auto_refresh_models,
          auto_install: !!form.auto_install,
          auto_install_hour: Number(form.auto_install_hour),
        },
      });
      loaded = JSON.stringify(form);
      notice = 'Update settings saved.';
    } catch (e) {
      error = formatApiError(e);
    } finally {
      saving = false;
    }
  }

  $effect(() => {
    load();
  });
</script>

<div class="card" style="margin-bottom: 14px">
  <h3 style="margin: 0 0 10px">Update Checks</h3>
  {#if notice}<p class="ok-text">{notice}</p>{/if}
  {#if error}<p class="err-text">{error}</p>{/if}
  {#if form}
    <div class="grid">
      <label class="check"><input type="checkbox" bind:checked={form.enabled} /> <span>Check GitHub for Newer Releases</span></label>
      <label class="stacked">
        <span>Check Interval</span>
        <select bind:value={form.check_interval_secs} disabled={!form.enabled}>
          <option value={900}>Every 15 Minutes</option>
          <option value={3600}>Hourly</option>
          <option value={21600}>Every 6 Hours</option>
          <option value={86400}>Daily</option>
        </select>
      </label>
      <label class="check"><input type="checkbox" bind:checked={form.auto_refresh_models} /> <span>Keep AI Models up to Date</span></label>
      <label class="check"><input type="checkbox" bind:checked={form.auto_install} disabled={!form.enabled} /> <span>Automatically Install Stable Releases</span></label>
      <label class="stacked">
        <span>Install Hour (server display time zone)</span>
        <select bind:value={form.auto_install_hour} disabled={!form.enabled || !form.auto_install}>
          {#each Array.from({ length: 24 }, (_, hour) => hour) as hour}
            <option value={hour}>{String(hour).padStart(2, '0')}:00</option>
          {/each}
        </select>
      </label>
    </div>
    <p class="muted help">
      Checks run in the background, away from DNS traffic, and flag a newer
      release with a banner on the Status page. Intervals under 10 minutes are
      refused: GitHub's unauthenticated API allows 60 requests per hour per
      address, shared with everything else using this network. Turning checks
      off removes the banner; Update Now and the manual update command still
      work. Keeping AI models up to date installs a new model bundle when
      a check finds one, which restarts the service. Automatic stable-release
      installation is off by default; when enabled, the server checks for a
      stable release during the selected hour. The release is compiled before
      the binary swap, so DNS interruption is limited to installation and the
      service restart, not the several-minute build. There is still a DNS gap,
      so choose a quiet hour; 03:00 is a sensible default. The selected hour
      uses the display time zone and the update safety checks.
    </p>
    <div class="row" style="gap: 10px; align-items: center; margin-top: 12px">
      <button onclick={save} disabled={saving || !dirty}>{saving ? 'Saving...' : 'Save'}</button>
      {#if dirty}<button class="secondary" onclick={load} disabled={saving}>Discard Changes</button>{/if}
    </div>
  {/if}
</div>

<style>
  .grid { display: flex; flex-wrap: wrap; gap: 14px 24px; align-items: end; }
  .stacked { display: flex; flex-direction: column; gap: 4px; font-size: 0.85rem; color: var(--muted); }
  .check { display: flex; align-items: center; gap: 8px; }
  .check input { width: auto; }
  .ok-text { color: var(--ok); margin: 0 0 10px; }
  .err-text { color: var(--danger); margin: 0 0 10px; }
</style>
