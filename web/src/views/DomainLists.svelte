<script>
  import { api, formatApiError } from '../api.js';

  let config = $state(null);
  let trusted = $state('');
  let blocked = $state('');
  let busy = $state(false);
  let error = $state(null);
  let notice = $state(null);

  async function load() {
    error = null;
    try {
      config = await api.config();
      if (config == null) {
        trusted = '';
        blocked = '';
        return;
      }
      trusted = (config.policy?.allowlist || []).join('\n');
      blocked = (config.policy?.blocklist || []).join('\n');
    } catch (e) {
      error = formatApiError(e);
    }
  }

  function parse(text) {
    // Split on newlines and commas, trim, deduplicate, and keep the original
    // casing so the editor can round-trip what the user typed. The backend
    // normalizes domains for comparison, so case here is cosmetic but not
    // semantically required.
    return [...new Set((text || '').split(/[\n,]/).map((s) => s.trim()).filter(Boolean))];
  }

  async function save() {
    busy = true;
    error = null;
    notice = null;
    try {
      await api.updateSettings({ policy: { allowlist: parse(trusted), blocklist: parse(blocked) } });
      notice = 'Domain lists saved and applied live.';
      await load();
    } catch (e) {
      error = formatApiError(e);
    } finally {
      busy = false;
    }
  }

  $effect(() => load());
</script>

<h1>Domain Lists</h1>
<p class="muted" style="max-width: 75ch">
  Add domains that should always be trusted or always blocked. Enter one
  domain per line; use <code>*.example.com</code> for subdomains. Trusted
  domains take precedence over domain blocking, including remote blocklist
  sources. Client access-control rules remain authoritative.
</p>

{#if notice}
  <div class="card" style="border-color: var(--ok); margin-bottom: 14px">{notice}</div>
{/if}
{#if error}
  <div class="card" style="border-color: var(--danger); color: var(--danger); margin-bottom: 14px">{error}</div>
{/if}

{#if config}
  <div class="lists">
    <div class="card">
      <h3 style="margin-top: 0">Trusted Domains (Allowlist)</h3>
      <p class="muted small">These domains bypass the normal blocklist and remote sources.</p>
      <textarea rows="14" bind:value={trusted} placeholder="updates.example.com\n*.trusted.example"></textarea>
    </div>
    <div class="card">
      <h3 style="margin-top: 0">Blocked Domains (Blocklist)</h3>
      <p class="muted small">These domains are blocked before normal resolution.</p>
      <textarea rows="14" bind:value={blocked} placeholder="ads.example.com\n*.tracking.example"></textarea>
    </div>
  </div>
  <div class="row" style="margin-top: 14px">
    <button onclick={save} disabled={busy}>{busy ? 'Saving…' : 'Save'}</button>
    <button class="secondary" onclick={load} disabled={busy}>Reload</button>
  </div>
{:else}
  <p class="muted">Loading…</p>
{/if}

<style>
  .lists { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; }
  textarea { width: 100%; min-height: 260px; background: var(--panel-2); border: 1px solid var(--border); border-radius: 6px; padding: 8px; font: inherit; color: inherit; resize: vertical; }
  .small { font-size: 0.8rem; }
  @media (max-width: 760px) { .lists { grid-template-columns: 1fr; } }
</style>
