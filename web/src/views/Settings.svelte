<script>
  import { api } from '../api.js';

  let config = $state(null);
  let notice = $state(null);

  $effect(() => {
    api.config()
      .then((c) => (config = c))
      .catch((e) => (notice = String(e.message || e)));
  });

  let token = $state(localStorage.getItem('daygle_token') || '');

  function saveToken() {
    if (token.trim()) localStorage.setItem('daygle_token', token.trim());
    else localStorage.removeItem('daygle_token');
    notice = 'API token saved.';
  }

  async function clearCache() {
    try {
      await api.clearCache();
      notice = 'Recursive cache cleared.';
    } catch (e) {
      notice = `Error: ${e.message || e}`;
    }
  }
</script>

<h1>Settings</h1>

<div class="card" style="margin-bottom: 16px">
  <h3 style="margin-top: 0">Operations</h3>
  <div class="row">
    <button onclick={clearCache}>Flush recursive cache</button>
  </div>
</div>

<div class="card" style="margin-bottom: 16px">
  <h3 style="margin-top: 0">API token</h3>
  <p class="muted">
    Provide the <code>api_token</code> configured on the server to authorize
    write operations from this browser.
  </p>
  <div class="row">
    <input type="password" placeholder="Bearer token" bind:value={token} />
    <button onclick={saveToken}>Save</button>
  </div>
</div>

{#if notice}
  <div class="card" style="border-color: var(--accent)">{notice}</div>
{/if}

<div class="card">
  <h3 style="margin-top: 0">Effective configuration</h3>
  {#if config}
    <pre>{JSON.stringify(config, null, 2)}</pre>
  {:else}
    <p class="muted">Loading…</p>
  {/if}
</div>

<style>
  pre {
    background: var(--panel-2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px;
    overflow: auto;
    max-height: 60vh;
    font-size: 0.8rem;
  }
</style>
