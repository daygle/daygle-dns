<script>
  import { api } from '../api.js';

  let logs = $state([]);
  let error = $state(null);

  async function refresh() {
    error = null;
    try {
      logs = await api.logs(300);
    } catch (e) {
      error = String(e.message || e);
    }
  }

  $effect(() => { refresh(); });
</script>

<h1>Logs</h1>

<div class="row" style="margin-bottom: 14px">
  <button class="secondary" onclick={refresh}>Refresh</button>
  <span class="muted">Showing the most recent {logs.length} entries</span>
</div>

{#if error}
  <div class="card" style="border-color: var(--danger); color: var(--danger)">{error}</div>
{:else}
  <div class="card" style="padding: 0; overflow: auto; max-height: 70vh">
    <table>
      <thead>
        <tr><th>Time</th><th>Level</th><th>Component</th><th>Message</th></tr>
      </thead>
      <tbody>
        {#each logs as entry (entry.timestamp + entry.component + entry.message)}
          <tr>
            <td style="white-space: nowrap">{entry.timestamp}</td>
            <td><span class:pill={true} class:ok={entry.level === 'info'} class:err={entry.level === 'error'}>
              {entry.level}
            </span></td>
            <td>{entry.component}</td>
            <td><code>{entry.message}</code></td>
          </tr>
        {/each}
      </tbody>
    </table>
    {#if logs.length === 0}
      <p class="muted" style="padding: 14px">No log entries yet.</p>
    {/if}
  </div>
{/if}
