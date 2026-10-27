<script>
  import { untrack } from 'svelte';
  import { api, formatApiError } from './api.js';
  import { formatDateTime } from './datetime.svelte.js';
  import { blockSourceLabel } from './blockSources.js';
  import ClientLabel from './ClientLabel.svelte';

  // Why a domain is (or is not) blocked for a device: the server's verdict,
  // every check in the order a query meets them, and the latest logged
  // blocks of the domain. `auto` runs it as soon as it opens (from a query
  // log row).
  let { domain = '', client = '', qtype = 'A', listener = '', auto = false } = $props();

  // The form starts from the props, then is the user's to edit.
  let form = $state(untrack(() => ({ domain, client, qtype: qtype || 'A', listener })));
  let result = $state(null);
  let error = $state(null);
  let busy = $state(false);

  const RESULT_LABELS = {
    block: 'Blocks',
    allow: 'Allows',
    rewrite: 'Rewrites',
    none: 'No Match',
    off: 'Not Active',
  };
  // How the answer reads (the API's action names).
  const ANSWERS = { block: 'NXDOMAIN', refused: 'REFUSED', nodata: 'No Data', redirect: 'Redirect' };
  const LISTENERS = [
    ['', 'Plain DNS'],
    ['dot', 'DNS over TLS'],
    ['doh', 'DNS over HTTPS'],
    ['doq', 'DNS over QUIC'],
  ];

  async function run() {
    if (!form.domain.trim() || !form.client.trim()) return;
    busy = true;
    error = null;
    try {
      const params = { domain: form.domain.trim(), client: form.client.trim(), qtype: form.qtype || 'A' };
      if (form.listener) params.listener = form.listener;
      result = await api.explainBlocking(params);
    } catch (e) {
      result = null;
      error = formatApiError(e);
    } finally {
      busy = false;
    }
  }

  // The check that decided, highlighted in the list.
  function decides(check) {
    const v = result?.verdict;
    if (!v?.source || check.source !== v.source) return false;
    if (v.group && check.group !== v.group) return false;
    return !v.matched || !check.matched || check.matched === v.matched;
  }

  $effect(() => {
    if (auto) run();
  });
</script>

<form class="ask" onsubmit={(e) => { e.preventDefault(); run(); }}>
  <label>Domain <input placeholder="ads.example.com" bind:value={form.domain} spellcheck="false" /></label>
  <label>Device <input placeholder="192.168.1.20 or a device name" bind:value={form.client} spellcheck="false" /></label>
  <label>Type
    <select bind:value={form.qtype}>
      {#each ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'HTTPS'] as t (t)}<option value={t}>{t}</option>{/each}
    </select>
  </label>
  <label>Asked Over
    <select bind:value={form.listener}>
      {#each LISTENERS as [value, label] (value)}<option value={value}>{label}</option>{/each}
    </select>
  </label>
  <button type="submit" disabled={busy || !form.domain.trim() || !form.client.trim()}>{busy ? 'Checking...' : 'Check'}</button>
</form>

{#if error}<p class="error">{error}</p>{/if}

{#if result}
  <div class="verdict" class:blocked={result.verdict.blocked}>
    <span class="pill" class:err={result.verdict.blocked} class:ok={!result.verdict.blocked}>
      {result.verdict.blocked ? 'Blocked' : 'Not Blocked'}
    </span>
    <span>
      <code>{result.domain}</code> for <ClientLabel address={result.client} />:
      {result.verdict.reason}
    </span>
    {#if result.verdict.blocked}
      <div class="muted small">
        By {blockSourceLabel(result.verdict.source)}{#if result.verdict.group} in group <strong>{result.verdict.group}</strong>{/if}{#if result.verdict.matched}{' '}· matched <code>{result.verdict.matched}</code>{/if}
        {' '}· answered {ANSWERS[result.verdict.action] || result.verdict.action}
      </div>
    {/if}
  </div>

  <h4>Every Check, in Order</h4>
  {#if result.checks.length === 0}
    <p class="muted">Nothing is set up that could block this domain for this device.</p>
  {:else}
    <div class="table-wrap">
      <table>
        <thead><tr><th>Check</th><th>Result</th><th>Details</th></tr></thead>
        <tbody>
          {#each result.checks as check, i (i)}
            <tr class:decides={decides(check)}>
              <td style="white-space: nowrap">{blockSourceLabel(check.source)}{#if check.group}<div class="muted small">{check.group}</div>{/if}</td>
              <td>
                <span class="pill" class:err={check.result === 'block'} class:ok={check.result === 'allow'} class:warn={check.result === 'rewrite'}>
                  {RESULT_LABELS[check.result] || check.result}
                </span>
              </td>
              <td>{check.detail}{#if decides(check)} <span class="pill decided">Decides</span>{/if}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
  <p class="muted help">
    A query meets these checks top to bottom: the allow list stops every later
    check, the first block answers the query, and a filtering group's own
    allow entries stop later groups. CNAME inspection and response policy
    zone rules on answers run once the answer arrives, so they show in the
    recent blocks below rather than here.
  </p>

  <h4>Recent Blocks of This Domain</h4>
  {#if result.recent.length === 0}
    <p class="muted">No blocks of <code>{result.domain}</code> in the query log.</p>
  {:else}
    <div class="table-wrap">
      <table>
        <thead><tr><th>Time</th><th>Device</th><th>Blocked By</th><th>Reason</th></tr></thead>
        <tbody>
          {#each result.recent as row (row.id)}
            <tr>
              <td style="white-space: nowrap">{formatDateTime(row.ts)}</td>
              <td><ClientLabel address={row.client} /></td>
              <td>{row.block ? blockSourceLabel(row.block.source) : '-'}{#if row.block?.group}<div class="muted small">{row.block.group}</div>{/if}</td>
              <td class="muted">{row.block?.reason || 'Logged before reasons were kept'}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
{/if}

<style>
  .ask { display: flex; flex-wrap: wrap; gap: 10px; align-items: flex-end; margin-bottom: 12px; }
  .ask label { display: flex; flex-direction: column; gap: 4px; flex: 1 1 160px; }
  .ask button { flex: 0 0 auto; }
  .error { color: var(--danger); }
  .verdict { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; padding: 10px 12px; border: 1px solid var(--ok); border-radius: 8px; margin-bottom: 14px; }
  .verdict.blocked { border-color: var(--danger); }
  .verdict .small { flex-basis: 100%; }
  .small { font-size: 0.8rem; }
  h4 { margin: 14px 0 8px; }
  tr.decides td { background: color-mix(in srgb, var(--danger) 10%, transparent); }
  .pill.decided { margin-left: 6px; }
</style>
