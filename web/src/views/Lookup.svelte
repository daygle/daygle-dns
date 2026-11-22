<script>
  import { api, formatApiError } from '../api.js';
  import PageHeader from '../PageHeader.svelte';
  import { icons } from '../icons.svelte.js';
  import { reverseRecordName } from '../reverseZone.js';

  // Resolve one name the way client queries are resolved and show why it
  // worked or failed: the answer, the reason for a failure, and every
  // query the resolver sent on the way (POST /api/resolver/lookup).

  const TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'PTR', 'SRV', 'CAA', 'HTTPS', 'SVCB', 'DS', 'DNSKEY', 'TLSA', 'NAPTR'];

  let name = $state('');
  let type = $state('A');
  let fresh = $state(true);
  let busy = $state(false);
  let error = $state(null);
  let result = $state(null);

  // An IP address typed in is looked up by its reverse name (like dig -x).
  const reverse = $derived(/^[0-9a-fA-F:.]+$/.test(name.trim()) && (name.includes(':') || /^\d+\.\d+\.\d+\.\d+$/.test(name.trim()))
    ? reverseRecordName(name.trim())
    : null);

  async function lookup() {
    const query = reverse || name.trim();
    if (!query) return;
    busy = true;
    error = null;
    result = null;
    try {
      result = await api.resolverLookup(query, reverse ? 'PTR' : type, fresh);
    } catch (e) {
      error = formatApiError(e);
    } finally {
      busy = false;
    }
  }

  // What a failure message means, in plain words, with what to try.
  function explain(message) {
    const m = (message || '').toLowerCase();
    if (m.includes('refused'))
      return 'A name server for this domain refused to answer. It is usually misconfigured (lame) for this zone; the trace shows which one.';
    if (m.includes('recursion limit') || m.includes('query budget'))
      return 'The resolver gave up after too many steps. The trace shows where the walk went.';
    if (m.includes('timed out') || m.includes('timeout'))
      return 'No name server answered in time. Usually the zone\'s own name servers are the problem: they are down, no longer host the zone, or drop its queries (the trace names them; if they ignore the zone over IPv4 too, nothing on this server can fix it). Only if those servers do answer other tools, check this server\'s IPv6 route, or set Outbound IP Versions to IPv4.';
    if (m.includes('dnssec') || m.includes('bogus') || m.includes('rrsig') || m.includes('nsec'))
      return 'The answer failed DNSSEC validation: the signatures are missing, expired or do not match.';
    if (m.includes('no glue') || m.includes('no nameserver found'))
      return 'The resolver could not find a working name server for the zone.';
    if (m.includes('servfail'))
      return 'An upstream server reported a failure of its own (SERVFAIL).';
    return null;
  }

  function rcodeClass(rcode) {
    if (!rcode) return 'bad';
    if (rcode === 'NOERROR') return 'ok';
    if (rcode === 'NXDOMAIN') return 'warn';
    return 'bad';
  }

  const ROUTES = {
    recursive: 'Recursive (from the root servers)',
    forwarding: 'Forwarded to upstreams',
    conditional: 'Conditional forwarder',
    stub: 'Stub zone',
    'local-root': 'Local root zone',
  };

  const servers = $derived(result ? new Set(result.trace.map((s) => s.server)).size : 0);
  const failedSteps = $derived(result ? result.trace.filter((s) => !s.rcode || !['NOERROR', 'NXDOMAIN'].includes(s.rcode)).length : 0);
</script>

<PageHeader
  icon={icons.lookup}
  title="Lookup"
  tagline="Resolve a name the way client queries are resolved and see why it works or fails: the answer, the reason for a failure, and every query sent to other name servers on the way. Filtering does not apply here; use Filtering → Domain Check for that."
/>

<div class="card">
  <form class="lookup" onsubmit={(e) => { e.preventDefault(); lookup(); }}>
    <label class="name">
      <span>Domain Name or IP Address</span>
      <input placeholder="www.example.com or 2001:db8::1" bind:value={name} autocomplete="off" spellcheck="false" />
    </label>
    <label>
      <span>Record Type</span>
      <select bind:value={type} disabled={!!reverse}>
        {#each TYPES as t (t)}<option value={t}>{t}</option>{/each}
      </select>
    </label>
    <button type="submit" disabled={busy || !name.trim()}>{busy ? 'Looking Up...' : 'Look Up'}</button>
  </form>
  <label class="check">
    <input type="checkbox" bind:checked={fresh} />
    Start from empty caches (every step from the root servers is taken and listed)
  </label>
  {#if reverse}
    <p class="muted help">Looking up the PTR record of this address: <code>{reverse}</code></p>
  {/if}
</div>

{#if error}
  <div class="card" style="border-color: var(--danger); color: var(--danger); margin-top: 14px">{error}</div>
{/if}

{#if result}
  <div class="card" style="margin-top: 14px">
    <div class="spread" style="margin-bottom: 10px">
      <h3 style="margin: 0; overflow-wrap: anywhere">{result.name} {result.type}</h3>
      <span class="pill {rcodeClass(result.rcode)}">{result.rcode}</span>
    </div>
    <div class="summary">
      <div class="pair"><span class="muted">Resolved By</span><span class="value">{ROUTES[result.route] || result.route}</span></div>
      <div class="pair"><span class="muted">Time</span><span class="value">{result.elapsed_ms.toLocaleString()} ms</span></div>
      <div class="pair"><span class="muted">Queries Sent</span><span class="value">{result.trace.length} to {servers} {servers === 1 ? 'server' : 'servers'}</span></div>
      <div class="pair"><span class="muted">DNSSEC Validation</span><span class="value">{result.dnssec_validation ? 'On' : 'Off'}</span></div>
    </div>

    {#if result.error}
      <div class="reason">
        <strong>Why it failed</strong>
        {#if explain(result.error)}<p>{explain(result.error)}</p>{/if}
        <code>{result.error}</code>
      </div>
    {:else if result.rcode === 'NXDOMAIN'}
      <p class="muted help">The name does not exist{result.negative_zone ? `, says the ${result.negative_zone} zone` : ''}.</p>
    {:else if result.answers.length === 0}
      <p class="muted help">The name exists but has no {result.type} records{result.negative_zone ? ` (zone ${result.negative_zone})` : ''}.</p>
    {/if}

    {#if result.answers.length}
      <div class="table-wrap">
        <table>
          <thead><tr><th>Name</th><th>Type</th><th>TTL</th><th>Data</th><th>DNSSEC</th></tr></thead>
          <tbody>
            {#each result.answers as r, i (i)}
              <tr>
                <td class="mono wrap">{r.name}</td>
                <td>{r.type}</td>
                <td>{r.ttl}</td>
                <td class="mono wrap">{r.data}</td>
                <td><span class="pill {r.dnssec === 'secure' ? 'ok' : r.dnssec === 'bogus' ? 'bad' : ''}">{r.dnssec ? r.dnssec[0].toUpperCase() + r.dnssec.slice(1) : ''}</span></td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </div>

  <div class="card" style="margin-top: 14px">
    <div class="spread" style="margin-bottom: 10px">
      <h3 style="margin: 0">Queries Sent</h3>
      {#if failedSteps}<span class="pill bad">{failedSteps} Failed</span>{/if}
    </div>
    {#if result.trace.length === 0}
      <p class="muted help">
        No queries left the server: the answer came from the cache. Tick
        "Start from empty caches" to see every step.
      </p>
    {:else}
      <div class="table-wrap">
        <table>
          <thead><tr><th>#</th><th>Server</th><th>Question</th><th>Result</th><th>Time</th></tr></thead>
          <tbody>
            {#each result.trace as s, i (i)}
              <tr class:failed={!s.rcode || !['NOERROR', 'NXDOMAIN'].includes(s.rcode)}>
                <td class="muted">{i + 1}</td>
                <td class="mono">{s.server}</td>
                <td class="mono wrap">{s.name} {s.type}</td>
                <td class="wrap">
                  {#if s.rcode}<span class="pill {rcodeClass(s.rcode)}">{s.rcode}</span>{:else}<span class="pill bad">No answer</span>{/if}
                  {#if s.outcome !== s.rcode}<span class="outcome">{s.outcome}</span>{/if}
                </td>
                <td class="num">{s.elapsed_ms.toLocaleString()} ms</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      <p class="muted help">
        Listed in the order the queries were sent. A row with no response code
        means the server never replied: the resolver's timeout elapsed or it
        moved on to another server. A failed row with a later answer for the
        same question means the walk continued elsewhere.
      </p>
    {/if}
  </div>
{/if}

<style>
  .lookup { display: grid; grid-template-columns: minmax(0, 1fr) 160px auto; gap: 12px; align-items: end; }
  @media (max-width: 640px) {
    .lookup { grid-template-columns: 1fr; }
  }
  label { display: flex; flex-direction: column; gap: 4px; font-size: 0.85rem; }
  label span { color: var(--muted); }
  label.check { flex-direction: row; align-items: center; gap: 8px; margin-top: 12px; }
  label.check input { width: auto; }
  .help { margin: 10px 0 0; }
  .summary { display: flex; flex-wrap: wrap; align-items: center; gap: 14px 36px; }
  .pair { display: flex; flex-direction: column; gap: 3px; }
  .pair .muted { font-size: 0.78rem; }
  .pair .value { font-size: 1.05rem; font-weight: 600; font-variant-numeric: tabular-nums; }
  .reason { margin-top: 14px; padding: 10px 12px; border: 1px solid var(--danger); border-radius: 8px; }
  .reason strong { color: var(--danger); }
  .reason p { margin: 6px 0; }
  .reason code { display: block; overflow-wrap: anywhere; font-size: 0.82rem; }
  .table-wrap { overflow-x: auto; margin-top: 12px; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--border); vertical-align: top; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.82rem; }
  .wrap { overflow-wrap: anywhere; }
  .num { white-space: nowrap; font-variant-numeric: tabular-nums; text-align: right; }
  .pill.warn { color: var(--warn); border-color: var(--warn); }
  .outcome { margin-left: 6px; }
  tr.failed td { background: color-mix(in srgb, var(--danger) 8%, transparent); }
</style>
