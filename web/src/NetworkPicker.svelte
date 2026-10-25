<script>
  // Pick client networks: tick named networks (Settings -> Networks) and/or
  // type other addresses. `value` is the list as the server stores it:
  // network names followed by CIDRs or single addresses.
  let {
    networks = [],
    value = $bindable([]),
    label = 'Other Addresses (CIDRs or IPs, comma-separated)',
    placeholder = '10.8.0.0/16',
    // Optional listener keywords (DOT/DOH/DOQ) shown as chips that group by
    // "which listener the query arrived on" rather than by address. Only
    // used where the server accepts them (client groups).
    listeners = false,
  } = $props();

  const LISTENERS = [
    { key: 'DOT', label: 'DoT' },
    { key: 'DOH', label: 'DoH' },
    { key: 'DOQ', label: 'DoQ' },
  ];
  const isListener = (entry) => LISTENERS.some((l) => l.key === String(entry).trim().toUpperCase());

  const nameOf = (entry) =>
    networks.find((n) => n.name.toLowerCase() === String(entry).trim().toLowerCase())?.name;

  // Ticked names follow `value`; the typed text is kept as typed.
  const named = $derived(value.map(nameOf).filter(Boolean));
  // Ticked listener keywords, as the strings the server stores ("DOT").
  const listenersOn = $derived(
    LISTENERS.map((l) => l.key).filter((key) => value.some((v) => String(v).trim().toUpperCase() === key)),
  );
  let extra = $state(value.filter((v) => !nameOf(v) && !isListener(v)).join(', '));

  function others(text) {
    return text
      .split(/[\n,]/)
      .map((s) => s.trim())
      .filter(Boolean);
  }

  function rebuild() {
    return [...listenersOn, ...named, ...others(extra)];
  }

  function toggle(name) {
    const next = named.includes(name) ? named.filter((n) => n !== name) : [...named, name];
    value = [...listenersOn, ...next, ...others(extra)];
  }

  function toggleListener(key) {
    const next = listenersOn.includes(key) ? listenersOn.filter((k) => k !== key) : [...listenersOn, key];
    value = [...next, ...named, ...others(extra)];
  }

  function typed(e) {
    extra = e.currentTarget.value;
    value = [...listenersOn, ...named, ...others(extra)];
  }
</script>

<div class="chips" role="group" aria-label="Network filters">
  {#if networks.length}
    {#each networks as n (n.name)}
      <label class="chip" class:on={named.includes(n.name)} title={n.cidrs.join(', ')}>
        <input type="checkbox" checked={named.includes(n.name)} onchange={() => toggle(n.name)} />
        {n.name}
      </label>
    {/each}
  {/if}
  {#if listeners}
    {#each LISTENERS as l (l.key)}
      <label
        class="chip"
        class:on={listenersOn.includes(l.key)}
        title="Queries arriving over DNS over {l.key === 'DOT'
              ? 'TLS'
              : l.key === 'DOH'
                ? 'HTTPS'
                : 'QUIC'}"
      >
        <input
          type="checkbox"
          checked={listenersOn.includes(l.key)}
          onchange={() => toggleListener(l.key)}
        />
        {l.label}
      </label>
    {/each}
  {/if}
</div>
<label class="other">{label} <input {placeholder} value={extra} oninput={typed} /></label>

<style>
  .chips { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 10px; }
  .chip {
    display: inline-flex;
    flex-direction: row;
    align-items: center;
    gap: 6px;
    padding: 4px 10px;
    border: 1px solid var(--border);
    border-radius: 999px;
    cursor: pointer;
    color: var(--text);
    font-size: 0.85rem;
  }
  .chip.on { border-color: var(--accent); background: rgb(91 140 255 / 0.15); }
  .chip input { width: auto; margin: 0; }
  .other { display: flex; flex-direction: column; gap: 4px; font-size: 0.85rem; color: var(--muted); }
</style>
