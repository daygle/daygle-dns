<script>
  // Pick client networks: tick named networks (Settings -> Networks) and/or
  // type other addresses. `value` is the list as the server stores it:
  // network names followed by CIDRs or single addresses.
  let {
    networks = [],
    value = $bindable([]),
    label = 'Other Addresses (CIDRs or IPs, comma-separated)',
    placeholder = '10.8.0.0/16',
  } = $props();

  const nameOf = (entry) =>
    networks.find((n) => n.name.toLowerCase() === String(entry).trim().toLowerCase())?.name;

  // Ticked names follow `value`; the typed text is kept as typed.
  const named = $derived(value.map(nameOf).filter(Boolean));
  let extra = $state(value.filter((v) => !nameOf(v)).join(', '));

  function others(text) {
    return text
      .split(/[\n,]/)
      .map((s) => s.trim())
      .filter(Boolean);
  }

  function toggle(name) {
    const next = named.includes(name) ? named.filter((n) => n !== name) : [...named, name];
    value = [...next, ...others(extra)];
  }

  function typed(e) {
    extra = e.currentTarget.value;
    value = [...named, ...others(extra)];
  }
</script>

{#if networks.length}
  <div class="chips" role="group" aria-label="Networks">
    {#each networks as n (n.name)}
      <label class="chip" class:on={named.includes(n.name)} title={n.cidrs.join(', ')}>
        <input type="checkbox" checked={named.includes(n.name)} onchange={() => toggle(n.name)} />
        {n.name}
      </label>
    {/each}
  </div>
{/if}
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
