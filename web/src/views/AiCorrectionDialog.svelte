<script>
  const REASONS = [
    'Misclassified',
    'Wrong Domain',
    'Trusted Domain',
    'Testing',
    'Other',
  ];

  let { domain, categories = [], onCancel, onConfirm } = $props();
  let reason = $state('');
  let category = $state('');
</script>

<svelte:window onkeydown={(event) => event.key === 'Escape' && onCancel()} />

<div class="modal-backdrop" role="presentation" onclick={(event) => event.target === event.currentTarget && onCancel()}>
  <div class="modal card" role="dialog" aria-modal="true" aria-labelledby="correction-title">
    <div class="spread modal-title">
      <h3 id="correction-title" style="margin: 0">Mark as Not a Threat</h3>
      <button class="secondary" style="padding: 2px 10px" onclick={onCancel} aria-label="Close">✕</button>
    </div>
    <p class="muted">
      {domain} stops blocking and leaves the exported threat list. The detection
      stays visible so the mistake can be reviewed, and you can restore it
      later. Pick a category to relabel the domain as well.
    </p>
    <label class="field">
      <span>Reason</span>
      <select bind:value={reason} required>
        <option value="" disabled>Select a reason</option>
        {#each REASONS as option (option)}
          <option value={option}>{option}</option>
        {/each}
      </select>
    </label>
    <label class="field">
      <span>Relabel As (optional)</span>
      <select bind:value={category}>
        <option value="">Keep the scanner's label</option>
        {#each categories as option (option)}
          <option value={option}>{option}</option>
        {/each}
      </select>
    </label>
    <div class="actions">
      <button class="secondary" onclick={onCancel}>Cancel</button>
      <button onclick={() => onConfirm(reason, category)} disabled={!reason}>Mark Not a Threat</button>
    </div>
  </div>
</div>

<style>
  .modal-backdrop { position: fixed; inset: 0; background: rgb(0 0 0 / 0.65); display: grid; place-items: center; padding: 20px; z-index: 50; }
  .modal { width: min(520px, 100%); }
  .modal-title { margin-bottom: 12px; }
  .field { display: flex; flex-direction: column; gap: 5px; color: var(--muted); font-size: 0.85rem; margin-top: 10px; }
  .field select { width: 100%; }
  .actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 18px; }
</style>
