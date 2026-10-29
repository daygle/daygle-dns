<script>
  const REASONS = [
    'False Positive',
    'Required Service',
    'Trusted Domain',
    'Testing',
    'Other',
  ];

  let { domain, onCancel, onConfirm } = $props();
  let reason = $state('');
</script>

<div class="modal-backdrop" role="presentation" onclick={(event) => event.target === event.currentTarget && onCancel()}>
  <div class="modal card" role="dialog" aria-modal="true" aria-labelledby="exemption-title">
    <div class="spread modal-title">
      <h3 id="exemption-title" style="margin: 0">Exempt Domain</h3>
      <button class="secondary" style="padding: 2px 10px" onclick={onCancel} aria-label="Close">✕</button>
    </div>
    <p class="muted">{domain} and its subdomains will never be blocked by the AI. Choose a reason to record with this exemption.</p>
    <label class="reason-label">
      <span>Reason</span>
      <select bind:value={reason} required>
        <option value="" disabled>Select a reason</option>
        {#each REASONS as option (option)}
          <option value={option}>{option}</option>
        {/each}
      </select>
    </label>
    <div class="actions">
      <button class="secondary" onclick={onCancel}>Cancel</button>
      <button onclick={() => onConfirm(reason)} disabled={!reason}>Exempt Domain</button>
    </div>
  </div>
</div>

<style>
  .modal-backdrop { position: fixed; inset: 0; background: rgb(0 0 0 / 0.65); display: grid; place-items: center; padding: 20px; z-index: 50; }
  .modal { width: min(520px, 100%); }
  .modal-title { margin-bottom: 12px; }
  .reason-label { display: flex; flex-direction: column; gap: 5px; color: var(--muted); font-size: 0.85rem; }
  .reason-label select { width: 100%; }
  .actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 18px; }
</style>
