<script>
  import { deviceName, loadDeviceNames } from './devices.svelte.js';

  // A client shown by its device name (Clients -> Devices) and address.
  let { address } = $props();
  const name = $derived(deviceName(address));

  $effect(() => {
    loadDeviceNames();
  });
</script>

{#if name}<span class="device">{name}</span> <code class="addr">{address}</code>{:else}<code>{address || '-'}</code>{/if}

<style>
  .device { font-weight: 500; }
  .addr { color: var(--muted); font-size: 0.85em; }
</style>
