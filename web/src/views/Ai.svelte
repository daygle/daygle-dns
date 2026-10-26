<script>
  import PageHeader from '../PageHeader.svelte';
  import { icons } from '../icons.svelte.js';
  import AiStatus from './AiStatus.svelte';
  import AiVerdicts from './AiVerdicts.svelte';

  // Opens Settings on a tab (null for viewers, who cannot).
  let { onOpenSettings = null } = $props();

  // The AI page groups the scanner overview and the per-domain verdicts as
  // tabs (same pattern as Settings and Logs).
  const TABS = [
    {
      id: 'scanner',
      label: 'Scanner',
      tagline:
        'Classifies the domains in your DNS traffic in the background, never on the query path. Train mode only records verdicts; Enforce mode blocks domains in the auto-block categories once their verdict reaches the block threshold. Exempt domains are never blocked by the AI.',
    },
    {
      id: 'verdicts',
      label: 'Verdicts',
      tagline:
        'Every domain the scanner has looked at, most recently classified first. Exempt a domain to keep the AI from ever blocking it or its subdomains.',
    },
  ];

  let tab = $state('scanner');
  const current = $derived(TABS.find((t) => t.id === tab));
</script>

<PageHeader icon={icons.ai} title="AI" tagline={current.tagline} />

<div class="tabs">
  {#each TABS as t (t.id)}
    <button class="tab" class:active={tab === t.id} onclick={() => (tab = t.id)}>{t.label}</button>
  {/each}
</div>

{#if tab === 'scanner'}
  <AiStatus {onOpenSettings} />
{:else}
  <AiVerdicts />
{/if}
