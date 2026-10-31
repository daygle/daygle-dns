<script>
  import PageHeader from '../PageHeader.svelte';
  import { icons } from '../icons.svelte.js';
  import AiStatus from './AiStatus.svelte';
  import AiThreats from './AiThreats.svelte';
  import AiExemptions from './AiExemptions.svelte';
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
        'Labels the domains in your DNS traffic in the background, never on the query path. Train mode only records verdicts; Enforce mode also blocks the threats this list finds. Blocking a content category is a filtering-group rule, not a scanner decision.',
    },
    {
      id: 'classifications',
      label: 'Classifications',
      tagline:
        'Every domain the scanner has categorized from your DNS traffic, most recently classified first. Pick a different category to relabel a domain yourself: your label survives re-scans and is what category blocking matches.',
    },
    {
      id: 'threats',
      label: 'Threats',
      tagline:
        "Domains the threat detector flagged, highest confidence first, each with its current block state. In Enforce mode this is the list the AI blocks for clients whose group allows it. Disputed verdicts (the verifier disagreed) are shown but never block.",
    },
    {
      id: 'exemptions',
      label: 'Exemptions',
      tagline:
        'Review domains exempted from AI blocking, including false positives, and remove exemptions when they are no longer needed.',
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
{:else if tab === 'threats'}
  <AiThreats />
{:else if tab === 'exemptions'}
  <AiExemptions />
{:else}
  <AiVerdicts />
{/if}
