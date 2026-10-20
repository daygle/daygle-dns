<script>
  import PageHeader from '../PageHeader.svelte';
  import { icons } from '../icons.svelte.js';
  import AiStatus from './AiStatus.svelte';
  import AiVerdicts from './AiVerdicts.svelte';

  // The AI page groups the scanner overview and the per-domain verdicts as
  // tabs (same pattern as Settings and Logs).
  const TABS = [
    {
      id: 'scanner',
      label: 'AI Safety Scanner',
      tagline:
        'The background scanner classifies domains from live query traffic into categories (using the heuristic rules or a fastText model) and threat verdicts can auto-block. Overrides here take precedence over verdicts.',
    },
    {
      id: 'verdicts',
      label: 'AI Verdicts',
      tagline:
        'Per-domain classifications from the AI scanner, newest activity first. Allow overrides a verdict permanently; every auto-block decision respects cleared and allow overrides.',
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
  <AiStatus />
{:else}
  <AiVerdicts />
{/if}
