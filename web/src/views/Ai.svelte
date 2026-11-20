<script>
  import { untrack } from 'svelte';
  import PageHeader from '../PageHeader.svelte';
  import { icons } from '../icons.svelte.js';
  import AiStatus from './AiStatus.svelte';
  import AiThreats from './AiThreats.svelte';
  import AiExemptions from './AiExemptions.svelte';
  import AiVerdicts from './AiVerdicts.svelte';
  import AiSettings from './AiSettings.svelte';

  // `initialTab` lets another page open a tab directly; `canEdit` is false
  // for read-only accounts, who get no Settings tab.
  let { initialTab = 'scanner', canEdit = true } = $props();

  // The AI page groups the scanner overview and the per-domain verdicts as
  // tabs (same pattern as Settings and Logs).
  const TABS = [
    {
      id: 'scanner',
      label: 'Scanner',
      tagline:
        'Labels the domains in your DNS traffic in the background, never on the query path. Train mode only records what it finds; Enforce mode also blocks the threats it detects. Blocking a content category is a filtering-group rule, not a scanner decision.',
    },
    {
      id: 'classifications',
      label: 'Classifications',
      tagline:
        'Every domain the scanner has categorized from your DNS traffic, most recently classified first. Pick a different category to relabel a domain yourself: your label survives re-scans and is what category blocking matches, and it is a content label only - threats are the scanner\'s own detections on the Threats tab. The undo button beside a label you set gives the domain back to the scanner.',
    },
    {
      id: 'threats',
      label: 'Threats',
      tagline:
        "Domains the threat detector flagged, highest confidence first, each with its current block state. With the shared classifier, which labels count as threats is chosen here; a dedicated threat model reports its own threats and blocks them above the threshold. Disputed threats are shown but never block.",
    },
    {
      id: 'exemptions',
      label: 'Exemptions',
      tagline:
        'Review domains exempted from AI blocking, including false positives, and remove exemptions when they are no longer needed.',
    },
    {
      id: 'settings',
      label: 'Settings',
      tagline:
        'When the scanner runs, how many domains it classifies, and when a detected threat blocks. Train mode only records; Enforce mode blocks.',
      edit: true,
    },
  ];
  const tabs = $derived(TABS.filter((t) => canEdit || !t.edit));

  let tab = $state(untrack(() => initialTab));
  const current = $derived(tabs.find((t) => t.id === tab) || tabs[0]);
</script>

<PageHeader icon={icons.ai} title="AI" tagline={current.tagline} />

<div class="tabs">
  {#each tabs as t (t.id)}
    <button class="tab" class:active={current.id === t.id} onclick={() => (tab = t.id)}>{t.label}</button>
  {/each}
</div>

{#if current.id === 'scanner'}
  <AiStatus onOpenThreats={() => (tab = 'threats')} />
{:else if current.id === 'settings'}
  <AiSettings />
{:else if current.id === 'threats'}
  <AiThreats />
{:else if current.id === 'exemptions'}
  <AiExemptions />
{:else}
  <AiVerdicts />
{/if}
