<script>
  import PageHeader from '../PageHeader.svelte';
  import { icons } from '../icons.svelte.js';
  import AiStatus from './AiStatus.svelte';
  import AiThreats from './AiThreats.svelte';
  import AiExemptions from './AiExemptions.svelte';
  import AiVerdicts from './AiVerdicts.svelte';
  import AiSettings from './AiSettings.svelte';
  import AiLlm from './AiLlm.svelte';

  // `canEdit` is false for read-only accounts, who get no Settings tab.
  let { canEdit = true } = $props();

  // The AI page groups the scanner overview and the per-domain verdicts as
  // tabs (same pattern as Settings and Logs).
  const TABS = [
    {
      id: 'scanner',
      label: 'Scanner',
      tagline:
        'Sorts the domains your network looks up into categories and spots threats, in the background. Train mode only records; Enforce mode also blocks threats.',
    },
    {
      id: 'classifications',
      label: 'Classifications',
      tagline:
        'Every domain the scanner has categorized, newest first. Pick a different category to relabel one; your label sticks, and a threat label makes it a threat.',
    },
    {
      id: 'threats',
      label: 'Threats',
      tagline:
        'Domains flagged as threats, most confident first. Choose which labels count as threats, check why a domain is or is not blocked, and correct mistakes.',
    },
    {
      id: 'exemptions',
      label: 'Exemptions',
      tagline:
        'Domains the AI will never block. Remove one when it is no longer needed.',
    },
    {
      id: 'llm',
      label: 'Language Model',
      tagline:
        'An optional local language model (Ollama) that reads the pages the AI fetched, for the domains it is least sure of. Install it, pick and update models, and update Ollama here.',
    },
    {
      id: 'settings',
      label: 'Settings',
      tagline:
        'How often the scanner runs, and how confident it must be before it blocks.',
      edit: true,
    },
  ];
  const tabs = $derived(TABS.filter((t) => canEdit || !t.edit));

  let tab = $state('scanner');
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
{:else if current.id === 'llm'}
  <AiLlm />
{:else}
  <AiVerdicts />
{/if}
