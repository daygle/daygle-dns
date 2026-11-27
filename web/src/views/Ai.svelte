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

  function selectTab(id) {
    tab = id;
    document.getElementById(`ai-tab-${id}`)?.focus();
  }

  function tabKey(event) {
    const index = tabs.findIndex((item) => item.id === current.id);
    const offset = { ArrowLeft: -1, ArrowRight: 1 }[event.key];
    let next;
    if (event.key === 'Home') next = 0;
    else if (event.key === 'End') next = tabs.length - 1;
    else if (offset) next = (index + offset + tabs.length) % tabs.length;
    else return;
    event.preventDefault();
    selectTab(tabs[next].id);
  }
</script>

<PageHeader icon={icons.ai} title="AI" tagline={current.tagline} />

<div class="tabs" role="tablist" aria-label="AI">
  {#each tabs as t (t.id)}
    <button
      class="tab"
      class:active={current.id === t.id}
      id={`ai-tab-${t.id}`}
      role="tab"
      aria-selected={current.id === t.id}
      aria-controls="ai-tabpanel"
      tabindex={current.id === t.id ? 0 : -1}
      onkeydown={tabKey}
      onclick={() => (tab = t.id)}
    >{t.label}</button>
  {/each}
</div>

<div id="ai-tabpanel" role="tabpanel" aria-labelledby={`ai-tab-${current.id}`}>
  {#if current.id === 'scanner'}
    <AiStatus onOpenThreats={() => selectTab('threats')} />
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
</div>
