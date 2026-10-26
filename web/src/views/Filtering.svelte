<script>
  import PageHeader from '../PageHeader.svelte';
  import { icons } from '../icons.svelte.js';
  import Blocklists from './Blocklists.svelte';
  import DomainLists from './DomainLists.svelte';
  import ResponseFilters from './ResponseFilters.svelte';

  // The Filtering page groups everything that decides what gets blocked or
  // rewritten as tabs (same pattern as Settings, Logs and AI).
  const TABS = [
    {
      id: 'blocklists',
      label: 'Blocklists',
      tagline:
        'Block ads, trackers and malware with published lists (plain domain lists, hosts files, adblock filters or response policy zones). Lists are checked before they are saved, refresh on their own schedule, and every change applies immediately.',
    },
    {
      id: 'domain-lists',
      label: 'Domain Lists',
      tagline:
        'Your own lists of domains to always allow or always block, for every client. An allowed domain is never blocked by a blocklist or the AI.',
    },
    {
      id: 'response-filters',
      label: 'Response Filters',
      tagline:
        'Rules that change DNS answers instead of blocking them.',
    },
  ];

  let tab = $state('blocklists');
  const current = $derived(TABS.find((t) => t.id === tab));
</script>

<PageHeader icon={icons.filtering} title="Filtering" tagline={current.tagline} />

<div class="tabs">
  {#each TABS as t (t.id)}
    <button class="tab" class:active={tab === t.id} onclick={() => (tab = t.id)}>{t.label}</button>
  {/each}
</div>

{#if tab === 'blocklists'}
  <Blocklists />
{:else if tab === 'domain-lists'}
  <DomainLists />
{:else}
  <ResponseFilters />
{/if}
