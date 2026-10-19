<script>
  import PageHeader from '../PageHeader.svelte';
  import { icons } from '../icons.svelte.js';
  import Blocklists from './Blocklists.svelte';
  import DomainLists from './DomainLists.svelte';
  import ClientGroups from './ClientGroups.svelte';
  import ResponseFilters from './ResponseFilters.svelte';

  // The Filtering page groups everything that decides what gets blocked or
  // rewritten as tabs (same pattern as Settings, Logs and AI).
  const TABS = [
    {
      id: 'blocklists',
      label: 'Blocklists',
      tagline:
        'Fetch remote blocklists (domain lists, hosts files or adblock filters) and merge them into the blocklist. Add, edit and remove sources below - changes are stored in the server database and applied to the running server immediately. Sources are validated before they are saved.',
    },
    {
      id: 'domain-lists',
      label: 'Domain Lists',
      tagline:
        'Add domains that should always be trusted or always blocked. Enter one domain per line; use *.example.com for subdomains. Trusted domains take precedence over domain blocking, including remote blocklist sources. Client access-control rules remain authoritative.',
    },
    {
      id: 'client-groups',
      label: 'Client Groups',
      tagline:
        'Per-client-group allow/block policies. Each group targets a set of client networks and applies its own allow list, block list and regex patterns; allow rules win over block rules, and groups are evaluated top to bottom.',
    },
    {
      id: 'response-filters',
      label: 'Response Filters',
      tagline:
        'Rules that change DNS answers instead of blocking them. Filter AAAA removes IPv6 answers so dual-stack clients fall back to IPv4.',
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
{:else if tab === 'client-groups'}
  <ClientGroups />
{:else}
  <ResponseFilters />
{/if}
