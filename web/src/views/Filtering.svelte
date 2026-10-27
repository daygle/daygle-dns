<script>
  import PageHeader from '../PageHeader.svelte';
  import { icons } from '../icons.svelte.js';
  import Blocklists from './Blocklists.svelte';
  import DomainLists from './DomainLists.svelte';
  import ResponseFilters from './ResponseFilters.svelte';
  import RpzZones from './RpzZones.svelte';
  import WhyBlocked from '../WhyBlocked.svelte';

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
      id: 'allow',
      label: 'Allow List',
      tagline:
        'Your own list of domains to always allow, for every client. An allowed domain is never blocked by a blocklist, the block list or the AI.',
    },
    {
      id: 'block',
      label: 'Block List',
      tagline: 'Your own list of domains to always block, for every client, whatever the blocklists say.',
    },
    {
      id: 'response-filters',
      label: 'Response Filters',
      tagline:
        'Rules that look at or change DNS answers: block trackers hidden behind CNAME records, force Safe Search, show a block page, and answer IPv6 lookups with IPv4 only.',
    },
    {
      id: 'rpz',
      label: 'Response Policy Zones',
      tagline:
        'DNS firewall rules in the standard RPZ format: subscribe to threat-intelligence feeds by zone transfer or URL, or write your own, with every RPZ action (NXDOMAIN, NODATA, drop, TCP-only, passthru and local data).',
    },
    {
      id: 'why',
      label: 'Why Blocked?',
      tagline:
        'Why a domain is or is not blocked for a device: every blocklist, list, filtering group, AI verdict and response policy zone it meets, in order, what each does with it, and which one decides.',
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
{:else if tab === 'allow' || tab === 'block'}
  <DomainLists kind={tab} />
{:else if tab === 'rpz'}
  <RpzZones />
{:else if tab === 'why'}
  <div class="card"><WhyBlocked /></div>
{:else}
  <ResponseFilters />
{/if}
