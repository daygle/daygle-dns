<script>
  import PageHeader from '../PageHeader.svelte';
  import { icons } from '../icons.svelte.js';
  import Zones from './Zones.svelte';
  import Records from './Records.svelte';
  import SplitHorizon from './SplitHorizon.svelte';

  // `recordZoneId` lives in the shell so the zone picked on the Records tab
  // is remembered across visits.
  let { recordZoneId = null, onSelectZone = () => {} } = $props();

  // The Zones page groups authoritative zone management as tabs (same
  // pattern as Settings, Logs, AI and Filtering).
  const TABS = [
    {
      id: 'zones',
      label: 'Zones',
      tagline:
        "Host authoritative zones backed by SQLite. Add a primary zone to serve records directly, or a secondary zone replicated from a master via AXFR/IXFR. Manage a zone's DNS records from the Records tab.",
    },
    {
      id: 'records',
      label: 'Records',
      tagline:
        'View and edit the DNS records of an authoritative zone. Pick a zone below; secondary zones are refreshed from their master and are read-only here.',
    },
    {
      id: 'split-horizon',
      label: 'Split Horizon',
      tagline:
        "Serve different answers for the same domain depending on the client's network - e.g. clients on LAN get 10.0.0.5 for intranet.example.com while everyone else gets the public address. Entries are matched in order: the first entry whose domain matches and whose networks contain the client wins, so the specific internal views must come before the public fallback. Use the ↑/↓ buttons to reorder entries for the same domain. Each entry serves typed answers (A, AAAA, MX, TXT, CNAME, SRV) to queries of the matching type - a CNAME answers every type - and an entry with no networks matches every client, so the public fallback needs no network list.",
    },
  ];

  let tab = $state('zones');
  const current = $derived(TABS.find((t) => t.id === tab));

  // A zone's Records button opens the Records tab with that zone selected.
  function openRecords(zoneId) {
    onSelectZone(zoneId);
    tab = 'records';
  }
</script>

<PageHeader icon={icons.zones} title="Zones" tagline={current.tagline} />

<div class="tabs">
  {#each TABS as t (t.id)}
    <button class="tab" class:active={tab === t.id} onclick={() => (tab = t.id)}>{t.label}</button>
  {/each}
</div>

{#if tab === 'zones'}
  <Zones onOpenRecords={openRecords} />
{:else if tab === 'records'}
  <Records zoneId={recordZoneId} {onSelectZone} />
{:else}
  <SplitHorizon />
{/if}
