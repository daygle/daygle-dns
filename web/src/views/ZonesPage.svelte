<script>
  import { untrack } from 'svelte';
  import PageHeader from '../PageHeader.svelte';
  import { icons } from '../icons.svelte.js';
  import Zones from './Zones.svelte';
  import Records from './Records.svelte';
  import SplitHorizon from './SplitHorizon.svelte';
  import ZoneSettings from './ZoneSettings.svelte';

  // `recordZoneId` lives in the shell so the zone picked on the Records tab
  // is remembered across visits.
  // `initialTab` lets another page open a tab directly; `canEdit` is false
  // for read-only accounts, who get no Settings tab.
  let { recordZoneId = null, onSelectZone = () => {}, onOpenSettings = null, initialTab = 'zones', canEdit = true } = $props();

  // The Zones page groups authoritative zone management as tabs (same
  // pattern as Settings, Logs, AI and Filtering).
  const TABS = [
    {
      id: 'zones',
      label: 'Zones',
      tagline:
        "The zones this server answers for. A primary zone serves records you manage here; a secondary zone copies one from another server. Stub and conditional forwarder zones send queries for a domain to chosen servers, and a Secondary ROOT Zone keeps a verified local copy of the root.",
    },
    {
      id: 'records',
      label: 'Records',
      tagline:
        "Add, edit and disable the records of a primary zone. Pick a zone below; a secondary zone's records come from its master and are read-only here.",
    },
    {
      id: 'split-horizon',
      label: 'Split Horizon',
      tagline:
        "Give different answers for the same name depending on the client's network, e.g. 10.0.0.5 for intranet.example.com on the LAN and the public address for everyone else.",
    },
    {
      id: 'settings',
      label: 'Settings',
      tagline:
        'Defaults for new zones and records, DNSSEC signing, and how other DNS servers may copy, update and be notified about your zones.',
      edit: true,
    },
  ];
  const tabs = $derived(TABS.filter((t) => canEdit || !t.edit));

  let tab = $state(untrack(() => initialTab));
  const current = $derived(tabs.find((t) => t.id === tab) || tabs[0]);

  // A zone's Records button opens the Records tab with that zone selected.
  function openRecords(zoneId) {
    onSelectZone(zoneId);
    tab = 'records';
  }
</script>

<PageHeader icon={icons.zones} title="Zones" tagline={current.tagline} />

<div class="tabs">
  {#each tabs as t (t.id)}
    <button class="tab" class:active={current.id === t.id} onclick={() => (tab = t.id)}>{t.label}</button>
  {/each}
</div>

{#if current.id === 'zones'}
  <Zones onOpenRecords={openRecords} />
{:else if current.id === 'records'}
  <Records zoneId={recordZoneId} {onSelectZone} />
{:else if current.id === 'settings'}
  <ZoneSettings />
{:else}
  <SplitHorizon {onOpenSettings} />
{/if}
