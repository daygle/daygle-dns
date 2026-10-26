<script>
  import PageHeader from '../PageHeader.svelte';
  import { icons } from '../icons.svelte.js';
  import Networks from './Networks.svelte';
  import ClientGroups from './ClientGroups.svelte';
  import ClientPolicies from './ClientPolicies.svelte';
  import Access from './Access.svelte';

  // Everything that treats some clients differently, in one place: the
  // named networks that say who they are, and the two kinds of per-client
  // rules that refer to them. `initialTab` lets another page open a tab.
  let { initialTab = 'networks' } = $props();

  const TABS = [
    {
      id: 'networks',
      label: 'Networks',
      tagline:
        'Name your networks (LAN, VPN, IoT...) once, then pick them by name wherever the server asks which clients something applies to: filtering groups, resolution policies, recursion access, encrypted DNS access, split horizon and more.',
    },
    {
      id: 'access',
      label: 'Access',
      tagline:
        'Who may use this server: which clients may have names resolved (recursion), and networks that are refused altogether.',
    },
    {
      id: 'filtering-groups',
      label: 'Filtering Groups',
      tagline:
        "Give a set of devices their own filtering: extra allow and block rules and blocklists on top of everything else, Safe Search, whether the AI may auto-block them, and when the rules apply - for example, block social media on the kids' devices at bedtime.",
    },
    {
      id: 'resolution-policies',
      label: 'Resolution Policies',
      tagline:
        'Decide how some clients\' queries are answered: forwarded to particular upstream servers, resolved from the root servers, or refused.',
    },
  ];

  let tab = $state(TABS.some((t) => t.id === initialTab) ? initialTab : 'networks');
  const current = $derived(TABS.find((t) => t.id === tab));
</script>

<PageHeader icon={icons.clients} title="Clients" tagline={current.tagline} />

<div class="tabs">
  {#each TABS as t (t.id)}
    <button class="tab" class:active={tab === t.id} onclick={() => (tab = t.id)}>{t.label}</button>
  {/each}
</div>

{#if tab === 'networks'}
  <Networks />
{:else if tab === 'access'}
  <Access />
{:else if tab === 'filtering-groups'}
  <ClientGroups />
{:else}
  <ClientPolicies />
{/if}
