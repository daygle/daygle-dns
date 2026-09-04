<script>
  import { api, setUnauthorizedHandler, getStoredUser } from './api.js';
  import Login from './views/Login.svelte';
  import Status from './views/Status.svelte';
  import Zones from './views/Zones.svelte';
  import SplitHorizon from './views/SplitHorizon.svelte';
  import Logs from './views/Logs.svelte';
  import Blocklists from './views/Blocklists.svelte';
  import AdvancedBlocking from './views/AdvancedBlocking.svelte';
  import Settings from './views/Settings.svelte';
  import Cache from './views/Cache.svelte';
  import DomainLists from './views/DomainLists.svelte';
  import About from './views/About.svelte';

  let view = $state('status');
  // `authed` is optimistic: we assume a session until a 401 says otherwise.
  let authed = $state(true);
  let user = $state(getStoredUser());
  // Viewer accounts are read-only: they never see the write-only views.
  const isViewer = $derived(user?.role === 'viewer');

  setUnauthorizedHandler(() => {
    authed = false;
  });

  function handleLogin() {
    authed = true;
    user = getStoredUser();
    if (isViewer && (view === 'zones' || view === 'split-horizon' || view === 'blocklists')) {
      view = 'status';
    }
  }

  async function handleLogout() {
    await api.logout();
    user = null;
    authed = false;
  }

  const tabs = [
    { id: 'status', label: 'Status' },
    { id: 'zones', label: 'Zones & Records', viewer: true },
    { id: 'split-horizon', label: 'Split Horizon', viewer: true },
    { id: 'blocklists', label: 'Blocklists', viewer: true },
    { id: 'domain-lists', label: 'Domain Lists', viewer: true },
    { id: 'advanced-blocking', label: 'Advanced Blocking', viewer: true },
    { id: 'cache', label: 'Cache' },
    { id: 'logs', label: 'Logs' },
    { id: 'settings', label: 'Settings', viewer: true },
    { id: 'about', label: 'About' },
  ].filter((t) => !isViewer || !t.viewer);
</script>

{#if !authed}
  <Login onLogin={handleLogin} />
{:else}
  <div class="shell">
    <aside>
      <div class="brand">
        <span class="logo">⬡</span>
        <div>
          <strong>Daygle DNS</strong>
          <div class="muted" style="font-size:0.75rem">Modern DNS server</div>
        </div>
      </div>
      <nav>
        {#each tabs as tab (tab.id)}
          <button
            class="nav-btn"
            class:active={view === tab.id}
            onclick={() => (view = tab.id)}
          >
            {tab.label}
          </button>
        {/each}
      </nav>
      {#if user}
        <div class="user-box">
          <div class="muted" style="font-size: 0.75rem">Signed in as</div>
          <div>{user.username}</div>
          <span class="pill" class:ok={!isViewer} class:err={isViewer}>
            {isViewer ? 'read-only' : 'admin'}
          </span>
          <button class="secondary logout" onclick={handleLogout}>Sign out</button>
        </div>
      {/if}
    </aside>

    <main>
      {#if view === 'status' || (isViewer && !tabs.some((t) => t.id === view))}
        <Status />
      {:else if view === 'zones'}
        <Zones />
      {:else if view === 'split-horizon'}
        <SplitHorizon />
      {:else if view === 'blocklists'}
        <Blocklists />
      {:else if view === 'domain-lists'}
        <DomainLists />
      {:else if view === 'cache'}
        <Cache />
      {:else if view === 'advanced-blocking'}
        <AdvancedBlocking />
      {:else if view === 'about'}
        <About />
      {:else if view === 'logs'}
        <Logs />
      {:else}
        <Settings />
      {/if}
    </main>
  </div>
{/if}

<style>
  .shell { display: flex; min-height: 100vh; }

  aside {
    width: 220px;
    background: var(--panel);
    border-right: 1px solid var(--border);
    padding: 20px 14px;
    display: flex;
    flex-direction: column;
    gap: 20px;
    position: sticky;
    top: 0;
    height: 100vh;
  }

  .brand { display: flex; gap: 10px; align-items: center; }
  .logo { font-size: 1.6rem; color: var(--accent); }

  nav { display: flex; flex-direction: column; gap: 4px; }
  .nav-btn {
    background: none;
    color: var(--muted);
    text-align: left;
    border-radius: 6px;
    padding: 9px 12px;
  }
  .nav-btn:hover { background: var(--panel-2); color: var(--text); }
  .nav-btn.active { background: var(--accent); color: #fff; }

  .user-box {
    margin-top: auto;
    padding: 10px;
    border-top: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: 0.85rem;
  }
  .logout { margin-top: 8px; }

  main { flex: 1; padding: 24px 28px; }
</style>
