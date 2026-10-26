<script>
  import { onMount } from 'svelte';
  import { api, setUnauthorizedHandler, getStoredUser } from './api.js';
  import Login from './views/Login.svelte';
  import Setup from './views/Setup.svelte';
  import Status from './views/Status.svelte';
  import ZonesPage from './views/ZonesPage.svelte';
  import Logs from './views/Logs.svelte';
  import Filtering from './views/Filtering.svelte';
  import Clients from './views/Clients.svelte';
  import Settings from './views/Settings.svelte';
  import Ai from './views/Ai.svelte';
  import Cache from './views/Cache.svelte';
  import Users from './views/Users.svelte';
  import Certificates from './views/Certificates.svelte';
  import About from './views/About.svelte';
  import Donate from './views/Donate.svelte';
  import Update from './views/Update.svelte';
  import Account from './views/Account.svelte';
  import { icons } from './icons.svelte.js';
  import { sidebar, setSidebar, isNarrow, toggleSidebar } from './nav.svelte.js';
import { loadDisplayPreferences } from './datetime.svelte.js';

  let view = $state('status');
  // Settings tab to open on the next visit (set by cross-page links).
  let settingsTab = $state('general');

  // A page left open across a server update keeps running the console bundle
  // it loaded, so new features never appear until a reload. The public health
  // endpoint reports the entry bundle the *server* embeds (`console_build`);
  // when it diverges from the bundle this page is running, offer a reload.
  let consoleOutdated = $state(false);

  function runningBundle() {
    // This page runs the bundle named in the shell's module script.
    const el = document.querySelector('script[type="module"][src*="/assets/index-"]');
    const match = /assets\/(index-[^/?#]+)\.js/.exec(el?.getAttribute('src') || '');
    return match ? match[1] : '';
  }

  async function checkConsoleBuild() {
    try {
      const health = await api.health();
      const served = health?.console_build || '';
      consoleOutdated = !!served && served !== runningBundle();
    } catch (_) {
      // The server may be restarting mid-update: keep the current banner state.
    }
  }

  // Check shortly after mount (so an already-outdated page finds out quickly)
  // and then on a minute interval, all without reactive dependencies so the
  // effect cannot loop back into itself.
  $effect(() => {
    const first = setTimeout(checkConsoleBuild, 2000);
    const interval = setInterval(checkConsoleBuild, 60_000);
    return () => {
      clearTimeout(first);
      clearInterval(interval);
    };
  });

  function openSettings(tab) {
    // Networks moved from Settings to the Clients page.
    if (tab === 'networks') {
      openClients('networks');
      return;
    }
    settingsTab = tab;
    view = 'settings';
  }
  // The Clients page's tab to open (Networks unless another page asks).
  let clientsTab = $state('networks');
  function openClients(tab) {
    clientsTab = tab;
    view = 'clients';
  }
  // Zone preselected on the Zones page's Records tab (remembered across visits).
  let recordZoneId = $state(null);
  let user = $state(getStoredUser());
  // Console auth is on by default, so start at the login/setup screen unless
  // a stored session says otherwise; the effect below re-verifies it (and a
  // 401 with `login: true` still forces the login screen at any time).
  let authed = $state(user !== null);
  // Shown only before the first admin account exists (auth setup).
  let needsSetup = $state(false);
  // Viewer accounts are read-only: they never see the write-only views.
  const isViewer = $derived(user?.role === 'viewer');

  setUnauthorizedHandler(() => {
    authed = false;
  });

  // Confirm the stored session is still live once, on mount. `api.me()` is
  // async, so its response is handled in a promise callback (never assigned
  // synchronously); this effect has no reactive dependencies and therefore
  // cannot loop back into itself.
  $effect(() => {
    const stored = getStoredUser();
    if (stored) {
      let cancelled = false;
      api.me()
        .then((me) => {
          if (cancelled || !me) return;
          // Only write when the profile differs from the stored copy, so a
          // successful re-verification cannot retrigger this effect.
          if (me.username !== user?.username || me.role !== user?.role) {
            user = me;
          }
        })
        .catch((e) => {
          if (cancelled) return;
          // A 401 with `login: true` means the session is gone: force the
          // shell to the login screen rather than relying on a later 401
          // during page interaction.
          if (e && e.needsLogin) {
            authed = false;
          }
        });
      return () => {
        cancelled = true;
      };
    }
    // No stored session: find out whether the first admin account still has
    // to be created, so the setup screen can be shown instead of sign-in.
    let cancelled = false;
    api.setupStatus()
      .then((s) => {
        if (!cancelled) needsSetup = !!(s && s.setup_pending);
      })
      .catch(() => {
        if (!cancelled) needsSetup = false;
      });
    return () => {
      cancelled = true;
    };
  });

  function handleLogin() {
    authed = true;
    user = getStoredUser();
    needsSetup = false;
    if (isViewer && (view === 'zones' || view === 'filtering')) {
      view = 'status';
    }
  }

  async function handleLogout() {
    await api.logout();
    user = null;
    authed = false;
  }

  // Load the date/time display settings once the console is usable.
  $effect(() => {
    if (authed) loadDisplayPreferences();
  });

  function openAccount() {
    view = 'account';
    if (isNarrow()) setSidebar(false);
  }

  // Remember the zone chosen on the Records tab so it is restored next visit.
  function setRecordZone(zoneId) {
    recordZoneId = zoneId;
  }

  // The sidebar, in sections: what the server is doing, the DNS it serves,
  // and running the server itself; About and Donate sit at the foot.
  const SECTIONS = [
    { id: 'monitor', label: 'Monitor' },
    { id: 'dns', label: 'DNS' },
    { id: 'server', label: 'Server' },
    { id: 'info', label: null },
  ];
  const tabs = [
    { id: 'status', label: 'Status', icon: icons.status, section: 'monitor' },
    { id: 'logs', label: 'Logs', icon: icons.logs, section: 'monitor' },
    { id: 'zones', label: 'Zones', icon: icons.zones, viewer: true, section: 'dns' },
    { id: 'filtering', label: 'Filtering', icon: icons.filtering, viewer: true, section: 'dns' },
    { id: 'clients', label: 'Clients', icon: icons.clients, viewer: true, section: 'dns' },
    { id: 'ai', label: 'AI', icon: icons.ai, viewer: true, section: 'dns' },
    { id: 'cache', label: 'Cache', icon: icons.cache, section: 'dns' },
    { id: 'settings', label: 'Settings', icon: icons.settings, viewer: true, section: 'server' },
    { id: 'certificates', label: 'Certificates', icon: icons.certificates, section: 'server' },
    { id: 'users', label: 'Users', icon: icons.users, viewer: true, section: 'server' },
    { id: 'update', label: 'Update', icon: icons.update, section: 'server' },
    { id: 'about', label: 'About', icon: icons.about, section: 'info' },
    { id: 'donate', label: 'Donate', icon: icons.heart, section: 'info' },
  ].filter((t) => !isViewer || !t.viewer);
  const navSections = $derived(
    SECTIONS.map((s) => ({ ...s, items: tabs.filter((t) => t.section === s.id) })).filter(
      (s) => s.items.length,
    ),
  );
</script>

{#if !authed}
  {#if needsSetup}
    <Setup />
  {:else}
    <Login onLogin={handleLogin} />
  {/if}
{:else}
  {#if consoleOutdated}
    <div class="update-banner" role="status">
      <span>
        Daygle DNS has been updated with new features. Reload the console to load them.
      </span>
      <button onclick={() => location.reload()}>Reload Console</button>
    </div>
  {/if}
  <div class="shell">
    <button
      type="button"
      class="backdrop"
      class:show={sidebar.open}
      aria-label="Close navigation"
      onclick={() => setSidebar(false)}
    ></button>
    <aside class:open={sidebar.open} class:closed={!sidebar.open}>
      <div class="side-head">
        <div class="brand">
          <span class="logo">⬡</span>
          <div>
            <strong>Daygle DNS</strong>
            <div class="muted" style="font-size:0.75rem">Modern DNS server</div>
          </div>
        </div>
        <button
          type="button"
          class="menu-btn"
          aria-label="Toggle navigation"
          aria-expanded={sidebar.open}
          onclick={toggleSidebar}
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <path d={sidebar.open ? icons.sidebarCollapse : icons.sidebarExpand} />
          </svg>
        </button>
      </div>
      <nav>
        {#each navSections as section (section.id)}
        <div class="nav-section" class:info={section.id === 'info'}>
          {#if section.label}<div class="nav-heading">{section.label}</div>{/if}
        {#each section.items as tab (tab.id)}
          <button
            class="nav-btn"
            class:active={view === tab.id}
            title={!sidebar.open ? tab.label : undefined}
            aria-label={tab.label}
            onclick={() => {
              view = tab.id;
              settingsTab = 'general';
              clientsTab = 'networks';
              if (isNarrow()) setSidebar(false);
            }}
          >
            <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d={tab.icon} />
            </svg>
            <span>{tab.label}</span>
          </button>
        {/each}
        </div>
        {/each}
      </nav>
      {#if user}
        <div class="user-box">
          <div class="user-row" title={isViewer ? 'Read-only account' : 'Full administrator access'}>
            <span class="avatar" aria-hidden="true">{user.username.slice(0, 1).toUpperCase()}</span>
            <div class="user-meta">
              <div class="user-name">{user.username}</div>
              <div class="user-role" class:admin={!isViewer}>{isViewer ? 'Read-Only' : 'Administrator'}</div>
            </div>
          </div>
          <div class="user-actions">
            <button class="secondary" class:current={view === 'account'} onclick={openAccount} title="Your preferences, password, two-factor login and API tokens">Account</button>
            <button class="secondary" onclick={handleLogout} title="End this session">Sign Out</button>
          </div>
        </div>
      {/if}
    </aside>

    <main>
      {#if view === 'account'}
        <Account {user} />
      {:else if view === 'status' || (isViewer && !tabs.some((t) => t.id === view))}
        <Status onOpenUpdate={() => (view = 'update')} />
      {:else if view === 'zones'}
        <ZonesPage {recordZoneId} onSelectZone={setRecordZone} onOpenSettings={isViewer ? null : openSettings} />
      {:else if view === 'filtering'}
        <Filtering />
      {:else if view === 'clients'}
        {#key clientsTab}
          <Clients initialTab={clientsTab} />
        {/key}
      {:else if view === 'cache'}
        <Cache onOpenSettings={isViewer ? null : openSettings} />
      {:else if view === 'users'}
        <Users />
      {:else if view === 'certificates'}
        <Certificates onOpenSettings={isViewer ? null : openSettings} />
      {:else if view === 'ai'}
        <Ai onOpenSettings={isViewer ? null : openSettings} />
      {:else if view === 'about'}
        <About />
      {:else if view === 'donate'}
        <Donate />
      {:else if view === 'update'}
        <Update />
      {:else if view === 'logs'}
        <Logs />
      {:else}
        <Settings initialTab={settingsTab} onOpenClients={openClients} />
      {/if}
    </main>
  </div>
{/if}

<style>
  .update-banner {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 14px;
    padding: 9px 16px;
    background: var(--accent);
    color: #fff;
    font-size: 0.88rem;
    text-align: center;
  }
  .update-banner button {
    flex: 0 0 auto;
    padding: 4px 12px;
    font-size: 0.82rem;
    background: rgba(255, 255, 255, 0.16);
    border-color: rgba(255, 255, 255, 0.55);
    color: #fff;
    white-space: nowrap;
  }
  .update-banner button:hover {
    background: rgba(255, 255, 255, 0.28);
  }

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

  .side-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
  }
  .menu-btn {
    flex: 0 0 auto;
    width: 38px;
    height: 38px;
    border-radius: 8px;
    background: var(--panel-2);
    border: 1px solid var(--border);
    color: var(--text);
    cursor: pointer;
    padding: 0;
    display: inline-flex;
    align-items: center;
    justify-content: center;
  }
  .menu-btn:hover {
    border-color: var(--accent);
    color: var(--accent);
  }
  .menu-btn:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 1px;
  }
  .menu-btn svg { width: 20px; height: 20px; }

  nav { display: flex; flex-direction: column; gap: 4px; flex: 1; min-height: 0; overflow-y: auto; }
  .nav-section { display: flex; flex-direction: column; gap: 2px; }
  .nav-section + .nav-section { margin-top: 10px; }
  .nav-heading {
    padding: 0 12px 4px;
    font-size: 0.68rem;
    font-weight: 600;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--muted);
    opacity: 0.8;
  }
  /* About and Donate: smaller, at the foot of the list. */
  .nav-section.info { margin-top: auto; padding-top: 10px; }
  .nav-section.info .nav-btn { padding: 6px 12px; font-size: 0.85rem; }
  .nav-btn {
    background: none;
    color: var(--muted);
    text-align: left;
    border-radius: 6px;
    padding: 9px 12px;
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .nav-btn:hover { background: var(--panel-2); color: var(--text); }
  .nav-btn.active { background: var(--accent); color: #fff; }
  .nav-icon {
    width: 17px;
    height: 17px;
    flex-shrink: 0;
  }

  .user-box {
    margin-top: auto;
    background: var(--panel-2);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 10px;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .user-row {
    display: flex;
    align-items: center;
    gap: 10px;
    min-width: 0;
  }
  .avatar {
    flex: 0 0 32px;
    width: 32px;
    height: 32px;
    border-radius: 50%;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    background: rgba(91, 140, 255, 0.16);
    color: var(--accent);
    font-weight: 700;
    font-size: 0.9rem;
    text-transform: uppercase;
  }
  .user-meta { min-width: 0; }
  .user-name {
    font-weight: 600;
    font-size: 0.9rem;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .user-role {
    font-size: 0.72rem;
    color: var(--muted);
  }
  .user-role.admin { color: var(--accent); }
  .user-actions {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 6px;
  }
  .user-actions button {
    padding: 6px 4px;
    font-size: 0.8rem;
    border-radius: 6px;
  }
  .user-actions .current { border-color: var(--accent); color: var(--accent); }

  .backdrop { display: none; }

  main { flex: 1; min-width: 0; padding: 24px 28px; }

  /* Collapsed, the sidebar is a slim icon rail on every screen size so
     navigation stays one tap away without covering the page. */
  aside.closed {
    width: 52px;
    padding: 16px 6px;
  }
  aside.closed .side-head { justify-content: center; }
  aside.closed .brand,
  aside.closed .user-box { display: none; }
  /* Icon-only navigation: labels are hidden and the buttons center. */
  aside.closed nav {
    min-height: 0;
    overflow-y: auto;
  }
  aside.closed .nav-btn {
    justify-content: center;
    padding: 9px 0;
  }
  aside.closed .nav-btn span { display: none; }
  aside.closed .nav-heading { display: none; }
  aside.closed .nav-section + .nav-section { margin-top: 6px; padding-top: 6px; border-top: 1px solid var(--border); }

  /* Narrow screens: the rail is pinned to the left edge and expanding it
     opens the full sidebar as an overlay drawer over the page. */
  @media (max-width: 899px) {
    aside {
      position: fixed;
      top: 0;
      left: 0;
      z-index: 40;
      transition: width 0.2s ease;
    }
    aside.open {
      width: 240px;
      overflow-y: auto;
    }
    main {
      margin-left: 52px;
      padding: 16px 12px;
    }

    .backdrop {
      display: block;
      position: fixed;
      inset: 0;
      z-index: 30;
      background: rgba(0, 0, 0, 0.5);
      border: none;
      border-radius: 0;
      opacity: 0;
      pointer-events: none;
      transition: opacity 0.2s ease;
    }
    .backdrop.show { opacity: 1; pointer-events: auto; }
  }

</style>
