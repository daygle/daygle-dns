<script>
  import { api, setUnauthorizedHandler, getStoredUser } from './api.js';
  import Login from './views/Login.svelte';
  import Status from './views/Status.svelte';
  import Zones from './views/Zones.svelte';
  import Records from './views/Records.svelte';
  import SplitHorizon from './views/SplitHorizon.svelte';
  import Logs from './views/Logs.svelte';
  import Blocklists from './views/Blocklists.svelte';
  import AdvancedBlocking from './views/AdvancedBlocking.svelte';
  import Settings from './views/Settings.svelte';
  import Cache from './views/Cache.svelte';
  import Users from './views/Users.svelte';
  import Certificates from './views/Certificates.svelte';
  import DomainLists from './views/DomainLists.svelte';
  import About from './views/About.svelte';
  import Update from './views/Update.svelte';
  import { icons } from './icons.svelte.js';
  import { sidebar, setSidebar, isNarrow, toggleSidebar } from './nav.svelte.js';

  let view = $state('status');
  // Zone preselected for the Records page (set when opening records from the Zones page).
  let recordZoneId = $state(null);
  let user = $state(getStoredUser());
  // Console auth is on by default, so start at the login/setup screen unless
  // a stored session says otherwise; the effect below re-verifies it (and a
  // 401 with `login: true` still forces the login screen at any time).
  let authed = $state(user !== null);
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
    if (!stored) return;
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
  });

  function handleLogin() {
    authed = true;
    user = getStoredUser();
    if (isViewer && (view === 'zones' || view === 'records' || view === 'split-horizon' || view === 'blocklists')) {
      view = 'status';
    }
  }

  async function handleLogout() {
    await api.logout();
    user = null;
    authed = false;
  }

  // Self-service password change (sidebar user box).
  let showPassword = $state(false);
  let currentPassword = $state('');
  let newPassword = $state('');
  let newPassword2 = $state('');
  let passwordError = $state(null);
  let passwordNotice = $state(null);
  let changingPassword = $state(false);

  function openPassword() {
    currentPassword = '';
    newPassword = '';
    newPassword2 = '';
    passwordError = null;
    passwordNotice = null;
    showPassword = true;
  }

  async function submitPassword(e) {
    e.preventDefault();
    passwordError = null;
    if (newPassword.length < 8) {
      passwordError = 'New password must be at least 8 characters.';
      return;
    }
    if (newPassword !== newPassword2) {
      passwordError = 'New passwords do not match.';
      return;
    }
    if (newPassword === currentPassword) {
      passwordError = 'The new password must differ from the current one.';
      return;
    }
    changingPassword = true;
    try {
      await api.changePassword(currentPassword, newPassword);
      showPassword = false;
      passwordNotice = 'Password changed. Your other sessions were signed out.';
      setTimeout(() => (passwordNotice = null), 8000);
    } catch (err) {
      passwordError = String(err.message || err);
    } finally {
      changingPassword = false;
    }
  }

  // Open the Records page for a given zone (used from the Zones page).
  function openZoneRecords(zoneId) {
    recordZoneId = zoneId;
    view = 'records';
  }

  // Remember the zone chosen on the Records page so it is restored next visit.
  function setRecordZone(zoneId) {
    recordZoneId = zoneId;
  }

  const tabs = [
    { id: 'status', label: 'Status', icon: icons.status },
    { id: 'zones', label: 'Zones', icon: icons.zones, viewer: true },
    { id: 'records', label: 'Records', icon: icons.records, viewer: true },
    { id: 'split-horizon', label: 'Split Horizon', icon: icons['split-horizon'], viewer: true },
    { id: 'blocklists', label: 'Blocklists', icon: icons.blocklists, viewer: true },
    { id: 'domain-lists', label: 'Domain Lists', icon: icons['domain-lists'], viewer: true },
    { id: 'advanced-blocking', label: 'Advanced Blocking', icon: icons['advanced-blocking'], viewer: true },
    { id: 'cache', label: 'Cache', icon: icons.cache },
    { id: 'users', label: 'Users', icon: icons.users },
    { id: 'certificates', label: 'Certificates', icon: icons.certificates },
    { id: 'logs', label: 'Logs', icon: icons.logs },
    { id: 'settings', label: 'Settings', icon: icons.settings, viewer: true },
    { id: 'update', label: 'Update', icon: icons.update },
    { id: 'about', label: 'About', icon: icons.about },
  ].filter((t) => !isViewer || !t.viewer);
</script>

{#if !authed}
  <Login onLogin={handleLogin} />
{:else}
  {#if showPassword}
    <div class="modal-backdrop" role="presentation" onclick={(e) => { if (e.target === e.currentTarget) showPassword = false; }}>
      <form class="card modal" onsubmit={submitPassword}>
        <div class="spread" style="margin-bottom: 10px">
          <h3 style="margin: 0">Change Password</h3>
          <button type="button" class="secondary" style="padding: 2px 10px" onclick={() => (showPassword = false)}>✕</button>
        </div>
        <p class="modal-note">
          Changing your password signs out your other sessions; this device
          stays signed in.
        </p>
        <label>
          <span>Current Password</span>
          <input type="password" autocomplete="current-password" bind:value={currentPassword} placeholder="••••••••" />
        </label>
        <label>
          <span>New Password</span>
          <input type="password" autocomplete="new-password" bind:value={newPassword} placeholder="At least 8 characters" />
        </label>
        <label>
          <span>Confirm New Password</span>
          <input type="password" autocomplete="new-password" bind:value={newPassword2} placeholder="Repeat the new password" />
        </label>
        {#if passwordError}<div class="form-error">{passwordError}</div>{/if}
        <div class="modal-actions">
          <button type="submit" disabled={changingPassword || !currentPassword || !newPassword || !newPassword2}>
            {changingPassword ? 'Saving…' : 'Save Password'}
          </button>
          <button type="button" class="secondary" onclick={() => (showPassword = false)}>Cancel</button>
        </div>
      </form>
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
    <button
      type="button"
      class="fab"
      class:hidden={sidebar.open}
      aria-label="Open navigation"
      onclick={() => setSidebar(true)}
    >
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <path d="M3 6h18M3 12h18M3 18h18" />
      </svg>
    </button>
    <aside class:open={sidebar.open} class:closed={!sidebar.open}>
      <div class="side-top">
        <button
          type="button"
          class="menu-btn"
          aria-label="Toggle navigation"
          aria-expanded={sidebar.open}
          onclick={toggleSidebar}
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            {#if sidebar.open}
              <path d="M6 6l12 12M18 6L6 18" />
            {:else}
              <path d="M3 6h18M3 12h18M3 18h18" />
            {/if}
          </svg>
        </button>
      </div>
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
            onclick={() => {
              view = tab.id;
              if (isNarrow()) setSidebar(false);
            }}
          >
            <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d={tab.icon} />
            </svg>
            <span>{tab.label}</span>
          </button>
        {/each}
      </nav>
      {#if user}
        <div class="user-box">
          <div class="muted" style="font-size: 0.75rem">Signed in as</div>
          <div>{user.username}</div>
          <span class="pill" class:ok={!isViewer} class:err={isViewer}>
            {isViewer ? 'Read-Only' : 'Admin'}
          </span>
          <button class="secondary logout" onclick={openPassword}>Change Password</button>
          <button class="secondary logout" onclick={handleLogout}>Sign out</button>
        </div>
      {/if}
      {#if passwordNotice}
        <div class="password-notice">{passwordNotice}</div>
      {/if}
    </aside>

    <main>
      {#if view === 'status' || (isViewer && !tabs.some((t) => t.id === view))}
        <Status />
      {:else if view === 'zones'}
        <Zones onOpenRecords={openZoneRecords} />
      {:else if view === 'records'}
        <Records zoneId={recordZoneId} onSelectZone={setRecordZone} />
      {:else if view === 'split-horizon'}
        <SplitHorizon />
      {:else if view === 'blocklists'}
        <Blocklists />
      {:else if view === 'domain-lists'}
        <DomainLists />
      {:else if view === 'cache'}
        <Cache />
      {:else if view === 'users'}
        <Users />
      {:else if view === 'certificates'}
        <Certificates />
      {:else if view === 'advanced-blocking'}
        <AdvancedBlocking />
      {:else if view === 'about'}
        <About />
      {:else if view === 'update'}
        <Update />
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

  .side-top { display: flex; justify-content: flex-end; }
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

  nav { display: flex; flex-direction: column; gap: 4px; }
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
    padding: 10px;
    border-top: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: 0.85rem;
  }
  .logout { margin-top: 8px; }

  .password-notice {
    margin-top: 10px;
    padding: 8px 10px;
    border: 1px solid var(--ok);
    border-radius: 6px;
    color: var(--ok);
    font-size: 0.8rem;
  }

  .backdrop { display: none; }

  .fab { display: none; }

  main { flex: 1; padding: 24px 28px; }

  /* Wide screens: the sidebar is in-flow; collapsed it becomes a slim rail
     holding just the menu toggle, so it can always be reopened. */
  @media (min-width: 900px) {
    aside.closed {
      width: 52px;
      padding: 16px 6px;
    }
    aside.closed .side-top { justify-content: center; }
    aside.closed .brand,
    aside.closed nav,
    aside.closed .user-box,
    aside.closed .password-notice { display: none; }
  }

  /* Narrow screens: the sidebar becomes a slide-in overlay drawer. */
  @media (max-width: 899px) {
    aside {
      position: fixed;
      top: 0;
      left: 0;
      height: 100vh;
      width: 240px;
      z-index: 40;
      transform: translateX(-100%);
      transition: transform 0.2s ease;
    }
    aside.open { transform: translateX(0); }
    main { padding: 16px 14px; }

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

    .fab {
      display: inline-flex;
      position: fixed;
      top: 10px;
      left: 10px;
      z-index: 35;
      width: 40px;
      height: 40px;
      border-radius: 8px;
      background: var(--panel-2);
      border: 1px solid var(--border);
      color: var(--text);
      cursor: pointer;
      padding: 0;
      align-items: center;
      justify-content: center;
    }
    .fab:hover {
      border-color: var(--accent);
      color: var(--accent);
    }
    .fab svg { width: 22px; height: 22px; }
    .fab.hidden { display: none; pointer-events: none; }
  }

  .modal-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.55);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 50;
  }
  .modal {
    width: 400px;
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .modal-note {
    margin: 0;
    font-size: 0.85rem;
    color: var(--muted);
    line-height: 1.45;
  }
  .modal label {
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: 0.85rem;
  }
  .modal label span { color: var(--muted); }
  .form-error {
    color: var(--danger);
    font-size: 0.85rem;
  }
  .modal-actions { display: flex; gap: 8px; }
</style>
