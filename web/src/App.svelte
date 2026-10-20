<script>
  import { onMount } from 'svelte';
  import { api, setUnauthorizedHandler, getStoredUser } from './api.js';
  import Login from './views/Login.svelte';
  import Setup from './views/Setup.svelte';
  import Status from './views/Status.svelte';
  import ZonesPage from './views/ZonesPage.svelte';
  import Logs from './views/Logs.svelte';
  import Filtering from './views/Filtering.svelte';
  import Settings from './views/Settings.svelte';
  import Ai from './views/Ai.svelte';
  import Cache from './views/Cache.svelte';
  import Users from './views/Users.svelte';
  import Certificates from './views/Certificates.svelte';
  import About from './views/About.svelte';
  import Update from './views/Update.svelte';
  import { icons } from './icons.svelte.js';
  import { sidebar, setSidebar, isNarrow, toggleSidebar } from './nav.svelte.js';
  import {
    display,
    loadDisplayPreferences,
    setMyPreferences,
    timeZoneOptions,
    DATE_FORMAT_OPTIONS,
    TIME_FORMAT_OPTIONS,
    choiceLabel,
    previewDateTime,
  } from './datetime.svelte.js';

  let view = $state('status');
  // Settings tab to open on the next visit (set by cross-page links).
  let settingsTab = $state('general');

  function openSettings(tab) {
    settingsTab = tab;
    view = 'settings';
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

  // Personal date/time preferences (sidebar user box).
  let showPrefs = $state(false);
  let prefsDraft = $state({ time_zone: '', date_format: '', time_format: '' });
  let prefsError = $state(null);
  let savingPrefs = $state(false);
  const zoneChoices = timeZoneOptions();

  function openPrefs() {
    prefsDraft = { time_zone: '', date_format: '', time_format: '', ...display.mine };
    prefsError = null;
    passwordNotice = null;
    showPrefs = true;
  }

  async function submitPrefs(e) {
    e.preventDefault();
    prefsError = null;
    savingPrefs = true;
    try {
      await api.savePreferences(prefsDraft);
      setMyPreferences(prefsDraft);
      showPrefs = false;
    } catch (err) {
      prefsError = String(err.message || err);
    } finally {
      savingPrefs = false;
    }
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

  // Remember the zone chosen on the Records tab so it is restored next visit.
  function setRecordZone(zoneId) {
    recordZoneId = zoneId;
  }

  const tabs = [
    { id: 'status', label: 'Status', icon: icons.status },
    { id: 'zones', label: 'Zones', icon: icons.zones, viewer: true },
    { id: 'filtering', label: 'Filtering', icon: icons.filtering, viewer: true },
    { id: 'ai', label: 'AI', icon: icons.ai, viewer: true },
    { id: 'logs', label: 'Logs', icon: icons.logs },
    { id: 'cache', label: 'Cache', icon: icons.cache },
    { id: 'users', label: 'Users', icon: icons.users, viewer: true },
    { id: 'certificates', label: 'Certificates', icon: icons.certificates },
    { id: 'settings', label: 'Settings', icon: icons.settings, viewer: true },
    { id: 'update', label: 'Update', icon: icons.update },
    { id: 'about', label: 'About', icon: icons.about },
  ].filter((t) => !isViewer || !t.viewer);
</script>

{#if !authed}
  {#if needsSetup}
    <Setup />
  {:else}
    <Login onLogin={handleLogin} />
  {/if}
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
  {#if showPrefs}
    <div class="modal-backdrop" role="presentation" onclick={(e) => { if (e.target === e.currentTarget) showPrefs = false; }}>
      <form class="card modal" onsubmit={submitPrefs}>
        <div class="spread" style="margin-bottom: 10px">
          <h3 style="margin: 0">My Preferences</h3>
          <button type="button" class="secondary" style="padding: 2px 10px" onclick={() => (showPrefs = false)}>✕</button>
        </div>
        <p class="modal-note">
          How dates and times are shown to you, on any device you sign in
          from. "Server Default" follows the setting an administrator chose
          for everyone.
        </p>
        <label>
          <span>Time Zone</span>
          <select bind:value={prefsDraft.time_zone}>
            <option value="">Server Default ({choiceLabel('time_zone', display.defaults.time_zone)})</option>
            {#each zoneChoices as [value, label]}<option value={value}>{label}</option>{/each}
          </select>
        </label>
        <label>
          <span>Date Format</span>
          <select bind:value={prefsDraft.date_format}>
            <option value="">Server Default ({choiceLabel('date_format', display.defaults.date_format)})</option>
            {#each DATE_FORMAT_OPTIONS as [value, label]}<option value={value}>{label}</option>{/each}
          </select>
        </label>
        <label>
          <span>Time Format</span>
          <select bind:value={prefsDraft.time_format}>
            <option value="">Server Default ({choiceLabel('time_format', display.defaults.time_format)})</option>
            {#each TIME_FORMAT_OPTIONS as [value, label]}<option value={value}>{label}</option>{/each}
          </select>
        </label>
        <p class="modal-note">Example: <strong>{previewDateTime(prefsDraft)}</strong></p>
        {#if prefsError}<div class="form-error">{prefsError}</div>{/if}
        <div class="modal-actions">
          <button type="submit" disabled={savingPrefs}>{savingPrefs ? 'Saving…' : 'Save Preferences'}</button>
          <button type="button" class="secondary" onclick={() => (showPrefs = false)}>Cancel</button>
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
        {#each tabs as tab (tab.id)}
          <button
            class="nav-btn"
            class:active={view === tab.id}
            title={!sidebar.open ? tab.label : undefined}
            aria-label={tab.label}
            onclick={() => {
              view = tab.id;
              settingsTab = 'general';
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
          <div class="user-row" title={isViewer ? 'Read-only account' : 'Full administrator access'}>
            <span class="avatar" aria-hidden="true">{user.username.slice(0, 1).toUpperCase()}</span>
            <div class="user-meta">
              <div class="user-name">{user.username}</div>
              <div class="user-role" class:admin={!isViewer}>{isViewer ? 'Read-Only' : 'Administrator'}</div>
            </div>
          </div>
          <div class="user-actions">
            {#if display.mine}
              <button class="secondary wide" onclick={openPrefs} title="Your time zone and date format">My Preferences</button>
            {/if}
            <button class="secondary" onclick={openPassword} title="Change your password">Change Password</button>
            <button class="secondary" onclick={handleLogout} title="End this session">Sign Out</button>
          </div>
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
        <ZonesPage {recordZoneId} onSelectZone={setRecordZone} />
      {:else if view === 'filtering'}
        <Filtering />
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
      {:else if view === 'update'}
        <Update />
      {:else if view === 'logs'}
        <Logs />
      {:else}
        <Settings initialTab={settingsTab} />
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
  .user-actions .wide { grid-column: 1 / -1; }

  .password-notice {
    margin-top: 10px;
    padding: 8px 10px;
    border: 1px solid var(--ok);
    border-radius: 6px;
    color: var(--ok);
    font-size: 0.8rem;
  }

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
  aside.closed .user-box,
  aside.closed .password-notice { display: none; }
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
