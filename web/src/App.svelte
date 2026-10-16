<script>
  import { onMount } from 'svelte';
  import { api, getStoredUser } from './api.js';
  import Login from './views/Login.svelte';
  import Setup from './views/Setup.svelte';
  import Zones from './views/Zones.svelte';
  import Users from './views/Users.svelte';
  import Certificates from './views/Certificates.svelte';
  import About from './views/About.svelte';
  import Settings from './views/Settings.svelte';
  import Blocklists from './views/Blocklists.svelte';
  import Update from './views/Update.svelte';
  import Status from './views/Status.svelte';

  let authed = false;
  let user = null;
  let path = window.location.pathname || '/';
  let checking = true;
  let needsSetup = false;

  const views = {
    '/': Zones,
    '/zones': Zones,
    '/users': Users,
    '/certificates': Certificates,
    '/about': About,
    '/settings': Settings,
    '/blocklists': Blocklists,
    '/update': Update,
    '/status': Status
  };

  function navigate(url) {
    history.pushState({}, '', url);
    path = url;
  }

  function handlePopState() {
    path = window.location.pathname || '/';
  }

  onMount(async () => {
    try {
      const stored = getStoredUser();
      if (stored) {
        // Re-verify the session is still live before trusting the stored copy.
        const me = await api.me();
        if (me) {
          user = me;
          authed = true;
        }
      }
    } catch (e) {
      user = null;
      authed = false;
    }

    try {
      const setup = await api.setupStatus();
      needsSetup = setup && setup.setup_pending;
    } catch (e) {
      needsSetup = false;
    }

    if (needsSetup) {
      if (path !== '/setup') {
        navigate('/setup');
      }
      checking = false;
      return;
    }

    checking = false;
  });

  window.addEventListener('popstate', handlePopState);
</script>{#if checking}
  <main class='page'>
    <section class='panel'>
      <p>Loading…</p>
    </section>
  </main>
{:else if needsSetup}
  <Setup />
{:else if !authed}
  <Login />
{:else}
  <nav class='nav'>
    <button class:active={path === '/'} on:click={() => navigate('/')}>Zones</button>
    <button class:active={path === '/zones'} on:click={() => navigate('/zones')}>Zones</button>
    <button class:active={path === '/blocklists'} on:click={() => navigate('/blocklists')}>Blocklists</button>
    <button class:active={path === '/certificates'} on:click={() => navigate('/certificates')}>Certificates</button>
    <button class:active={path === '/users'} on:click={() => navigate('/users')}>Users</button>
    <button class:active={path === '/settings'} on:click={() => navigate('/settings')}>Settings</button>
    <button class:active={path === '/status'} on:click={() => navigate('/status')}>Status</button>
    <button class:active={path === '/update'} on:click={() => navigate('/update')}>Update</button>
    <button class:active={path === '/about'} on:click={() => navigate('/about')}>About</button>
    <button class='logout' on:click={() => { api.logout(); window.location.href = '/'; }}>Logout</button>
  </nav>
  <main class='view'>
    <svelte:component this={views[path] || Zones} />
  </main>
{/if}

<style>
  .page { display:flex; align-items:center; justify-content:center; min-height:100vh; padding:1rem; }
  .panel { background:var(--panel,#1e1e1e); color:var(--fg,#e0e0e0); border-radius:8px; padding:2rem; max-width:400px; width:100%; box-shadow:0 8px 24px rgba(0,0,0,0.4); }
  .nav { display:flex; flex-wrap:wrap; gap:0.5rem; padding:0.5rem 1rem; background:var(--panel,#1e1e1e); border-bottom:1px solid var(--border,#333); }
  .nav button { padding:0.4rem 0.8rem; border-radius:4px; border:1px solid var(--border,#333); background:var(--bg,#121212); color:var(--fg,#e0e0e0); cursor:pointer; }
  .nav button.active { background:var(--accent,#4a9eff); color:#fff; }
  .nav .logout { margin-left:auto; }
  .view { padding:1rem; }
</style>