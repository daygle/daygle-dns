<script>
  import { api } from '../api.js';

  let { onLogin = () => {} } = $props();

  // `mode` is resolved on mount: 'login' (default), 'setup' (first run - no
  // admin account exists yet) or 'open' (auth disabled; never shown because
  // App.svelte only renders this component when auth is required).
  let mode = $state('login');
  let resolving = $state(true);

  let username = $state('');
  let password = $state('');
  let password2 = $state('');
  let error = $state(null);
  let busy = $state(false);

  $effect(() => {
    let cancelled = false;
    api
      .authSetupStatus()
      .then((status) => {
        if (cancelled) return;
        if (status && status.setup_pending) mode = 'setup';
      })
      .catch(() => { /* keep the login form; submitting will surface the error */ })
      .finally(() => {
        if (!cancelled) resolving = false;
      });
    return () => {
      cancelled = true;
    };
  });

  async function submit(e) {
    e.preventDefault();
    if (!username.trim() || !password) return;
    if (mode === 'setup' && password !== password2) {
      error = 'Passwords do not match';
      return;
    }
    busy = true;
    error = null;
    try {
      if (mode === 'setup') {
        await api.authSetup(username.trim(), password);
      } else {
        await api.login(username.trim(), password);
      }
      password = '';
      password2 = '';
      onLogin();
    } catch (err) {
      error = String(err.message || err);
    } finally {
      busy = false;
    }
  }

  const isSetup = $derived(mode === 'setup');
</script>

<div class="login-wrap">
  <form class="card login-card" onsubmit={submit}>
    <div class="brand">
      <span class="logo">⬡</span>
      <div>
        <strong>Daygle DNS</strong>
        <div class="muted" style="font-size: 0.8rem">
          {isSetup ? 'Create the administrator account' : 'Sign in to the console'}
        </div>
      </div>
    </div>

    {#if isSetup}
      <p class="setup-note">
        Welcome! This is the first run of the console, so pick an administrator
        username and password. They are stored in the server config and used to
        sign in from now on.
      </p>
    {/if}

    {#if error}
      <div class="error">{error}</div>
    {/if}

    <label>
      <span>Username</span>
      <input
        type="text"
        autocomplete={isSetup ? 'username' : 'username'}
        bind:value={username}
        placeholder="admin"
        autofocus
      />
    </label>
    <label>
      <span>Password</span>
      <input
        type="password"
        autocomplete={isSetup ? 'new-password' : 'current-password'}
        bind:value={password}
        placeholder={isSetup ? 'At least 8 characters' : '••••••••'}
      />
    </label>
    {#if isSetup}
      <label>
        <span>Confirm Password</span>
        <input
          type="password"
          autocomplete="new-password"
          bind:value={password2}
          placeholder="Repeat the password"
        />
      </label>
    {/if}

    <button type="submit" disabled={busy || resolving || !username.trim() || !password
      || (isSetup && !password2)}>
      {#if busy}
        {isSetup ? 'Creating account…' : 'Signing in…'}
      {:else}
        {isSetup ? 'Create Account' : 'Sign in'}
      {/if}
    </button>
  </form>
</div>

<style>
  .login-wrap {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .login-card {
    width: 340px;
    display: flex;
    flex-direction: column;
    gap: 14px;
  }
  .brand { display: flex; gap: 10px; align-items: center; }
  .logo { font-size: 1.6rem; color: var(--accent); }
  label {
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: 0.85rem;
  }
  label span { color: var(--muted); }
  .setup-note {
    margin: 0;
    font-size: 0.85rem;
    color: var(--muted);
    line-height: 1.45;
  }
  .error {
    background: rgba(255, 91, 106, 0.12);
    border: 1px solid var(--danger);
    color: var(--danger);
    border-radius: 6px;
    padding: 8px 10px;
    font-size: 0.85rem;
  }
</style>
