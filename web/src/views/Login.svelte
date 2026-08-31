<script>
  import { api } from '../api.js';

  let username = $state('');
  let password = $state('');
  let error = $state(null);
  let busy = $state(false);

  async function submit(e) {
    e.preventDefault();
    if (!username.trim() || !password) return;
    busy = true;
    error = null;
    try {
      await api.login(username.trim(), password);
      password = '';
    } catch (err) {
      error = String(err.message || err);
    } finally {
      busy = false;
    }
  }
</script>

<div class="login-wrap">
  <form class="card login-card" onsubmit={submit}>
    <div class="brand">
      <span class="logo">⬡</span>
      <div>
        <strong>Daygle DNS</strong>
        <div class="muted" style="font-size: 0.8rem">Sign in to the console</div>
      </div>
    </div>

    {#if error}
      <div class="error">{error}</div>
    {/if}

    <label>
      <span>Username</span>
      <input
        type="text"
        autocomplete="username"
        bind:value={username}
        placeholder="admin"
        autofocus
      />
    </label>
    <label>
      <span>Password</span>
      <input
        type="password"
        autocomplete="current-password"
        bind:value={password}
        placeholder="••••••••"
      />
    </label>

    <button type="submit" disabled={busy || !username.trim() || !password}>
      {busy ? 'Signing in…' : 'Sign in'}
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
  .error {
    background: rgba(255, 91, 106, 0.12);
    border: 1px solid var(--danger);
    color: var(--danger);
    border-radius: 6px;
    padding: 8px 10px;
    font-size: 0.85rem;
  }
</style>
