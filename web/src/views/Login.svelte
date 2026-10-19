<script>
  import { api } from '../api.js';

  let username = '';
  let password = '';
  let error = '';
  let loading = false;

  async function submit() {
    error = '';
    if (username.trim().length < 1) {
      error = 'Username is required.';
      return;
    }
    if (password.length < 1) {
      error = 'Password is required.';
      return;
    }

    loading = true;
    try {
      const resp = await api.login(username.trim(), password);
      if (resp && resp.token) {
        window.location.href = '/';
      } else {
        error = 'Login failed.';
      }
    } catch (e) {
      error = e && e.message ? e.message : (String(e) || 'Login failed.');
    } finally {
      loading = false;
    }
  }
</script>

<main class="page">
  <section class="panel">
    <h2>Sign in</h2>
    <form on:submit|preventDefault={submit} class="form">
      <label for="username">Username</label>
      <input id="username" type="text" bind:value={username} autocomplete="username" />

      <label for="password">Password</label>
      <input id="password" type="password" bind:value={password} autocomplete="current-password" />

      {#if error}
        <div class="error">{error}</div>
      {/if}

      <button type="submit" disabled={loading}>{loading ? 'Signing in…' : 'Sign in'}</button>
    </form>
  </section>
</main>

<style>
  .page {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    padding: 1rem;
  }
  .panel {
    background: var(--panel, #1e1e1e);
    color: var(--fg, #e0e0e0);
    border-radius: 8px;
    padding: 2rem;
    max-width: 400px;
    width: 100%;
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
  }
  h2 {
    margin: 0 0 0.5rem 0;
    font-size: 1.5rem;
  }
  .form {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }
  label {
    font-weight: 600;
  }
  input {
    padding: 0.5rem;
    border-radius: 4px;
    border: 1px solid var(--border, #333);
    background: var(--bg, #121212);
    color: var(--fg, #e0e0e0);
  }
  button {
    margin-top: 0.5rem;
    padding: 0.75rem;
    border-radius: 4px;
    border: none;
    background: var(--accent, #4a9eff);
    color: #fff;
    font-weight: 600;
    cursor: pointer;
  }
  button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }
  .error {
    color: var(--danger, #ff6b6b);
    font-size: 0.9rem;
  }
</style>