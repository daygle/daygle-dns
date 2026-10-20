<script>
  import { api } from '../api.js';

  let username = '';
  let password = '';
  let error = '';
  let loading = false;

  async function submit() {
    error = '';
    if (username.trim().length < 1) {
      error = 'Enter your username.';
      return;
    }
    if (password.length < 1) {
      error = 'Enter your password.';
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
    <div class="brand"><span class="logo" aria-hidden="true">⬡</span> Daygle DNS</div>
    <h2>Sign In</h2>
    <form on:submit|preventDefault={submit} class="form">
      <label for="username">Username</label>
      <!-- svelte-ignore a11y_autofocus -->
      <input id="username" type="text" bind:value={username} autocomplete="username" autofocus spellcheck="false" />

      <label for="password">Password</label>
      <input id="password" type="password" bind:value={password} autocomplete="current-password" />

      {#if error}
        <div class="error">{error}</div>
      {/if}

      <button type="submit" disabled={loading}>{loading ? 'Signing In…' : 'Sign In'}</button>
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
    color: var(--text, #e6e9f2);
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
  .brand {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 1.25rem;
    font-weight: 700;
    color: var(--muted, #8b93a7);
  }
  .logo { color: var(--accent, #5b8cff); font-size: 1.3rem; }
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
    color: var(--text, #e6e9f2);
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