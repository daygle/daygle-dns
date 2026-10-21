<script>
  import { api } from '../api.js';

  let username = '';
  let password = '';
  // Second step for accounts with two-factor login.
  let needCode = false;
  let code = '';
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

    if (needCode && code.trim().length < 1) {
      error = 'Enter the code from your authenticator app.';
      return;
    }

    loading = true;
    try {
      const resp = await api.login(username.trim(), password, needCode ? code.trim() : '');
      if (resp && resp.token) {
        window.location.href = '/';
      } else {
        error = 'Login failed.';
      }
    } catch (e) {
      if (e?.data?.two_factor) {
        // The password was right; ask for the code (or say it was wrong).
        if (needCode) error = e.message;
        needCode = true;
        code = '';
        setTimeout(() => document.getElementById('code')?.focus(), 0);
        return;
      }
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
      {#if needCode}
        <p class="hint">
          Enter the 6-digit code from your authenticator app for <strong>{username.trim()}</strong>.
          Lost your phone? Use one of your recovery codes instead.
        </p>
        <label for="code">Code</label>
        <input id="code" type="text" bind:value={code} autocomplete="one-time-code" inputmode="text" spellcheck="false" />
      {:else}
        <label for="username">Username</label>
        <!-- svelte-ignore a11y_autofocus -->
        <input id="username" type="text" bind:value={username} autocomplete="username" autofocus spellcheck="false" />

        <label for="password">Password</label>
        <input id="password" type="password" bind:value={password} autocomplete="current-password" />
      {/if}

      {#if error}
        <div class="error">{error}</div>
      {/if}

      <button type="submit" disabled={loading}>{loading ? 'Signing In…' : needCode ? 'Verify' : 'Sign In'}</button>
      {#if needCode}
        <button type="button" class="link" on:click={() => { needCode = false; code = ''; error = ''; password = ''; }}>Start Over</button>
      {/if}
    </form>
  </section>
</main>

<style>
  .hint {
    margin: 0 0 0.5rem 0;
    color: var(--muted, #8b93a7);
    font-size: 0.9rem;
    line-height: 1.4;
  }
  .link {
    background: none;
    border: none;
    color: var(--muted, #8b93a7);
    text-decoration: underline;
    cursor: pointer;
    padding: 0.25rem;
  }
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