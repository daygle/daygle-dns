<script>
  import { api } from '../api.js';

  let username = '';
  let password = '';
  let confirm = '';
  // Optional profile fields shown on the initial admin account.
  let firstName = '';
  let lastName = '';
  let email = '';
  let error = '';
  let loading = false;

  async function submit() {
    error = '';
    if (username.trim().length < 1) {
      error = 'Choose a username.';
      return;
    }
    if (username.trim().length > 64) {
      error = 'Username must be at most 64 characters.';
      return;
    }
    if (/\s/.test(username)) {
      error = 'Username must not contain spaces.';
      return;
    }
    if ([...password].length < 8) {
      error = 'Password must be at least 8 characters.';
      return;
    }
    if (password.length > 1024) {
      error = 'Password must be at most 1024 characters.';
      return;
    }
    if (password !== confirm) {
      error = 'Passwords do not match.';
      return;
    }

    loading = true;
    try {
      const resp = await api.setup(username.trim(), password, firstName, lastName, email);
      if (resp && resp.token) {
        window.location.href = '/';
      } else {
        error = 'Setup completed but no session was returned.';
      }
    } catch (e) {
      error = e && e.message ? e.message : (String(e) || 'Failed to create the administrator account.');
    } finally {
      loading = false;
    }
  }
</script>

<main class="page">
  <section class="panel">
    <div class="brand"><span class="logo" aria-hidden="true">⬡</span> Daygle DNS</div>
    <h2>Welcome</h2>
    <p class="muted">
      Create the administrator account for this server. You can add more
      accounts later on the Users page.
    </p>
    <form on:submit|preventDefault={submit} class="form">
      <label for="username">Username</label>
      <!-- svelte-ignore a11y_autofocus -->
      <input id="username" type="text" bind:value={username} autocomplete="username" autofocus spellcheck="false" />

      <label for="password">Password</label>
      <input id="password" type="password" bind:value={password} autocomplete="new-password" />
      <div class="hint">At least 8 characters.</div>

      <label for="confirm">Confirm Password</label>
      <input id="confirm" type="password" bind:value={confirm} autocomplete="new-password" />

      <label for="name">Name <span class="optional">(Optional)</span></label>
      <div class="pair">
        <input id="name" type="text" bind:value={firstName} placeholder="First" autocomplete="given-name" aria-label="First name" />
        <input type="text" bind:value={lastName} placeholder="Last" autocomplete="family-name" aria-label="Last name" />
      </div>

      <label for="email">Email <span class="optional">(Optional)</span></label>
      <input id="email" type="email" bind:value={email} placeholder="you@example.com" autocomplete="off" />

      {#if error}
        <div class="error">{error}</div>
      {/if}

      <button type="submit" disabled={loading}>{loading ? 'Creating…' : 'Create Account and Sign In'}</button>
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
  .hint { font-size: 0.8rem; color: var(--muted, #8b93a7); margin-top: -0.4rem; }
  .optional { font-weight: 400; color: var(--muted, #8b93a7); }
  .pair { display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; }
  .pair input { min-width: 0; width: 100%; box-sizing: border-box; }
  .muted {
    color: var(--muted, #a0a0a0);
    margin-bottom: 1.5rem;
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