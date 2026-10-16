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
        api.setToken(resp.token);
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