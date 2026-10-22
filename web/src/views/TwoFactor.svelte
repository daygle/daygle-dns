<script>
  import { onMount } from 'svelte';
  import qrcode from 'qrcode-generator';
  import { api, formatApiError } from '../api.js';

  // Two-factor login for the signed-in account (Account page): turn it on
  // (scan a QR code, confirm a code, keep the recovery codes), make new
  // recovery codes, or turn it off. Every change asks for the password again.

  // 'loading' | 'off' | 'on' | 'scan' | 'codes'
  let step = $state('loading');
  let recoveryLeft = $state(0);
  let password = $state('');
  let code = $state('');
  let setup = $state(null);
  let qrSvg = $state('');
  let codes = $state([]);
  // The password-confirmed action waiting on the "on" screen.
  let action = $state(null);
  let busy = $state(false);
  let error = $state(null);

  onMount(load);

  async function load() {
    try {
      const status = await api.twoFactorStatus();
      recoveryLeft = status.recovery_codes_left;
      step = status.enabled ? 'on' : 'off';
    } catch (e) {
      error = formatApiError(e);
      step = 'off';
    }
  }

  async function run(fn) {
    busy = true;
    error = null;
    try {
      await fn();
    } catch (e) {
      error = formatApiError(e);
    } finally {
      busy = false;
    }
  }

  function start(e) {
    e.preventDefault();
    run(async () => {
      setup = await api.twoFactorSetup(password);
      const qr = qrcode(0, 'M');
      qr.addData(setup.uri);
      qr.make();
      qrSvg = qr.createSvgTag({ cellSize: 4, margin: 2, scalable: true });
      password = '';
      code = '';
      step = 'scan';
    });
  }

  function confirmCode(e) {
    e.preventDefault();
    run(async () => {
      codes = (await api.twoFactorEnable(code.trim())).recovery_codes;
      step = 'codes';
    });
  }

  function confirmAction(e) {
    e.preventDefault();
    run(async () => {
      if (action === 'off') {
        await api.twoFactorDisable(password);
        step = 'off';
      } else {
        codes = (await api.twoFactorRecoveryCodes(password)).recovery_codes;
        step = 'codes';
      }
      password = '';
      action = null;
    });
  }

  function downloadCodes() {
    const text = `Daygle DNS recovery codes\nEach code signs you in once, instead of an authenticator app code.\n\n${codes.join('\n')}\n`;
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = 'daygle-dns-recovery-codes.txt';
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  // Group the secret in fours for typing it into an app by hand.
  const spacedSecret = $derived(setup ? setup.secret.match(/.{1,4}/g).join(' ') : '');
</script>

<div class="card panel">
  <h3 style="margin: 0">Two-Factor Login</h3>

  {#if step === 'loading'}
    <p class="muted">Loading...</p>
  {:else if step === 'off'}
    <form onsubmit={start}>
      <p class="modal-note">
        Signing in will also ask for a code from an authenticator app on your
        phone (Google Authenticator, Microsoft Authenticator, 1Password,
        Bitwarden and others), so a stolen password is not enough on its own.
      </p>
      <label>
        <span>Your Password</span>
        <input type="password" autocomplete="current-password" bind:value={password} placeholder="••••••••" />
      </label>
      {#if error}<div class="form-error">{error}</div>{/if}
      <div class="modal-actions">
        <button type="submit" disabled={busy || !password}>{busy ? 'Checking...' : 'Set Up'}</button>
      </div>
    </form>
  {:else if step === 'scan'}
    <form onsubmit={confirmCode}>
      <p class="modal-note">
        Scan this QR code with your authenticator app, then enter the 6-digit
        code it shows.
      </p>
      <div class="qr">{@html qrSvg}</div>
      <p class="modal-note center">
        Can't scan it? Enter this key in the app instead:<br />
        <code class="secret">{spacedSecret}</code>
      </p>
      <label>
        <span>Code From the App</span>
        <input type="text" inputmode="numeric" autocomplete="one-time-code" bind:value={code} placeholder="123456" />
      </label>
      {#if error}<div class="form-error">{error}</div>{/if}
      <div class="modal-actions">
        <button type="submit" disabled={busy || code.trim().length < 6}>{busy ? 'Checking...' : 'Turn On'}</button>
        <button type="button" class="secondary" onclick={() => { step = 'off'; setup = null; error = null; }}>Cancel</button>
      </div>
    </form>
  {:else if step === 'codes'}
    <p class="modal-note">
      Two-factor login is on. Keep these recovery codes somewhere safe: each
      one signs you in once if you lose your phone. They are shown only now.
    </p>
    <div class="codes">
      {#each codes as c (c)}<code>{c}</code>{/each}
    </div>
    <div class="modal-actions">
      <button type="button" onclick={downloadCodes}>Download Codes</button>
      <button type="button" class="secondary" onclick={() => navigator.clipboard?.writeText(codes.join('\n'))}>Copy</button>
      <button type="button" class="secondary" onclick={() => { codes = []; load(); }}>Done</button>
    </div>
  {:else if step === 'on'}
    <p class="modal-note">
      <span class="pill ok">On</span> Signing in asks for a code from your
      authenticator app. You have <strong>{recoveryLeft}</strong>
      recovery code{recoveryLeft === 1 ? '' : 's'} left.
    </p>
    {#if action}
      <form onsubmit={confirmAction}>
        <label>
          <span>Your Password</span>
          <input type="password" autocomplete="current-password" bind:value={password} placeholder="••••••••" />
        </label>
        {#if error}<div class="form-error">{error}</div>{/if}
        <div class="modal-actions">
          <button type="submit" class:danger={action === 'off'} disabled={busy || !password}>
            {action === 'off' ? 'Turn Off' : 'Make New Codes'}
          </button>
          <button type="button" class="secondary" onclick={() => { action = null; password = ''; error = null; }}>Back</button>
        </div>
      </form>
    {:else}
      <div class="modal-actions">
        <button type="button" class="secondary" onclick={() => (action = 'codes')}>New Recovery Codes</button>
        <button type="button" class="danger" onclick={() => (action = 'off')}>Turn Off</button>
      </div>
      <p class="modal-note">
        New recovery codes replace the old ones. Lost both your phone and
        your codes? An administrator can reset two-factor login for you on
        the Users page.
      </p>
    {/if}
  {/if}
</div>

<style>
  .panel { display: flex; flex-direction: column; gap: 12px; }
  .panel label { max-width: 360px; }
  .panel form { display: flex; flex-direction: column; gap: 12px; }
  .modal-note { margin: 0; font-size: 0.85rem; color: var(--muted); line-height: 1.45; }
  .form-error { color: var(--danger); font-size: 0.85rem; }
  .modal-actions { display: flex; flex-wrap: wrap; gap: 8px; }
  .qr { display: flex; justify-content: center; margin: 4px 0 8px; }
  .qr :global(svg) { width: 200px; height: 200px; background: #fff; border-radius: 6px; }
  .center { text-align: center; }
  .secret { font-size: 0.95rem; letter-spacing: 0.04em; word-break: break-all; }
  .codes {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 6px 16px;
    padding: 10px 14px;
    background: var(--panel-2);
    border-radius: 6px;
  }
  .codes code { font-size: 1rem; letter-spacing: 0.05em; }
  label { display: flex; flex-direction: column; gap: 4px; font-size: 0.85rem; }
  label span { color: var(--muted); font-size: 0.85rem; }
</style>
