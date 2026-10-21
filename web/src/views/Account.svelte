<script>
  import PageHeader from '../PageHeader.svelte';
  import { icons } from '../icons.svelte.js';
  import { api } from '../api.js';
  import TwoFactor from './TwoFactor.svelte';
  import ApiTokens from './ApiTokens.svelte';
  import {
    display,
    setMyPreferences,
    timeZoneOptions,
    DATE_FORMAT_OPTIONS,
    TIME_FORMAT_OPTIONS,
    choiceLabel,
    previewDateTime,
  } from '../datetime.svelte.js';

  // The signed-in account's own settings, one tab each. Preferences,
  // two-factor login and API tokens need a server that keeps per-user
  // preferences (`display.mine`); the password tab is always there.
  let { user } = $props();
  const isViewer = $derived(user?.role === 'viewer');

  const TABS = $derived(
    [
      {
        id: 'preferences',
        label: 'Preferences',
        tagline: 'How dates and times are shown to you, on any device you sign in from.',
        personal: true,
      },
      {
        id: 'password',
        label: 'Password',
        tagline: 'Change the password you sign in with.',
      },
      {
        id: 'two-factor',
        label: 'Two-Factor Login',
        tagline: 'Ask for a code from your phone when signing in, so a stolen password is not enough.',
        personal: true,
      },
      {
        id: 'tokens',
        label: 'API Tokens',
        tagline: 'Tokens for scripts and tools that use the API as you.',
        personal: true,
      },
    ].filter((t) => display.mine || !t.personal),
  );
  let tab = $state(display.mine ? 'preferences' : 'password');
  const current = $derived(TABS.find((t) => t.id === tab) || TABS[0]);

  // Preferences.
  const zoneChoices = timeZoneOptions();
  let prefsDraft = $state({ time_zone: '', date_format: '', time_format: '', ...display.mine });
  let prefsError = $state(null);
  let prefsNotice = $state(null);
  let savingPrefs = $state(false);

  async function submitPrefs(e) {
    e.preventDefault();
    prefsError = null;
    prefsNotice = null;
    savingPrefs = true;
    try {
      await api.savePreferences(prefsDraft);
      setMyPreferences(prefsDraft);
      prefsNotice = 'Preferences saved.';
    } catch (err) {
      prefsError = String(err.message || err);
    } finally {
      savingPrefs = false;
    }
  }

  // Password.
  let currentPassword = $state('');
  let newPassword = $state('');
  let newPassword2 = $state('');
  let passwordError = $state(null);
  let passwordNotice = $state(null);
  let changingPassword = $state(false);

  async function submitPassword(e) {
    e.preventDefault();
    passwordError = null;
    passwordNotice = null;
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
      currentPassword = '';
      newPassword = '';
      newPassword2 = '';
      passwordNotice = 'Password changed. Your other sessions were signed out.';
    } catch (err) {
      passwordError = String(err.message || err);
    } finally {
      changingPassword = false;
    }
  }
</script>

<PageHeader icon={icons.account} title="Account" tagline={current.tagline} />

<div class="tabs">
  {#each TABS as t (t.id)}
    <button class="tab" class:active={current.id === t.id} onclick={() => (tab = t.id)}>{t.label}</button>
  {/each}
</div>

{#if current.id === 'preferences'}
  <form class="card panel" onsubmit={submitPrefs}>
    <h3 style="margin: 0">Preferences</h3>
    <p class="note">
      "Server Default" follows the setting an administrator chose for everyone.
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
    <p class="note">Example: <strong>{previewDateTime(prefsDraft)}</strong></p>
    {#if prefsError}<div class="form-error">{prefsError}</div>{/if}
    {#if prefsNotice}<div class="form-ok">{prefsNotice}</div>{/if}
    <div class="actions">
      <button type="submit" disabled={savingPrefs}>{savingPrefs ? 'Saving…' : 'Save Preferences'}</button>
    </div>
  </form>
{:else if current.id === 'password'}
  <form class="card panel" onsubmit={submitPassword}>
    <h3 style="margin: 0">Password</h3>
    <p class="note">
      Changing your password signs out your other sessions; this device stays
      signed in.
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
    {#if passwordNotice}<div class="form-ok">{passwordNotice}</div>{/if}
    <div class="actions">
      <button type="submit" disabled={changingPassword || !currentPassword || !newPassword || !newPassword2}>
        {changingPassword ? 'Saving…' : 'Save Password'}
      </button>
    </div>
  </form>
{:else if current.id === 'two-factor'}
  <TwoFactor />
{:else}
  <ApiTokens readOnlyAccount={isViewer} />
{/if}

<style>
  .panel { max-width: 560px; display: flex; flex-direction: column; gap: 12px; }
  .note { margin: 0; font-size: 0.85rem; color: var(--muted); line-height: 1.45; }
  label { display: flex; flex-direction: column; gap: 4px; font-size: 0.85rem; }
  label span { color: var(--muted); }
  .form-error { color: var(--danger); font-size: 0.85rem; }
  .form-ok { color: var(--ok); font-size: 0.85rem; }
  .actions { display: flex; gap: 8px; }
</style>
