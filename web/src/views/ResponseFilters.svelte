<script>
  import { api, formatApiError } from '../api.js';

  let loaded = $state(false);
  let cnameInspection = $state(true);
  let cnameBusy = $state(false);
  let safeSearch = $state(false);
  let youtubeRestricted = $state(false);
  let safeBusy = $state(false);
  let filterAaaa = $state(false);
  let filterAaaaExcept = $state('');
  let busy = $state(false);
  let error = $state(null);
  let notice = $state(null);

  async function load() {
    error = null;
    try {
      const cfg = await api.config();
      cnameInspection = cfg?.policy?.cname_inspection !== false;
      safeSearch = !!cfg?.policy?.safe_search;
      youtubeRestricted = !!cfg?.policy?.youtube_restricted;
      filterAaaa = !!cfg?.policy?.filter_aaaa;
      // Load the saved exceptions: Save sends the whole list, so starting
      // empty would erase them on the next save.
      filterAaaaExcept = (cfg?.policy?.filter_aaaa_except || []).join('\n');
      loaded = true;
    } catch (e) {
      error = formatApiError(e);
    }
  }

  // Split a textarea into a trimmed list on newlines or commas.
  function parseList(text) {
    return (text || '')
      .split(/[\n,]/)
      .map((s) => s.trim())
      .filter(Boolean);
  }

  async function saveCnameInspection() {
    cnameBusy = true;
    error = null;
    notice = null;
    try {
      await api.updateSettings({ policy: { cname_inspection: cnameInspection } });
      notice = `CNAME inspection ${cnameInspection ? 'on' : 'off'}.`;
    } catch (e) {
      error = formatApiError(e);
    } finally {
      cnameBusy = false;
    }
  }

  async function saveSafeSearch() {
    safeBusy = true;
    error = null;
    notice = null;
    try {
      await api.updateSettings({
        policy: { safe_search: safeSearch, youtube_restricted: youtubeRestricted },
      });
      notice = 'Safe Search settings saved.';
    } catch (e) {
      error = formatApiError(e);
    } finally {
      safeBusy = false;
    }
  }

  async function saveFilterAaaa() {
    busy = true;
    error = null;
    notice = null;
    try {
      await api.updateSettings({
        policy: {
          filter_aaaa: filterAaaa,
          filter_aaaa_except: parseList(filterAaaaExcept),
        },
      });
      notice = 'Filter AAAA settings saved.';
    } catch (e) {
      error = formatApiError(e);
    } finally {
      busy = false;
    }
  }

  $effect(() => {
    load();
  });
</script>

{#if notice}
  <div class="card" style="border-color: var(--ok); margin-bottom: 14px">{notice}</div>
{/if}
{#if error}
  <div class="card" style="border-color: var(--danger); color: var(--danger); margin-bottom: 14px">{error}</div>
{/if}

{#if loaded}
  <div class="card" style="margin-bottom: 14px">
    <div class="spread" style="margin-bottom: 10px">
      <h3 style="margin: 0">CNAME Inspection</h3>
      <label class="check">
        <input type="checkbox" bind:checked={cnameInspection} /> <span>Enabled</span>
      </label>
    </div>
    <p class="muted help" style="margin: 0 0 10px">
      Also checks the names an answer leads to through CNAME records, and blocks
      the query when one of them is blocked. Trackers often hide behind a
      first-party name (<code>metrics.shop.example</code> pointing to
      <code>tracker.example</code>) that a blocklist alone would let through.
      Blocklists, Allow &amp; Block Lists and filtering groups all apply; a
      name on the allow list is never blocked this way.
    </p>
    <div class="row">
      <button onclick={saveCnameInspection} disabled={cnameBusy}>{cnameBusy ? 'Saving...' : 'Save'}</button>
    </div>
  </div>

  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">Safe Search</h3>
    <label class="check">
      <input type="checkbox" bind:checked={safeSearch} />
      <span>Force Safe Search on Google, Bing and DuckDuckGo</span>
    </label>
    <label class="check" style="margin-top: 6px">
      <input type="checkbox" bind:checked={youtubeRestricted} />
      <span>Force YouTube Restricted Mode</span>
    </label>
    <p class="muted help" style="margin: 10px 0">
      Answers the search engines' names with their "safe" addresses, which
      hide explicit results whatever the device, browser or account settings
      say. These switches apply to every client; to turn them on for some
      devices only, leave them off here and tick them in a filtering group
      under Clients → Filtering Groups. Devices using their own encrypted DNS
      (for example a browser's secure DNS) bypass this, as they bypass all
      filtering.
    </p>
    <div class="row">
      <button onclick={saveSafeSearch} disabled={safeBusy}>{safeBusy ? 'Saving...' : 'Save'}</button>
    </div>
  </div>

  <div class="card">
    <div class="spread" style="margin-bottom: 10px">
      <h3 style="margin: 0">Filter AAAA (Force IPv4)</h3>
      <label class="check">
        <input type="checkbox" bind:checked={filterAaaa} /> <span>Enabled</span>
      </label>
    </div>
    <p class="muted help" style="margin: 0 0 10px">
      Answers IPv6 (AAAA) lookups with an empty response, so devices with both
      IPv4 and IPv6 use IPv4. Useful when IPv6 is broken or slow on your
      network.
    </p>
    <label class="field">
      <span>Keep IPv6 For</span>
      <textarea
        rows="3"
        placeholder={'*.ipv6.example.com\nnas.home.arpa'}
        bind:value={filterAaaaExcept}
      ></textarea>
    </label>
    <p class="muted help">Names that keep their IPv6 answers, one per line; <code>*.example.com</code> covers the subdomains.</p>
    <div class="row" style="margin-top: 10px">
      <button onclick={saveFilterAaaa} disabled={busy}>{busy ? 'Saving...' : 'Save'}</button>
    </div>
  </div>
{:else if !error}
  <div class="card">
    <p class="muted">Loading...</p>
  </div>
{/if}

<style>
  textarea { width: 100%; }
  .field { display: flex; flex-direction: column; gap: 4px; font-size: 0.85rem; color: var(--muted); }
  .check { display: inline-flex; align-items: center; gap: 8px; }
</style>
