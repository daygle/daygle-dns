// What can block a query, as the query log and the "Why Blocked?" tool name
// it (the server's `block.source` / check `source` values).
export const BLOCK_SOURCES = [
  ['blocklist_source', 'Blocklist'],
  ['blocklist', 'Block List'],
  ['allowlist', 'Allow List'],
  ['group', 'Filtering Group'],
  ['service', 'Blocked Service'],
  ['group_blocklist', 'Group Blocklist'],
  ['ai', 'AI Scanner'],
  ['rpz', 'Response Policy Zone'],
  ['cname', 'CNAME Inspection'],
  ['denied_network', 'Denied Network'],
  ['listener', 'Listener Access'],
  ['aaaa_filter', 'Filter AAAA'],
  ['client_rule', 'Client Rule'],
  ['safe_search', 'Safe Search'],
  ['plugin', 'Plugin'],
];

const LABELS = Object.fromEntries(BLOCK_SOURCES);

export function blockSourceLabel(source) {
  return LABELS[source] || (source ? source.replaceAll('_', ' ') : '-');
}
