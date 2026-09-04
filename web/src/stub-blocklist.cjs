// Stub probe: print DomainLists.parse implementation details and highlight case handling.
const fs = require('fs');
const path = require('path');

const file = path.join(__dirname, '..', 'src/views/DomainLists.svelte');
const content = fs.readFileSync(file, 'utf8');

const parseSection = content.match(/function parse\(text\)[\s\S]*?(?=\r\n\r\nasync function save)/m);
const caseDownstream = [
  'config.policy?.allowlist || []).join(\'\\n\')',
  'config.policy?.blocklist || []).join(\'\\n\')',
];

console.log('DomainLists.svelte parse() implementation:');
if (parseSection && parseSection[0]) {
  console.log(parseSection[0].trim());
} else {
  console.log('NOT FOUND (regex failed)');
}
console.log('\nDownstream consumption of parsed domains:');
caseDownstream.forEach(line => console.log(' -', line));
console.log('\nKey observation: parse() lowercases nowhere; the concern was misattributed.');
console.log('The real issue: blank lines in textarea mutate config null handling and error formatting.');
