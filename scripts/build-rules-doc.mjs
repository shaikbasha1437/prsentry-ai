// Regenerates docs/RULES.md from the rule catalog (SARIF helpUri links point at these anchors).
import { createRequire } from 'node:module'; import fs from 'node:fs';
const require = createRequire(import.meta.url);
const rules = require('../js/rules.js');
const cat = rules.ruleCatalog();
let md = '# PRSentry AI rule catalog\n\n' + cat.length + ' deterministic checks. They run only on **added** lines of a diff, one line at a time (plus a few lines of context). They are heuristics: expect false positives and false negatives. They are not a substitute for a SAST tool or human review.\n\n| Rule | Default severity | Category | CWE |\n|---|---|---|---|\n';
for (const r of cat) md += '| [`' + r.id + '`](#' + r.id + ') ' + r.title + ' | ' + r.severity + ' | ' + r.category + ' | ' + (r.cwe || '') + ' |\n';
md += '\nSome rules raise or lower severity from context (for example a weak hash next to "password" becomes high; next to "etag" it becomes low; CORS `*` with credentials becomes high).\n';
for (const r of cat) md += '\n## ' + r.id + '\n\n**' + r.title + '** · ' + r.severity + ' · ' + r.category + (r.cwe ? ' · [' + r.cwe + '](https://cwe.mitre.org/data/definitions/' + r.cwe.slice(4) + '.html)' : '') + '\n\n' + r.explain + '\n';
fs.writeFileSync(new URL('../docs/RULES.md', import.meta.url), md);
console.log('docs/RULES.md:', cat.length, 'rules');
