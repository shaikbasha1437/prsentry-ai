const diff = require('../js/diff.js');
const rules = require('../js/rules.js');
const review = require('../js/review.js');
/* Build a diff that ADDS the given lines to path (optionally with context and removed lines). */
function addDiff(path, added, opts) {
  const o = opts || {}; const ctx = o.context || []; const del = o.removed || [];
  const body = ctx.map((l) => ' ' + l).concat(del.map((l) => '-' + l), added.map((l) => '+' + l));
  return 'diff --git a/' + path + ' b/' + path + '\n--- a/' + path + '\n+++ b/' + path + '\n@@ -1,' + (ctx.length + del.length) + ' +1,' + (ctx.length + added.length) + ' @@\n' + body.join('\n') + '\n';
}
function run(path, added, opts) { return rules.analyze(diff.parse(addDiff(path, added, opts)).files, opts && opts.analyze); }
function ids(path, added, opts) { return run(path, added, opts).map((f) => f.ruleId); }
const J = (...a) => a.join(''); // build fake secret-shaped strings without storing them contiguously in the repo
module.exports = { diff, rules, review, addDiff, run, ids, J };
