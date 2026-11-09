const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { diff, rules, review } = require('./helpers.cjs');
const raw = fs.readFileSync(__dirname + '/../samples/demo-prs.json', 'utf8');
const demos = JSON.parse(raw).prs;
const result = (id) => { const p = demos.find((d) => d.id === id); const files = diff.parse(p.diff).files; const f = rules.analyze(files); return { p, files, f, s: review.summarize(f), has: (r) => f.some((x) => x.ruleId === r) }; };

test('six original demo PRs ship with the app', () => {
  assert.deepEqual(demos.map((d) => d.id), ['clean-refactor', 'sql-injection', 'leaked-secret', 'react-xss', 'async-bug', 'prompt-injection']);
  for (const d of demos) { assert.ok(d.title && d.diff && d.description); assert.ok(diff.parse(d.diff).files.length >= 1); assert.match(d.url, /\.example\//); }
});
test('demo file never stores provider-shaped secrets contiguously (secret scanning safe)', () => {
  assert.ok(!/AKIA[A-Z0-9]{16}/.test(raw)); assert.ok(!/hooks\.slack\.com/.test(raw)); assert.ok(!/gh[pousr]_[A-Za-z0-9]{30}/.test(raw)); assert.ok(!/xox[abposr]-/.test(raw));
});
test('clean refactor: no findings, approve', () => {
  const r = result('clean-refactor'); assert.equal(r.f.length, 0); assert.equal(r.s.event, 'APPROVE'); assert.equal(r.s.score, 100);
  assert.ok(r.files.some((f) => f.status === 'added' && f.path === 'test/dates.test.js'));
});
test('SQL injection PR: two SQL findings, missing tests, request changes', () => {
  const r = result('sql-injection');
  assert.equal(r.f.filter((x) => x.ruleId === 'sql-injection').length, 2); assert.ok(r.has('missing-tests')); assert.ok(r.has('loose-equality'));
  assert.equal(r.s.event, 'REQUEST_CHANGES');
});
test('leaked secret PR: fake AWS key + Slack webhook (critical), credential, sensitive log, debugger, TODO', () => {
  const r = result('leaked-secret');
  for (const id of ['secret-aws-access-key', 'secret-slack-token', 'secret-generic', 'sensitive-log', 'debug-leftover', 'todo-added']) assert.ok(r.has(id), id);
  assert.equal(r.s.counts.critical, 2); assert.equal(r.s.event, 'REQUEST_CHANGES'); assert.ok(!r.has('missing-tests'));
  assert.ok(r.f.find((x) => x.ruleId === 'secret-aws-access-key').confidence <= 0.6, 'placeholder value lowers confidence');
});
test('React XSS PR: dangerouslySetInnerHTML (high) and innerHTML (medium) with fixes', () => {
  const r = result('react-xss'); const x = r.f.filter((f) => f.ruleId === 'xss-sink');
  assert.equal(x.length, 2); assert.deepEqual(x.map((f) => f.severity).sort(), ['high', 'medium']);
  assert.ok(x.every((f) => f.fix && f.fix.replacement)); assert.equal(r.s.event, 'REQUEST_CHANGES');
});
test('async bug PR: floating promise, async forEach, off-by-one, swallowed error, deps; comment', () => {
  const r = result('async-bug');
  for (const id of ['floating-promise', 'off-by-one', 'swallowed-error', 'dependency-added', 'dependency-bump']) assert.ok(r.has(id), id);
  assert.equal(r.f.filter((x) => x.ruleId === 'floating-promise').length, 2);
  assert.equal(r.s.event, 'COMMENT');
});
test('prompt-injection PR: reviewer-directed comment caught, plus the real bugs it tried to hide', () => {
  const r = result('prompt-injection');
  assert.ok(r.has('prompt-injection')); assert.ok(r.has('command-injection')); assert.ok(r.has('unsafe-deserialization'));
  assert.ok(r.s.injection); assert.equal(r.s.event, 'REQUEST_CHANGES');
});
test('every demo exports schema-shaped SARIF and a review payload', () => {
  for (const d of demos) {
    const f = rules.analyze(diff.parse(d.diff).files);
    assert.deepEqual(review.validateSarif(review.sarif(d, f, {})), [], d.id);
    const p = review.reviewPayload(d, f, {}); assert.ok(['APPROVE', 'COMMENT', 'REQUEST_CHANGES'].includes(p.event));
  }
});
