/* PRSentry AI GitHub Action (no dependencies; runs on Node 20+). Shares the exact rule engine used by the web app. */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const diff = require('../js/diff.js');
const rules = require('../js/rules.js');
const review = require('../js/review.js');
const github = require('../js/github.js');
const llm = require('../js/llm.js');

const SEV = ['critical', 'high', 'medium', 'low', 'info'];
function input(env, name, def) { const v = env['INPUT_' + name.replace(/ /g, '_').toUpperCase()]; return v == null || v === '' ? (def == null ? '' : def) : String(v).trim(); }
function bool(v) { return /^(true|1|yes|on)$/i.test(String(v)); }
function esc(s) { return String(s).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A'); }
function escProp(s) { return esc(s).replace(/:/g, '%3A').replace(/,/g, '%2C'); }

async function api(f, base, token, method, p, body) {
  const res = await f(base + p, { method, headers: { Accept: 'application/vnd.github+json', Authorization: 'Bearer ' + token, 'X-GitHub-Api-Version': '2022-11-28', 'Content-Type': 'application/json', 'User-Agent': 'prsentry-ai-action' }, body: body ? JSON.stringify(body) : undefined });
  const text = await res.text(); let json = null; try { json = JSON.parse(text); } catch (e) { /* not json */ }
  return { ok: res.ok, status: res.status, json, text };
}

/* run(env, deps) -> { findings, summary, sarifPath, posted, uploaded, exitCode }. deps: { fetch, log, cwd } */
async function run(env, deps) {
  const d = deps || {};
  const f = d.fetch || fetch;
  const log = d.log || ((s) => process.stdout.write(s + '\n'));
  const cwd = env.GITHUB_WORKSPACE || d.cwd || process.cwd();
  const apiBase = (env.GITHUB_API_URL || 'https://api.github.com').replace(/\/$/, '');
  const token = input(env, 'github-token');
  const mode = input(env, 'mode', 'rules').toLowerCase();
  const dryRun = bool(input(env, 'dry-run', 'false'));
  const failOn = input(env, 'fail-on', 'high').toLowerCase();
  const key = input(env, 'llm-api-key');
  if (key) log('::add-mask::' + key);
  const event = env.GITHUB_EVENT_PATH && fs.existsSync(env.GITHUB_EVENT_PATH) ? JSON.parse(fs.readFileSync(env.GITHUB_EVENT_PATH, 'utf8')) : {};
  const [owner, repo] = String(env.GITHUB_REPOSITORY || '/').split('/');
  const number = parseInt(input(env, 'pr-number') || (event.pull_request && event.pull_request.number) || (event.number) || '', 10);
  if (!owner || !repo || !number) throw new Error('PRSentry needs a pull_request event (or the pr-number input) and GITHUB_REPOSITORY.');
  if (!token) throw new Error('No github-token available.');

  log('PRSentry AI ' + review.VERSION + ': reviewing ' + owner + '/' + repo + '#' + number + ' in ' + mode + ' mode' + (dryRun ? ' (dry run: no GitHub writes)' : ''));
  const { pr, files } = await github.fetchPr({ owner, repo, number }, { fetch: f, token, apiBase });
  if (!pr.headSha && event.pull_request && event.pull_request.head) pr.headSha = event.pull_request.head.sha;
  const disabled = input(env, 'disabled-rules').split(',').map((s) => s.trim()).filter(Boolean);
  let findings = rules.analyze(files, { disabled });
  log('Rules: ' + findings.length + ' finding(s) across ' + files.length + ' file(s).');
  let unanchored = [];
  let llmUsed = false;
  if (mode === 'llm') {
    const provider = input(env, 'llm-provider', 'openai');
    if (!llm.PROVIDERS[provider]) throw new Error('Unknown llm-provider "' + provider + '".');
    if (llm.PROVIDERS[provider].needsKey && !key) log('::warning::mode is "llm" but llm-api-key is empty; continuing with rules only.');
    else {
      const cfg = { provider, key, model: input(env, 'llm-model') || llm.PROVIDERS[provider].defaultModel, baseUrl: input(env, 'llm-base-url') || undefined, referer: 'https://github.com/' + owner + '/' + repo, title: 'PRSentry AI Action' };
      const chunks = review.chunkDiff(files, 12000).slice(0, Math.max(1, parseInt(input(env, 'max-llm-chunks', '6'), 10) || 6));
      const llmFindings = [];
      for (let i = 0; i < chunks.length; i++) {
        try {
          const m = review.buildMessages(chunks[i], pr);
          const out = await llm.call(cfg, m, { fetch: f, timeoutMs: 90000 });
          const parsed = review.parseLLM(out.text);
          if (parsed.error) log('::warning::LLM chunk ' + (i + 1) + ': ' + parsed.error);
          for (const w of review.llmOutputWarnings(parsed, out.text)) log('::warning::' + w);
          llmFindings.push(...parsed.findings);
          llmUsed = true;
        } catch (e) { log('::warning::LLM chunk ' + (i + 1) + ' failed: ' + String(e.message || e).replace(key || '\u0000', '***')); }
      }
      const a = review.anchor(llmFindings, files);
      unanchored = a.unanchored;
      findings = review.merge(findings, a.anchored);
      log('LLM: ' + a.anchored.length + ' anchored, ' + a.unanchored.length + ' unanchored (dropped from inline comments).');
    }
  }
  const opts = { mode: llmUsed ? 'rules + llm' : 'rules', unanchored: unanchored.length, unanchoredList: unanchored, maxComments: parseInt(input(env, 'max-comments', '30'), 10) || 30, allowApprove: bool(input(env, 'allow-approve', 'false')) };
  const summary = review.summarize(findings, {}, opts);
  // SARIF + annotations + job summary (no permissions needed)
  const sarifDoc = review.sarif(pr, findings, {}, opts);
  const sarifPath = path.resolve(cwd, input(env, 'sarif-file', 'prsentry.sarif'));
  fs.mkdirSync(path.dirname(sarifPath), { recursive: true });
  fs.writeFileSync(sarifPath, JSON.stringify(sarifDoc, null, 2));
  for (const x of findings.slice(0, 50)) {
    const level = x.severity === 'critical' || x.severity === 'high' ? 'error' : x.severity === 'medium' ? 'warning' : 'notice';
    log('::' + level + ' file=' + escProp(x.file) + (x.line ? ',line=' + x.line : '') + ',title=' + escProp('PRSentry ' + x.severity + ': ' + x.title) + '::' + esc(x.explanation.slice(0, 400)));
  }
  const md = review.reviewMarkdown(pr, findings, {}, opts);
  if (env.GITHUB_STEP_SUMMARY) fs.appendFileSync(env.GITHUB_STEP_SUMMARY, md + '\n');
  let posted = false; let uploaded = false;
  if (!dryRun && bool(input(env, 'upload-sarif', 'false'))) {
    const body = { commit_sha: pr.headSha, ref: 'refs/pull/' + number + '/head', sarif: zlib.gzipSync(Buffer.from(JSON.stringify(sarifDoc))).toString('base64'), tool_name: 'PRSentry AI' };
    const r = await api(f, apiBase, token, 'POST', '/repos/' + owner + '/' + repo + '/code-scanning/sarifs', body);
    if (r.ok) { uploaded = true; log('Uploaded SARIF to code scanning (id ' + (r.json && r.json.id) + ').'); }
    else log('::warning::SARIF upload failed (' + r.status + '): ' + ((r.json && r.json.message) || r.text).slice(0, 200) + '. Needs "security-events: write" and code scanning available for this repository.');
  }
  if (!dryRun && bool(input(env, 'post-review', 'true'))) {
    const payload = review.reviewPayload(pr, findings, {}, opts);
    const p = '/repos/' + owner + '/' + repo + '/pulls/' + number + '/reviews';
    let r = await api(f, apiBase, token, 'POST', p, payload);
    if (!r.ok && r.status === 422 && payload.comments.length) {
      log('::warning::GitHub rejected inline comments (' + ((r.json && r.json.message) || '422') + '); retrying with a summary-only review.');
      r = await api(f, apiBase, token, 'POST', p, { event: payload.event, body: md.slice(0, 60000), commit_id: payload.commit_id });
    }
    if (!r.ok && payload.event === 'APPROVE') r = await api(f, apiBase, token, 'POST', p, Object.assign({}, payload, { event: 'COMMENT' }));
    if (r.ok) { posted = true; log('Posted review: ' + payload.event + ' with ' + payload.comments.length + ' inline comment(s).'); }
    else log('::warning::Could not post the review (' + r.status + '): ' + ((r.json && r.json.message) || r.text).slice(0, 200) + '. Fork PRs get a read-only GITHUB_TOKEN; needs "pull-requests: write".');
  }
  if (env.GITHUB_OUTPUT) fs.appendFileSync(env.GITHUB_OUTPUT, 'findings=' + findings.length + '\nrecommendation=' + summary.event + '\nscore=' + summary.score + '\nsarif-file=' + sarifPath + '\n');
  let exitCode = 0;
  const idx = SEV.indexOf(failOn);
  if (idx >= 0) { const bad = findings.filter((x) => SEV.indexOf(x.severity) <= idx); if (bad.length) { exitCode = 1; log('::error::PRSentry found ' + bad.length + ' finding(s) at or above "' + failOn + '". Recommendation: ' + summary.label + ' (score ' + summary.score + ').'); } }
  if (!exitCode) log('PRSentry: ' + summary.label + ' (score ' + summary.score + '/100).');
  return { findings, summary, sarifPath, posted, uploaded, exitCode, unanchored };
}
module.exports = { run, input, bool };
if (require.main === module) {
  run(process.env).then((r) => { process.exitCode = r.exitCode; }).catch((e) => { process.stdout.write('::error::' + esc(e.message || String(e)) + '\n'); process.exitCode = 1; });
}
