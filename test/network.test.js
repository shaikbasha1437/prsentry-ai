const { test } = require('node:test');
const assert = require('node:assert/strict');
const github = require('../js/github.js');
const llm = require('../js/llm.js');

function mockFetch(routes, log) {
  return async (url, init) => {
    log && log.push({ url, init });
    for (const [re, fn] of routes) if (re.test(url) && (!fn.accept || (init.headers.Accept || '').includes(fn.accept))) { const r = fn(url, init); return { ok: r.status < 400, status: r.status, text: async () => (typeof r.body === 'string' ? r.body : JSON.stringify(r.body)), headers: { get: (k) => (r.headers || {})[k.toLowerCase()] || null } }; }
    throw new TypeError('network');
  };
}
const META = { html_url: 'https://github.com/o/r/pull/5', title: 'T', user: { login: 'u' }, body: 'b', base: { ref: 'main' }, head: { ref: 'f', sha: 'deadbeef' }, state: 'open', additions: 1, deletions: 0, changed_files: 1 };
const DIFF = 'diff --git a/a.js b/a.js\n--- a/a.js\n+++ b/a.js\n@@ -1 +1,2 @@\n x\n+eval(y)\n';

test('parsePrUrl accepts PR URLs and owner/repo#n, rejects others', () => {
  assert.deepEqual(github.parsePrUrl('https://github.com/acme/shop/pull/12'), { owner: 'acme', repo: 'shop', number: 12 });
  assert.deepEqual(github.parsePrUrl('github.com/acme/shop.js/pull/3/files#diff-1'), { owner: 'acme', repo: 'shop.js', number: 3 });
  assert.deepEqual(github.parsePrUrl('acme/shop#9'), { owner: 'acme', repo: 'shop', number: 9 });
  assert.equal(github.parsePrUrl('https://github.com/acme/shop/issues/12'), null);
  assert.equal(github.parsePrUrl('https://evil.example/acme/shop/pull/1'), null);
});
test('fetchPr gets metadata + diff; token only sent as Authorization to the API', async () => {
  const log = [];
  const f = mockFetch([[/\/pulls\/5$/, Object.assign((u, i) => (i.headers.Accept.includes('diff') ? { status: 200, body: DIFF, headers: { 'x-ratelimit-remaining': '4999' } } : { status: 200, body: META }), {})]], log);
  const out = await github.fetchPr({ owner: 'o', repo: 'r', number: 5 }, { fetch: f, token: 'fixture-pat-not-real' });
  assert.equal(out.pr.title, 'T'); assert.equal(out.pr.headSha, 'deadbeef'); assert.equal(out.files.length, 1); assert.equal(out.pr.rateRemaining, '4999'); assert.equal(out.pr.source, 'diff');
  assert.equal(log.length, 2); assert.ok(log.every((l) => l.url.startsWith('https://api.github.com/repos/o/r/pulls/5')));
  assert.ok(log.every((l) => l.init.headers.Authorization === 'Bearer fixture-pat-not-real')); assert.equal(log[1].init.headers.Accept, 'application/vnd.github.diff');
  assert.ok(!log.some((l) => /fixture-pat/.test(l.url)));
});
test('fetchPr without a token sends no Authorization header', async () => {
  const log = [];
  const f = mockFetch([[/\/pulls\/5$/, (u, i) => (i.headers.Accept.includes('diff') ? { status: 200, body: DIFF } : { status: 200, body: META })]], log);
  await github.fetchPr({ owner: 'o', repo: 'r', number: 5 }, { fetch: f });
  assert.ok(log.every((l) => !('Authorization' in l.init.headers)));
});
test('fetchPr falls back to the files endpoint when the diff is too large (406)', async () => {
  const f = mockFetch([[/\/files\?/, () => ({ status: 200, body: [{ filename: 'a.js', status: 'modified', changes: 1, patch: '@@ -1 +1,2 @@\n x\n+eval(y)' }] })], [/\/pulls\/5$/, (u, i) => (i.headers.Accept.includes('diff') ? { status: 406, body: { message: 'too large' } } : { status: 200, body: META })]]);
  const out = await github.fetchPr({ owner: 'o', repo: 'r', number: 5 }, { fetch: f });
  assert.equal(out.pr.source, 'files'); assert.equal(out.files[0].additions, 1);
});
test('fetchPr explains 404, 401, rate limit and offline errors', async () => {
  const mk = (status, headers) => mockFetch([[/./, () => ({ status, body: { message: 'x' }, headers })]]);
  await assert.rejects(github.fetchPr({ owner: 'o', repo: 'r', number: 1 }, { fetch: mk(404) }), /not found/);
  await assert.rejects(github.fetchPr({ owner: 'o', repo: 'r', number: 1 }, { fetch: mk(401) }), /rejected the token/);
  await assert.rejects(github.fetchPr({ owner: 'o', repo: 'r', number: 1 }, { fetch: mk(403, { 'x-ratelimit-remaining': '0' }) }), /rate limit/);
  await assert.rejects(github.fetchPr({ owner: 'o', repo: 'r', number: 1 }, { fetch: async () => { throw new TypeError('x'); } }), /Could not reach api\.github\.com/);
});
test('LLM request builders: Anthropic browser header, Gemini key header, OpenAI developer role, OpenRouter referer', () => {
  const msg = { system: 'S', messages: [{ role: 'user', content: 'U' }], maxTokens: 100, temperature: 0, json: true };
  const a = llm.buildRequest({ provider: 'anthropic', key: 'k', model: 'claude-haiku-4-5' }, msg);
  assert.equal(a.url, 'https://api.anthropic.com/v1/messages'); assert.equal(a.init.headers['anthropic-dangerous-direct-browser-access'], 'true'); assert.equal(a.init.headers['x-api-key'], 'k');
  const g = llm.buildRequest({ provider: 'gemini', key: 'k', model: 'gemini-2.5-flash' }, msg);
  assert.match(g.url, /models\/gemini-2\.5-flash:generateContent$/); assert.equal(g.init.headers['x-goog-api-key'], 'k'); assert.ok(!g.url.includes('key='));
  assert.equal(JSON.parse(g.init.body).generationConfig.responseMimeType, 'application/json');
  const o = llm.buildRequest({ provider: 'openai', key: 'k', model: 'gpt-5-mini' }, msg);
  const ob = JSON.parse(o.init.body); assert.equal(ob.messages[0].role, 'developer'); assert.deepEqual(ob.response_format, { type: 'json_object' });
  const r = llm.buildRequest({ provider: 'compatible', key: 'k', model: 'openai/gpt-5-mini', baseUrl: 'https://openrouter.ai/api/v1' }, msg);
  assert.equal(r.init.headers['HTTP-Referer'], 'https://shaikbasha1437.github.io/prsentry-ai/'); assert.equal(r.init.headers['X-Title'], 'PRSentry AI');
  const ol = llm.buildRequest({ provider: 'compatible', model: 'llama3.2' }, msg);
  assert.equal(ol.url, 'http://localhost:11434/v1/chat/completions'); assert.ok(!ol.init.headers.authorization);
});
test('LLM call parses replies, errors and network failures with mocked fetch', async () => {
  const reply = (body, status) => async () => ({ ok: (status || 200) < 400, status: status || 200, text: async () => JSON.stringify(body) });
  const r = await llm.call({ provider: 'anthropic', key: 'k' }, { system: 's', messages: [{ role: 'user', content: 'u' }] }, { fetch: reply({ content: [{ type: 'text', text: '{"findings":[]}' }], usage: { input_tokens: 10, output_tokens: 5 } }) });
  assert.equal(r.text, '{"findings":[]}'); assert.equal(r.usage.input, 10); assert.ok(r.cost > 0);
  await assert.rejects(llm.call({ provider: 'gemini', key: 'bad' }, { system: 's', messages: [] }, { fetch: reply({ error: { message: 'API key not valid' } }, 400) }), /key was rejected/);
  await assert.rejects(llm.call({ provider: 'openai', key: 'k' }, { system: 's', messages: [] }, { fetch: async () => { throw new TypeError('Failed to fetch'); } }), /OpenAI/);
  await assert.rejects(llm.call({ provider: 'openai' }, { system: 's', messages: [] }, { fetch: reply({}) }), /Add your OpenAI key/);
});
