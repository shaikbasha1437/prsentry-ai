/* PRSentry GitHub client (read-only from the browser): PR URL parsing and fetching metadata + unified diff
   through the public REST API, which allows CORS. An optional token is sent only to api.github.com. */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory(require('./diff.js'));
  else (root.PRSentry = root.PRSentry || {}).github = factory(root.PRSentry.diff);
})(typeof self !== 'undefined' ? self : this, function (diff) {
  'use strict';
  const API = 'https://api.github.com';
  function parsePrUrl(input) {
    const s = String(input || '').trim();
    let m = /^(?:https?:\/\/)?(?:www\.)?github\.com\/([\w.-]+)\/([\w.-]+)\/pull\/(\d+)(?:[/?#].*)?$/i.exec(s);
    if (!m) m = /^([\w.-]+)\/([\w.-]+)#(\d+)$/.exec(s);
    if (!m) return null;
    return { owner: m[1], repo: m[2].replace(/\.git$/, ''), number: +m[3] };
  }
  function headers(token, accept) { const h = { Accept: accept || 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' }; if (token) h.Authorization = 'Bearer ' + token; return h; }
  function explain(status, body, rate) {
    if (status === 404) return 'Pull request not found. Check the URL; private repositories need a token with read access.';
    if (status === 401) return 'GitHub rejected the token. Check it or remove it in Settings.';
    if ((status === 403 || status === 429) && rate === '0') return 'GitHub API rate limit reached for your IP (60 requests/hour without a token). Add a token in Settings or try again later.';
    if (status === 406 || status === 422) return 'GitHub would not render this diff (it may be too large). Falling back to the per-file patch list.';
    return 'GitHub API error ' + status + (body && body.message ? ': ' + String(body.message).slice(0, 160) : '');
  }
  async function get(f, url, token, accept) {
    let res;
    try { res = await f(url, { headers: headers(token, accept) }); } catch (e) { throw new Error('Could not reach api.github.com (offline or blocked).'); }
    const text = await res.text();
    if (!res.ok) { let j = null; try { j = JSON.parse(text); } catch (e) { /* ignore */ } const err = new Error(explain(res.status, j, res.headers && res.headers.get && res.headers.get('x-ratelimit-remaining'))); err.status = res.status; throw err; }
    return { text, rate: res.headers && res.headers.get ? res.headers.get('x-ratelimit-remaining') : null };
  }
  /* fetchPr({owner,repo,number}, {fetch, token}) -> { pr, diffText, files } */
  async function fetchPr(ref, deps) {
    const d = deps || {}; const f = d.fetch || fetch.bind(globalThis); const token = d.token || '';
    const base = (d.apiBase || API) + '/repos/' + encodeURIComponent(ref.owner) + '/' + encodeURIComponent(ref.repo) + '/pulls/' + ref.number;
    const meta = JSON.parse((await get(f, base, token)).text);
    let diffText; let rate = null; let source = 'diff';
    try { const r = await get(f, base, token, 'application/vnd.github.diff'); diffText = r.text; rate = r.rate; }
    catch (e) {
      if (e.status !== 406 && e.status !== 422) throw e;
      const entries = []; source = 'files';
      for (let page = 1; page <= 10; page++) { const r = await get(f, base + '/files?per_page=100&page=' + page, token); const arr = JSON.parse(r.text); entries.push(...arr); rate = r.rate; if (arr.length < 100) break; }
      diffText = diff.fromGithubFiles(entries);
    }
    const pr = { owner: ref.owner, repo: ref.repo, number: ref.number, url: meta.html_url || 'https://github.com/' + ref.owner + '/' + ref.repo + '/pull/' + ref.number, title: meta.title || '', author: meta.user && meta.user.login, body: String(meta.body || '').slice(0, 4000), base: meta.base && meta.base.ref, head: meta.head && meta.head.ref, headSha: meta.head && meta.head.sha, state: meta.state, draft: !!meta.draft, additions: meta.additions, deletions: meta.deletions, changedFiles: meta.changed_files, rateRemaining: rate, source };
    return { pr, diffText, files: diff.parse(diffText).files };
  }
  return { API, parsePrUrl, fetchPr, headers, explain };
});
