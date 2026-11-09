/* PRSentry AI web app. Everything runs in the browser; keys stay in localStorage on this device only. */
(function () {
  'use strict';
  const P = window.PRSentry; const LLM = window.AgentKit.llm;
  const D = P.diff; const R = P.rules; const V = P.review; const G = P.github;
  const $ = (s, r) => (r || document).querySelector(s);
  const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const LS = { settings: 'prsentry.settings', keys: 'prsentry.keys', review: 'prsentry.review', theme: 'prsentry.theme' };
  const SEV = V.SEV; const CAT = V.CAT;
  const store = { get(k, d) { try { const v = localStorage.getItem(k); return v == null ? d : JSON.parse(v); } catch (e) { return d; } }, set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) { /* quota or private mode */ } }, del(k) { try { localStorage.removeItem(k); } catch (e) { /* ignore */ } } };

  let settings = Object.assign({ provider: 'openai', model: '', baseUrl: '', remember: true, maxChunks: 6, disabled: [] }, store.get(LS.settings, {}));
  let keys = Object.assign({ llm: '', github: '' }, settings.remember ? store.get(LS.keys, {}) : {});
  let demos = [];
  let state = store.get(LS.review, null); // { pr, diffText, source, demoId, llm, triage, loadedAt }
  let files = []; let ruleFindings = []; let findings = [];
  const ui = { view: 'findings', diffMode: 'unified', sev: 'all', cat: 'all', file: 'all', status: 'active', busy: false };

  /* ---------------- persistence + derive ---------------- */
  function saveState() { if (state) store.set(LS.review, state); else store.del(LS.review); }
  function saveSettings() { store.set(LS.settings, settings); if (settings.remember) store.set(LS.keys, keys); else store.del(LS.keys); }
  function derive() {
    if (!state) { files = []; ruleFindings = []; findings = []; return; }
    files = D.parse(state.diffText).files;
    ruleFindings = R.analyze(files, { disabled: settings.disabled });
    findings = V.merge(ruleFindings, (state.llm && state.llm.anchored) || []);
  }
  function statusOf(f) { return (state.triage[f.id] && state.triage[f.id].status) || 'open'; }
  function opts() { const un = (state.llm && state.llm.unanchored) || []; return { mode: state.llm ? (state.llm.simulated ? 'rules + simulated AI sample' : 'rules + ' + state.llm.providerLabel) : 'rules only', unanchored: un.length, unanchoredList: un }; }

  /* ---------------- toast with undo ---------------- */
  let toastTimer = null;
  function toast(msg, undo) {
    const t = $('#toast');
    t.innerHTML = '<span>' + esc(msg) + '</span>' + (undo ? '<button type="button" id="toast-undo">Undo</button>' : '');
    t.classList.add('show');
    if (undo) $('#toast-undo').onclick = () => { undo(); t.classList.remove('show'); };
    clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.remove('show'), undo ? 7000 : 3500);
  }
  function status(msg, isError) { const s = $('#status'); if (!msg) { s.hidden = true; return; } s.hidden = false; s.textContent = msg; s.classList.toggle('error', !!isError); }

  /* ---------------- modals: X, Cancel, Esc, backdrop, Back; discard prompt for unsaved edits ---------------- */
  let modal = null; let lastFocus = null;
  function openModal(title, html, o) {
    const op = o || {};
    if (modal) removeModal();
    lastFocus = document.activeElement;
    history.pushState({ prsModal: true }, '');
    $('#modal-host').innerHTML = '<div class="backdrop"><section class="modal ' + (op.wide ? 'wide' : '') + '" role="dialog" aria-modal="true" aria-labelledby="modal-title"><div class="modal-header"><h2 id="modal-title">' + esc(title) + '</h2><button type="button" data-close="x" aria-label="Close">×</button></div><div class="modal-body">' + html + '</div><div class="modal-footer">' + (op.extraFooter || '') + '<button type="button" data-close="cancel">' + esc(op.cancelLabel || (op.save ? 'Cancel' : 'Close')) + '</button>' + (op.save ? '<button type="button" id="modal-save" class="primary">' + esc(op.saveLabel || 'Save') + '</button>' : '') + '</div></section></div>';
    modal = { dirty: false, watch: !!op.dirty };
    document.body.style.overflow = 'hidden';
    $('.backdrop').addEventListener('mousedown', (e) => { if (e.target.classList.contains('backdrop')) closeModal(); });
    $$('[data-close]').forEach((b) => (b.onclick = () => closeModal()));
    $('.modal-body').addEventListener('input', () => { if (modal && modal.watch) modal.dirty = true; });
    if (op.save) $('#modal-save').onclick = () => op.save();
    if (op.onmount) op.onmount();
    setTimeout(() => { const first = $('.modal-body input:not([type=checkbox]):not([type=hidden]),.modal-body textarea,.modal-body select'); (op.focusFirst && first ? first : $('.modal [data-close=x]')).focus(); }, 0);
  }
  function removeModal() { modal = null; $('#modal-host').innerHTML = ''; document.body.style.overflow = ''; if (lastFocus && lastFocus.focus && document.contains(lastFocus)) lastFocus.focus(); }
  function closeModal(force) { if (!modal) return; if (!force && modal.dirty && !confirm('Discard unsaved changes?')) return; modal.dirty = false; history.back(); }
  addEventListener('popstate', () => { if (!modal) return; if (modal.dirty && !confirm('Discard unsaved changes?')) { history.pushState({ prsModal: true }, ''); return; } removeModal(); });
  addEventListener('keydown', (e) => {
    if (!modal) return;
    if (e.key === 'Escape') { e.preventDefault(); closeModal(); return; }
    if (e.key === 'Tab') { const els = $$('.modal button,.modal input,.modal select,.modal textarea,.modal a[href]').filter((x) => !x.disabled && x.offsetParent !== null); if (!els.length) return; const first = els[0]; const last = els[els.length - 1]; if (e.shiftKey && document.activeElement === first) { last.focus(); e.preventDefault(); } else if (!e.shiftKey && document.activeElement === last) { first.focus(); e.preventDefault(); } }
  });

  /* ---------------- loading ---------------- */
  function setReview(next, label) {
    const old = state;
    state = next; derive(); saveState(); ui.file = 'all'; ui.view = 'findings';
    render();
    $('#workspace').scrollIntoView({ behavior: 'smooth', block: 'start' });
    toast(label, old ? () => { state = old; derive(); saveState(); render(); toast('Previous review restored.'); } : null);
  }
  function blankReview(pr, diffText, source, demoId) { return { pr, diffText, source, demoId: demoId || null, llm: null, triage: {}, loadedAt: new Date().toISOString() }; }
  function loadDemo(id) {
    const d = demos.find((x) => x.id === id); if (!d) return;
    const pr = { title: d.title, owner: d.owner, repo: d.repo, number: d.number, url: d.url, author: d.author, base: d.base, head: d.head, body: d.description, headSha: null };
    setReview(blankReview(pr, d.diff, 'demo', d.id), 'Demo PR loaded: ' + d.title + '. Rules ran locally.');
  }
  function loadDiffText(text, name) {
    const parsed = D.parse(text);
    if (!parsed.files.length) { status('No unified diff found. Paste the output of git diff, git format-patch, or a GitHub .diff/.patch URL\u2019s contents.', true); return false; }
    status('');
    const pr = { title: parsed.meta.subject || name || 'Pasted diff', owner: null, repo: null, number: null, url: '', author: parsed.meta.from || '', headSha: null };
    setReview(blankReview(pr, text, name ? 'file' : 'paste'), (name ? 'Loaded ' + name : 'Diff loaded') + ': ' + parsed.files.length + ' file(s).');
    return true;
  }
  async function fetchPr(e) {
    if (e) e.preventDefault();
    const raw = $('#pr-url').value.trim();
    const ref = G.parsePrUrl(raw);
    if (!ref) { status('Enter a GitHub pull request URL like https://github.com/owner/repo/pull/123 (or owner/repo#123).', true); $('#pr-url').focus(); return; }
    if (ui.busy) return;
    ui.busy = true; $('#pr-fetch').disabled = true; status('Fetching ' + ref.owner + '/' + ref.repo + '#' + ref.number + ' from api.github.com…');
    try {
      const out = await G.fetchPr(ref, { token: keys.github });
      status('Fetched ' + out.files.length + ' file(s).' + (out.pr.rateRemaining ? ' GitHub API requests left this hour: ' + out.pr.rateRemaining + '.' : '') + (out.pr.source === 'files' ? ' (Large diff: rebuilt from the per-file patch list.)' : ''));
      setReview(blankReview(out.pr, out.diffText, 'github'), 'Fetched ' + ref.owner + '/' + ref.repo + '#' + ref.number + '.');
    } catch (err) { status(String(err.message || err), true); }
    finally { ui.busy = false; $('#pr-fetch').disabled = false; }
  }
  function readFile(file) {
    if (!file) return;
    if (file.size > 5 * 1024 * 1024) { status('That file is larger than 5 MB. Split the patch or paste a smaller diff.', true); return; }
    const r = new FileReader();
    r.onload = () => loadDiffText(String(r.result), file.name);
    r.onerror = () => status('Could not read ' + file.name + '.', true);
    r.readAsText(file);
  }
  function openPaste() {
    openModal('Paste a unified diff', '<div class="field"><label for="paste-text">Diff or patch</label><textarea id="paste-text" rows="14" spellcheck="false" placeholder="diff --git a/app.js b/app.js\n--- a/app.js\n+++ b/app.js\n@@ -1,3 +1,4 @@\n …"></textarea><div class="help">Output of <code>git diff</code>, <code>git format-patch</code>, or a GitHub <code>.diff</code> page. Nothing is uploaded.</div><div id="paste-err" class="err" role="alert"></div></div>', {
      dirty: true, save: () => { const t = $('#paste-text').value; if (!t.trim()) { $('#paste-err').textContent = 'Paste a diff first, or press Cancel.'; return; } if (!D.parse(t).files.length) { $('#paste-err').textContent = 'No diff found in that text. It needs ---/+++ file headers and @@ hunks.'; return; } modal.dirty = false; closeModal(true); setTimeout(() => loadDiffText(t), 0); }, saveLabel: 'Review diff', focusFirst: true
    });
  }

  /* ---------------- rendering ---------------- */
  function cweLink(c) { if (!c) return ''; const n = c.replace(/^CWE-/, ''); return '<a href="https://cwe.mitre.org/data/definitions/' + esc(n) + '.html" target="_blank" rel="noopener">' + esc(c) + '</a>'; }
  function codeLines(rows, hitNo) { return rows.map((r) => '<div class="ln ' + (r.type === 'add' ? 'add' : r.type === 'del' ? 'del' : '') + (r.no === hitNo ? ' hit' : '') + '"><span>' + (r.no == null ? '' : r.no) + '</span><code>' + (r.type === 'add' ? '+' : r.type === 'del' ? '-' : ' ') + esc(r.text) + '</code></div>').join(''); }
  function filtered() {
    return findings.filter((f) => {
      const s = statusOf(f);
      if (ui.status === 'active' && (s === 'dismissed' || s === 'false-positive')) return false;
      if (ui.status !== 'active' && ui.status !== 'all' && s !== ui.status) return false;
      if (ui.sev !== 'all' && f.severity !== ui.sev) return false;
      if (ui.cat !== 'all' && f.category !== ui.cat) return false;
      if (ui.file !== 'all' && f.file !== ui.file) return false;
      return true;
    });
  }
  function findingCard(f) {
    const s = statusOf(f); const t = state.triage[f.id] || {};
    const sn = f.snippet;
    const rows = sn ? sn.before.map((r) => ({ no: r.no, type: r.type, text: r.text })).concat([{ no: sn.line.no, type: 'add', text: sn.line.text }], sn.after.map((r) => ({ no: r.no, type: r.type, text: r.text }))) : [];
    let fix = '';
    if (f.fix && f.fix.replacement != null && sn) {
      const repl = f.fix.replacement === '' ? [] : f.fix.replacement.split('\n');
      fix = '<div class="fix-label">Suggested fix</div><div class="code">' + codeLines([{ no: f.line, type: 'del', text: sn.line.text }].concat(repl.map((x) => ({ no: null, type: 'add', text: x }))), -1) + (repl.length ? '' : '<div class="ln"><span></span><code class="muted"> (delete the line)</code></div>') + '</div>';
    }
    const sources = (f.sources || [f.source]).map((x) => (x === 'llm' ? (state.llm && state.llm.simulated ? 'AI sample' : 'AI') : 'rules')).join(' + ');
    return '<article class="finding sev-' + f.severity + ' st-' + s + '" data-id="' + esc(f.id) + '">' +
      '<div class="f-top"><span class="sev">' + esc(f.severity) + '</span><span class="f-title">' + esc(f.title) + '</span>' + (s !== 'open' ? '<span class="st-badge ' + s + '">' + esc(s.replace('-', ' ')) + (t.reason ? ': ' + esc(t.reason) : '') + '</span>' : '') + '</div>' +
      '<div class="f-meta"><span class="pill">' + esc(f.category) + '</span>' + (f.cwe ? cweLink(f.cwe) + ' ·' : '') + (f.line ? '<button type="button" class="linkish" data-act="goto" data-file="' + esc(f.file) + '" data-line="' + f.line + '">' + esc(f.file) + ':' + f.line + '</button>' : '<span class="mono">' + esc(f.file) + '</span> · PR level') + ' · confidence ' + Math.round(f.confidence * 100) + '% · ' + esc(sources) + ' · <span class="mono">' + esc(f.ruleId) + '</span></div>' +
      '<p class="f-exp">' + esc(f.explanation) + '</p>' + (f.llmNote ? '<p class="f-note"><b>AI reviewer:</b> ' + esc(f.llmNote) + '</p>' : '') +
      (rows.length ? '<div class="code" aria-label="Code context">' + codeLines(rows, f.line) + '</div>' : '') + fix + (f.fix && f.fix.note ? '<p class="f-note">' + esc(f.fix.note) + '</p>' : '') + (t.note ? '<p class="f-note"><b>Triage note:</b> ' + esc(t.note) + '</p>' : '') +
      '<div class="f-actions">' + (s === 'open' ? '<button type="button" data-act="accept">✓ Accept</button><button type="button" data-act="dismiss">Dismiss…</button><button type="button" data-act="fp">False positive</button>' : '<button type="button" data-act="reopen">↺ Reopen</button>') + '</div></article>';
  }
  function diffView() {
    const byLine = new Map(); for (const f of findings) { if (f.line == null) continue; const k = f.file + '\u0000' + f.line; if (!byLine.has(k)) byLine.set(k, []); byLine.get(k).push(f); }
    const notes = (path, no, span) => { const list = (byLine.get(path + '\u0000' + no) || []).filter((f) => statusOf(f) !== 'dismissed' && statusOf(f) !== 'false-positive'); return list.length ? '<tr class="note"><td colspan="' + span + '">' + list.map((f) => '<div class="inline-f sev-' + f.severity + '"><b>' + esc(f.severity) + '</b>' + esc(f.title) + (f.cwe ? ' · ' + esc(f.cwe) : '') + ' <button type="button" class="linkish" data-act="show" data-id="' + esc(f.id) + '">details</button></div>').join('') + '</td></tr>' : ''; };
    const list = files.filter((f) => ui.file === 'all' || f.path === ui.file);
    return list.map((f, fi) => {
      const count = findings.filter((x) => x.file === f.path && statusOf(x) !== 'dismissed' && statusOf(x) !== 'false-positive').length;
      const head = '<summary><span class="pill">' + esc(f.status) + '</span><span class="path">' + (f.oldPath && f.oldPath !== f.path ? esc(f.oldPath) + ' → ' : '') + esc(f.path) + '</span><span class="fc"><span class="plus">+' + f.additions + '</span> <span class="minus">−' + f.deletions + '</span>' + (count ? ' · ' + count + ' finding' + (count > 1 ? 's' : '') : '') + '</span></summary>';
      if (f.binary) return '<details class="file" open>' + head + '<div class="binary">Binary file, not reviewed.</div></details>';
      if (!f.hunks.length) return '<details class="file" open>' + head + '<div class="binary">No content changes' + (f.status === 'renamed' ? ' (pure rename)' : f.newMode ? ' (mode ' + esc(f.oldMode || '') + ' → ' + esc(f.newMode) + ')' : '') + '.</div></details>';
      const id = (no) => 'L' + fi + '-' + no;
      let rows = '';
      for (const h of f.hunks) {
        if (ui.diffMode === 'split') {
          rows += '<tr class="hunk"><td colspan="4">@@ -' + h.oldStart + ',' + h.oldLines + ' +' + h.newStart + ',' + h.newLines + ' @@ ' + esc(h.header) + '</td></tr>';
          for (const r of D.sideBySide(h)) {
            const L = r.left; const Rr = r.right; const same = L && Rr && L === Rr;
            rows += '<tr' + (Rr && Rr.newNo != null ? ' id="' + id(Rr.newNo) + '" data-line="' + Rr.newNo + '"' : '') + '><td class="n">' + (L && L.oldNo != null ? L.oldNo : '') + '</td><td class="c ' + (L ? (same ? '' : 'del') : 'empty') + '">' + (L ? esc((same ? ' ' : '-') + L.text) : '') + '</td><td class="n">' + (Rr && Rr.newNo != null ? Rr.newNo : '') + '</td><td class="c ' + (Rr ? (same ? '' : 'add') : 'empty') + '">' + (Rr ? esc((same ? ' ' : '+') + Rr.text) : '') + '</td></tr>';
            if (Rr && Rr.type === 'add') rows += notes(f.path, Rr.newNo, 4);
          }
        } else {
          rows += '<tr class="hunk"><td colspan="3">@@ -' + h.oldStart + ',' + h.oldLines + ' +' + h.newStart + ',' + h.newLines + ' @@ ' + esc(h.header) + '</td></tr>';
          for (const l of h.lines) {
            rows += '<tr class="' + (l.type === 'ctx' ? '' : l.type) + '"' + (l.newNo != null ? ' id="' + id(l.newNo) + '" data-line="' + l.newNo + '"' : '') + '><td class="n">' + (l.oldNo != null ? l.oldNo : '') + '</td><td class="n">' + (l.newNo != null ? l.newNo : '') + '</td><td class="c">' + esc((l.type === 'add' ? '+' : l.type === 'del' ? '-' : ' ') + l.text) + (l.noNewline ? ' <span class="muted">⏎̸ no newline at end of file</span>' : '') + '</td></tr>';
            if (l.type === 'add') rows += notes(f.path, l.newNo, 3);
          }
        }
      }
      return '<details class="file" open data-path="' + esc(f.path) + '" data-fi="' + fi + '">' + head + '<div class="dv"><table>' + rows + '</table></div></details>';
    }).join('') || '<div class="empty">No files match this filter.</div>';
  }
  function render() {
    const ws = $('#workspace');
    $$('.demo').forEach((b) => b.classList.toggle('active', !!state && state.demoId === b.dataset.demo));
    if (!state) { ws.innerHTML = '<div class="empty-state"><svg viewBox="0 0 64 64" width="56" height="56" aria-hidden="true"><path d="M32 4 8 13v17c0 15 10 26 24 30 14-4 24-15 24-30V13z" fill="none" stroke="currentColor" stroke-width="2.5"/><path d="m21 33 8 8 15-17" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/></svg><h3>No pull request loaded</h3><p>Pick a demo to see the full flow: findings anchored to exact lines, triage, a merge recommendation, and exports for GitHub (review Markdown, REST payload, SARIF).</p></div>'; return; }
    const pr = state.pr; const st = D.stats(files); const s = V.summarize(findings, state.triage, opts());
    const scColor = s.event === 'APPROVE' ? 'var(--ok)' : s.event === 'COMMENT' ? 'var(--med)' : 'var(--high)';
    const demo = state.demoId && demos.find((d) => d.id === state.demoId);
    const src = { demo: 'Demo PR (fictional)', github: 'GitHub', paste: 'Pasted diff', file: 'Patch file' }[state.source] || state.source;
    const aiLabel = state.llm ? (state.llm.simulated ? 'Simulated AI sample merged (no model was called)' : 'AI review merged: ' + esc(state.llm.providerLabel) + ' · ' + esc(state.llm.model) + ' · ' + state.llm.chunks + ' chunk(s)' + (state.llm.cost != null ? ' · ~$' + state.llm.cost.toFixed(4) : '')) : '';
    const fileOpts = ['<option value="all">All files (' + files.length + ')</option>'].concat(files.map((f) => '<option value="' + esc(f.path) + '"' + (ui.file === f.path ? ' selected' : '') + '>' + esc(f.path) + '</option>')).join('');
    const list = filtered();
    const un = (state.llm && state.llm.unanchored) || [];
    ws.innerHTML =
      '<div class="pr-head"><div style="min-width:0"><h2 id="pr-title">' + esc(pr.title || 'Untitled change') + '</h2><div class="pr-meta"><span class="pill" id="src-pill">' + esc(src) + '</span>' + (pr.owner ? '<span class="mono">' + esc(pr.owner + '/' + pr.repo + (pr.number ? '#' + pr.number : '')) + '</span>' : '') + (pr.author ? '<span>by ' + esc(pr.author) + '</span>' : '') + '<span id="stats">' + st.files + ' file' + (st.files === 1 ? '' : 's') + ' · <span class="plus">+' + st.additions + '</span> <span class="minus">−' + st.deletions + '</span>' + (st.binary ? ' · ' + st.binary + ' binary' : '') + '</span>' + (state.source === 'github' && pr.url ? '<a href="' + esc(pr.url) + '" target="_blank" rel="noopener">open on GitHub ↗</a>' : '') + '</div>' + (pr.body && state.source !== 'github' ? '<p class="muted small" style="margin:6px 0 0">' + esc(pr.body) + '</p>' : '') + '</div><div class="pr-tools"><button type="button" id="btn-clear" class="danger">Clear review</button></div></div>' +
      (s.injection ? '<div class="banner" id="inj-banner" role="alert"><b>⚠ Prompt-injection attempt detected.</b> Added text in this PR tries to instruct AI reviewers. PRSentry treats the diff as data and never follows it, but have a human confirm the verdict.</div>' : '') +
      '<div class="summary"><div class="score" style="--v:' + s.score + ';--sc:' + scColor + '" aria-label="Score ' + s.score + ' out of 100"><div><b id="score">' + s.score + '</b><small>grade ' + s.grade + '</small></div></div>' +
      '<div><p class="verdict ' + s.event + '" id="verdict">' + esc(s.label) + '</p><ul class="reasons" id="reasons">' + s.reasons.map((r) => '<li>' + esc(r) + '</li>').join('') + '</ul></div>' +
      '<div class="ai-col"><div class="counts" id="counts">' + SEV.map((k) => '<div class="count ' + k + '"><b>' + s.counts[k] + '</b><span>' + k + '</span></div>').join('') + '</div><div class="ai-box" id="ai-box">' + (aiLabel ? '<b>' + aiLabel + '</b>' + (un.length ? ' · ' + un.length + ' unanchored dropped' : '') : '<b>Rules only.</b> ' + (keyReady() ? 'Your ' + esc(LLM.PROVIDERS[settings.provider].label) + ' key is set.' : 'Add your own AI key in Settings for a second pass.')) + '<div class="row">' + '<button type="button" id="btn-ai" class="primary"' + (keyReady() ? '' : ' disabled') + '>✦ Run AI review</button>' + (demo && demo.sampleLlm ? '<button type="button" id="btn-sample">▶ Play sample AI review</button>' : '') + (state.llm ? '<button type="button" id="btn-ai-clear">Remove AI findings</button>' : '') + (keyReady() ? '' : '<button type="button" id="btn-ai-settings">Add key…</button>') + '</div></div></div></div>' +
      '<div class="toolbar" role="toolbar" aria-label="Filters"><div class="seg" role="group" aria-label="View"><button type="button" data-view="findings" aria-pressed="' + (ui.view === 'findings') + '">Findings (' + list.length + ')</button><button type="button" data-view="diff" aria-pressed="' + (ui.view === 'diff') + '">Diff</button></div>' +
      '<label class="sr-only" for="f-sev">Severity</label><select id="f-sev"><option value="all">All severities</option>' + SEV.map((k) => '<option' + (ui.sev === k ? ' selected' : '') + '>' + k + '</option>').join('') + '</select>' +
      '<label class="sr-only" for="f-cat">Category</label><select id="f-cat"><option value="all">All categories</option>' + CAT.map((k) => '<option' + (ui.cat === k ? ' selected' : '') + '>' + k + '</option>').join('') + '</select>' +
      '<label class="sr-only" for="f-file">File</label><select id="f-file">' + fileOpts + '</select>' +
      '<label class="sr-only" for="f-status">Status</label><select id="f-status">' + [['active', 'Open + accepted'], ['open', 'Open'], ['accepted', 'Accepted'], ['dismissed', 'Dismissed'], ['false-positive', 'False positive'], ['all', 'Everything']].map(([v, l]) => '<option value="' + v + '"' + (ui.status === v ? ' selected' : '') + '>' + l + '</option>').join('') + '</select>' +
      (ui.view === 'diff' ? '<span class="spacer"></span><div class="seg" role="group" aria-label="Diff layout"><button type="button" data-mode="unified" aria-pressed="' + (ui.diffMode === 'unified') + '">Unified</button><button type="button" data-mode="split" aria-pressed="' + (ui.diffMode === 'split') + '">Side by side</button></div>' : '') + '</div>' +
      '<div class="body" id="view">' + (ui.view === 'findings' ? (list.length ? list.map(findingCard).join('') : '<div class="empty" id="no-findings">' + (findings.length ? 'No findings match these filters.' : '✓ No findings from the enabled checks. That is not proof the change is safe; a human should still review it.') + '</div>') : diffView()) + '</div>' +
      (un.length ? '<details class="unanchored" id="unanchored"><summary>' + un.length + ' AI finding' + (un.length > 1 ? 's' : '') + ' not tied to a changed line (left out of the review)</summary><ul>' + un.map((f) => '<li><span class="mono">' + esc(f.file) + (f.line ? ':' + f.line : '') + '</span> — ' + esc(f.title) + ' <span class="muted">(' + esc(f.unanchoredReason) + ')</span></li>').join('') + '</ul></details>' : '') +
      '<div class="exports"><h3>Export</h3><button type="button" id="ex-md">Review Markdown</button><button type="button" id="ex-payload">GitHub API payload</button><button type="button" id="ex-sarif">↓ SARIF 2.1.0</button><button type="button" id="ex-json">↓ JSON</button></div>';
    bindWorkspace();
  }
  function keyReady() { const p = LLM.PROVIDERS[settings.provider]; return !!p && (!p.needsKey || !!keys.llm) && (settings.provider !== 'compatible' || !!(settings.baseUrl || p.baseUrl)); }
  function bindWorkspace() {
    $('#btn-clear').onclick = () => { const old = state; state = null; derive(); saveState(); render(); toast('Review cleared.', () => { state = old; derive(); saveState(); render(); }); };
    $$('[data-view]').forEach((b) => (b.onclick = () => { ui.view = b.dataset.view; render(); }));
    $$('[data-mode]').forEach((b) => (b.onclick = () => { ui.diffMode = b.dataset.mode; render(); }));
    $('#f-sev').onchange = (e) => { ui.sev = e.target.value; render(); };
    $('#f-cat').onchange = (e) => { ui.cat = e.target.value; render(); };
    $('#f-file').onchange = (e) => { ui.file = e.target.value; render(); };
    $('#f-status').onchange = (e) => { ui.status = e.target.value; render(); };
    $('#btn-ai').onclick = confirmAi;
    if ($('#btn-sample')) $('#btn-sample').onclick = playSample;
    if ($('#btn-ai-clear')) $('#btn-ai-clear').onclick = () => { const old = state.llm; state.llm = null; derive(); saveState(); render(); toast('AI findings removed.', () => { state.llm = old; derive(); saveState(); render(); }); };
    if ($('#btn-ai-settings')) $('#btn-ai-settings').onclick = openSettings;
    $('#ex-md').onclick = openMarkdown; $('#ex-payload').onclick = openPayload; $('#ex-sarif').onclick = downloadSarif; $('#ex-json').onclick = downloadJson;
    $('#view').onclick = (e) => {
      const b = e.target.closest('[data-act]'); if (!b) return;
      const act = b.dataset.act;
      if (act === 'goto') { gotoLine(b.dataset.file, +b.dataset.line); return; }
      if (act === 'show') { const f = findings.find((x) => x.id === b.dataset.id); if (f) { ui.view = 'findings'; ui.status = 'all'; render(); const el = $('.finding[data-id="' + CSS.escape(f.id) + '"]'); if (el) { el.scrollIntoView({ block: 'center' }); el.focus && el.setAttribute('tabindex', '-1'); el.focus(); } } return; }
      const card = b.closest('.finding'); const f = findings.find((x) => x.id === card.dataset.id); if (!f) return;
      if (act === 'accept') triage(f, { status: 'accepted' }, 'Accepted: ' + f.title);
      if (act === 'fp') triage(f, { status: 'false-positive' }, 'Marked false positive: ' + f.title);
      if (act === 'reopen') triage(f, null, 'Reopened: ' + f.title);
      if (act === 'dismiss') openDismiss(f);
    };
  }
  function triage(f, value, msg) {
    const before = state.triage[f.id] ? Object.assign({}, state.triage[f.id]) : null;
    if (value) state.triage[f.id] = Object.assign({ at: new Date().toISOString() }, value); else delete state.triage[f.id];
    saveState(); render();
    toast(msg, () => { if (before) state.triage[f.id] = before; else delete state.triage[f.id]; saveState(); render(); });
  }
  function openDismiss(f) {
    const reasons = ['Not exploitable here', 'Intended behaviour', 'Fixed elsewhere / follow-up issue', 'Test or example code', 'Other'];
    openModal('Dismiss finding', '<p class="muted small" style="margin-top:0">' + esc(f.title) + ' · <span class="mono">' + esc(f.file) + (f.line ? ':' + f.line : '') + '</span></p><div class="field"><span class="lbl" id="reason-lbl">Reason (required)</span><div role="radiogroup" aria-labelledby="reason-lbl">' + reasons.map((r, i) => '<label style="display:flex;gap:8px;align-items:center;font-weight:400;margin:4px 0"><input type="radio" name="reason" value="' + esc(r) + '" style="width:auto"> ' + esc(r) + '</label>').join('') + '</div></div><div class="field"><label for="dismiss-note">Note (optional)</label><textarea id="dismiss-note" rows="3" style="font-family:inherit" placeholder="Why is this safe to ignore?"></textarea></div><div id="dismiss-err" class="err" role="alert"></div>', {
      dirty: true, saveLabel: 'Dismiss', save: () => {
        const r = $('input[name=reason]:checked'); if (!r) { $('#dismiss-err').textContent = 'Pick a reason, or press Cancel to keep the finding open.'; return; }
        const note = $('#dismiss-note').value.trim(); modal.dirty = false; closeModal(true);
        setTimeout(() => triage(f, { status: 'dismissed', reason: r.value, note }, 'Dismissed: ' + f.title), 0);
      }
    });
  }
  function gotoLine(file, line) {
    ui.view = 'diff'; if (ui.file !== 'all' && ui.file !== file) ui.file = 'all'; render();
    const det = $('details.file[data-path="' + CSS.escape(file) + '"]'); if (!det) return;
    det.open = true; const row = det.querySelector('tr[data-line="' + line + '"]');
    if (row) { row.scrollIntoView({ block: 'center' }); row.classList.remove('flash'); void row.offsetWidth; row.classList.add('flash'); }
  }

  /* ---------------- AI review ---------------- */
  function cfg() { const p = LLM.PROVIDERS[settings.provider]; return { provider: settings.provider, key: keys.llm, model: settings.model || p.defaultModel, baseUrl: settings.baseUrl || undefined }; }
  function confirmAi() {
    if (!state || !keyReady()) return;
    const chunks = V.chunkDiff(files, 12000); const use = chunks.slice(0, settings.maxChunks || 6);
    const chars = use.reduce((a, c) => a + c.length, 0); const c = cfg(); const p = LLM.PROVIDERS[c.provider];
    let host = ''; try { host = new URL(c.baseUrl || p.baseUrl).host; } catch (e) { host = c.baseUrl || ''; }
    openModal('Send the diff for AI review?', '<div class="note-box">This sends <b>' + use.length + ' chunk' + (use.length === 1 ? '' : 's') + '</b> (~' + Math.round(chars / 1000) + 'k characters of code) to <b>' + esc(p.label) + '</b> at <span class="mono">' + esc(host) + '</span> using model <span class="mono">' + esc(c.model) + '</span>, directly from your browser with your key.' + (chunks.length > use.length ? ' The diff has ' + chunks.length + ' chunks; only the first ' + use.length + ' are sent (change the limit in Settings).' : '') + '</div><p class="small muted">The diff is fenced as untrusted data with a random marker, and the model is told never to follow instructions inside it. Findings must point at an added line or they are dropped as unanchored. Rule findings stay as they are; AI findings are merged and de-duplicated.</p>', { save: () => { closeModal(true); setTimeout(() => runAi(use), 0); }, saveLabel: 'Send to ' + p.label });
  }
  async function runAi(chunks) {
    if (ui.busy) return; ui.busy = true;
    const c = cfg(); const p = LLM.PROVIDERS[c.provider]; const raw = []; let cost = 0; let costKnown = true; const errors = []; const warnings = [];
    try {
      for (let i = 0; i < chunks.length; i++) {
        status('AI review: chunk ' + (i + 1) + ' of ' + chunks.length + ' → ' + p.label + '…');
        try {
          const out = await LLM.call(c, V.buildMessages(chunks[i], state.pr), { timeoutMs: 90000 });
          const parsed = V.parseLLM(out.text);
          if (parsed.error) errors.push('Chunk ' + (i + 1) + ': ' + parsed.error);
          warnings.push(...V.llmOutputWarnings(parsed, out.text));
          raw.push(...parsed.findings);
          if (out.cost == null) costKnown = false; else cost += out.cost;
        } catch (e) { errors.push('Chunk ' + (i + 1) + ': ' + (e.message || e)); if (i === 0 && /key|rejected|401|403|CORS|reach|Network/i.test(String(e.message))) break; }
      }
      if (!raw.length && errors.length) { status('AI review failed. ' + errors[0], true); return; }
      const a = V.anchor(raw, files);
      state.llm = { anchored: a.anchored, unanchored: a.unanchored, provider: c.provider, providerLabel: p.label, model: c.model, chunks: chunks.length, cost: costKnown ? cost : null, at: new Date().toISOString(), simulated: false, warnings };
      derive(); saveState(); render();
      status('AI review done: ' + a.anchored.length + ' finding(s) anchored to changed lines' + (a.unanchored.length ? ', ' + a.unanchored.length + ' unanchored dropped' : '') + '.' + (errors.length ? ' ' + errors.length + ' chunk(s) had errors: ' + errors[0] : '') + (warnings.length ? ' Warning: ' + warnings[0] : ''), !!errors.length);
    } finally { ui.busy = false; }
  }
  function playSample() {
    const d = state && demos.find((x) => x.id === state.demoId); if (!d || !d.sampleLlm) return;
    const parsed = V.parseLLM(d.sampleLlm); const a = V.anchor(parsed.findings, files);
    const old = state.llm;
    state.llm = { anchored: a.anchored, unanchored: a.unanchored, provider: 'sample', providerLabel: 'Sample', model: 'recorded sample', chunks: 1, cost: null, at: new Date().toISOString(), simulated: true, warnings: [] };
    derive(); saveState(); render();
    toast('Sample AI reply merged: ' + a.anchored.length + ' anchored, ' + a.unanchored.length + ' unanchored. No model was called.', () => { state.llm = old; derive(); saveState(); render(); });
  }

  /* ---------------- exports ---------------- */
  function download(name, text, type) { const b = new Blob([text], { type: type || 'application/json' }); const a = document.createElement('a'); a.href = URL.createObjectURL(b); a.download = name; document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500); }
  async function copy(text, label) { try { await navigator.clipboard.writeText(text); toast((label || 'Text') + ' copied.'); } catch (e) { const ta = document.createElement('textarea'); ta.value = text; document.body.appendChild(ta); ta.select(); let ok = false; try { ok = document.execCommand('copy'); } catch (er) { ok = false; } ta.remove(); toast(ok ? (label || 'Text') + ' copied.' : 'Copy blocked by the browser. Select the text and copy it manually.'); } }
  function baseName() { const p = state.pr; return 'prsentry-' + (p.repo ? p.repo + '-' + (p.number || 'diff') : state.demoId || 'diff'); }
  function openMarkdown() {
    const md = V.reviewMarkdown(state.pr, findings, state.triage, opts());
    openModal('GitHub review Markdown', '<p class="small muted" style="margin-top:0">Summary plus inline comments with <code>```suggestion</code> blocks. Paste into a PR comment, or use the API payload to post it as a real review.</p><pre class="out" id="md-out">' + esc(md) + '</pre>', { wide: true, extraFooter: '<button type="button" id="md-copy">Copy Markdown</button><button type="button" id="md-dl">↓ Download .md</button>', onmount: () => { $('#md-copy').onclick = () => copy(md, 'Markdown'); $('#md-dl').onclick = () => download(baseName() + '-review.md', md, 'text/markdown'); } });
  }
  function openPayload() {
    const payload = V.reviewPayload(state.pr, findings, state.triage, opts());
    const ex = V.apiExamples(state.pr, payload);
    openModal('GitHub REST payload', '<div class="note-box"><b>This page never posts to GitHub.</b> To publish the review yourself, send this body to <span class="mono">' + esc(ex.method + ' ' + ex.path) + '</span> with a token that can write pull requests (or use the bundled GitHub Action).' + (state.pr.headSha ? '' : ' <br>No head commit SHA is known for this diff, so <code>commit_id</code> is omitted (GitHub then uses the latest commit).') + (state.pr.owner && state.source === 'github' ? '' : ' <br>Replace OWNER/REPO/PR_NUMBER with your pull request.') + '</div>' +
      '<div class="copyrow"><h3>Request body (review.json)</h3><button type="button" data-copy="json">Copy JSON</button></div><pre class="out" id="payload-json">' + esc(ex.json) + '</pre>' +
      '<div class="copyrow"><h3>gh CLI</h3><button type="button" data-copy="gh">Copy</button></div><pre class="out" id="payload-gh">' + esc(ex.gh) + '</pre>' +
      '<div class="copyrow"><h3>curl</h3><button type="button" data-copy="curl">Copy</button></div><pre class="out" id="payload-curl">' + esc(ex.curl) + '</pre>', { wide: true, extraFooter: '<button type="button" id="payload-dl">↓ Download review.json</button>', onmount: () => { $$('[data-copy]').forEach((b) => (b.onclick = () => copy(ex[b.dataset.copy], b.dataset.copy === 'json' ? 'Payload' : b.dataset.copy + ' command'))); $('#payload-dl').onclick = () => download('review.json', ex.json); } });
  }
  function downloadSarif() { const doc = V.sarif(state.pr, findings, state.triage, opts()); const errs = V.validateSarif(doc); if (errs.length) { toast('SARIF check failed: ' + errs[0]); return; } download(baseName() + '.sarif', JSON.stringify(doc, null, 2), 'application/sarif+json'); toast('SARIF 2.1.0 downloaded (' + doc.runs[0].results.length + ' results).'); }
  function downloadJson() { download(baseName() + '.json', JSON.stringify(V.jsonExport(state.pr, findings, state.triage, opts()), null, 2)); toast('JSON downloaded. Keys are never included.'); }

  /* ---------------- settings, rules, about ---------------- */
  function openSettings() {
    const provs = Object.keys(LLM.PROVIDERS);
    openModal('Settings', '<div class="note-box">Keys are stored only in this browser (localStorage) and sent only to the provider you pick. They are never put in exports, links or the demo data. AI review sends the diff to that provider.</div>' +
      '<div class="row2"><div class="field"><label for="s-provider">AI provider</label><select id="s-provider">' + provs.map((p) => '<option value="' + p + '"' + (p === settings.provider ? ' selected' : '') + '>' + esc(LLM.PROVIDERS[p].label) + '</option>').join('') + '</select></div><div class="field"><label for="s-model">Model</label><input id="s-model" list="s-models" value="' + esc(settings.model) + '" placeholder="' + esc(LLM.PROVIDERS[settings.provider].defaultModel) + '"><datalist id="s-models"></datalist></div></div>' +
      '<div class="presets" id="s-presets"></div>' +
      '<div class="field" id="s-base-wrap"><label for="s-base">Base URL</label><input id="s-base" type="url" value="' + esc(settings.baseUrl) + '" placeholder="https://openrouter.ai/api/v1"><div class="help">For Ollama, start it with <code>OLLAMA_ORIGINS=https://shaikbasha1437.github.io</code> so the browser may call it.</div></div>' +
      '<div class="field"><label for="s-key">AI API key</label><input id="s-key" type="password" autocomplete="off" spellcheck="false" value="' + esc(keys.llm) + '"><div class="help" id="s-key-help"></div></div>' +
      '<div class="field"><label for="s-gh">GitHub token (optional)</label><input id="s-gh" type="password" autocomplete="off" spellcheck="false" value="' + esc(keys.github) + '" placeholder="fine-grained, read-only Pull requests + Contents"><div class="help">Only for private repos or a higher rate limit. Sent only to api.github.com, read-only requests.</div></div>' +
      '<div class="row2"><div class="field"><label for="s-chunks">Max AI requests per review</label><input id="s-chunks" type="number" min="1" max="20" value="' + esc(settings.maxChunks) + '"></div><div class="field"><span class="lbl">Storage</span><label style="display:flex;gap:8px;align-items:center;font-weight:400"><input id="s-remember" type="checkbox" style="width:auto"' + (settings.remember ? ' checked' : '') + '> Remember keys on this device</label></div></div>' +
      '<div class="row"><button type="button" id="s-test">Test AI connection</button> <button type="button" id="s-forget" class="danger">Forget keys</button></div><p id="s-test-out" class="small" role="status"></p>', {
      dirty: true, wide: false, save: () => {
        settings.provider = $('#s-provider').value; settings.model = $('#s-model').value.trim(); settings.baseUrl = $('#s-base').value.trim(); settings.maxChunks = Math.max(1, Math.min(20, parseInt($('#s-chunks').value, 10) || 6)); settings.remember = $('#s-remember').checked;
        keys.llm = $('#s-key').value.trim(); keys.github = $('#s-gh').value.trim();
        saveSettings(); modal.dirty = false; closeModal(true); setTimeout(() => { render(); toast('Settings saved.'); }, 0);
      }, onmount: () => {
        const sync = () => {
          const p = LLM.PROVIDERS[$('#s-provider').value];
          $('#s-models').innerHTML = p.models.map((m) => '<option value="' + esc(m) + '">').join(''); $('#s-model').placeholder = p.defaultModel;
          $('#s-base-wrap').hidden = $('#s-provider').value !== 'compatible';
          $('#s-presets').innerHTML = $('#s-provider').value === 'compatible' ? LLM.PRESETS.map((x) => '<button type="button" data-preset="' + x.id + '">' + esc(x.label) + '</button>').join('') : '';
          $$('[data-preset]').forEach((b) => (b.onclick = () => { const x = LLM.PRESETS.find((y) => y.id === b.dataset.preset); $('#s-base').value = x.baseUrl; $('#s-model').value = x.model; modal.dirty = true; }));
          $('#s-key-help').innerHTML = (p.needsKey ? 'Required. ' : 'Optional for local servers. ') + (p.keyUrl ? '<a href="' + p.keyUrl + '" target="_blank" rel="noopener">Get a key ↗</a>' : '') + (p.pricingUrl ? ' · <a href="' + p.pricingUrl + '" target="_blank" rel="noopener">pricing ↗</a>' : '') + ($('#s-provider').value === 'openai' ? ' · OpenAI\u2019s invalid-key reply has no CORS header, so a wrong key shows up as a network error.' : '');
        };
        $('#s-provider').onchange = sync; sync();
        $('#s-forget').onclick = () => { const old = Object.assign({}, keys); keys = { llm: '', github: '' }; store.del(LS.keys); $('#s-key').value = ''; $('#s-gh').value = ''; render(); toast('Keys forgotten on this device.', () => { keys = old; saveSettings(); render(); }); };
        $('#s-test').onclick = async () => {
          const c = { provider: $('#s-provider').value, key: $('#s-key').value.trim(), model: $('#s-model').value.trim() || LLM.PROVIDERS[$('#s-provider').value].defaultModel, baseUrl: $('#s-base').value.trim() || undefined };
          $('#s-test-out').textContent = 'Testing…';
          try { const out = await LLM.call(c, { system: 'Reply with the JSON {"ok":true} only.', messages: [{ role: 'user', content: 'ping' }], maxTokens: 20, temperature: 0 }, { timeoutMs: 30000 }); $('#s-test-out').textContent = '✓ Connected to ' + LLM.PROVIDERS[c.provider].label + ' (' + (out.model || c.model) + ', ' + out.latencyMs + ' ms).'; }
          catch (e) { $('#s-test-out').textContent = '✗ ' + (e.message || e); }
        };
      }
    });
  }
  function openRules() {
    const cat = R.ruleCatalog(); const dis = new Set(settings.disabled);
    openModal('Rule catalog (' + cat.length + ' checks)', '<p class="small muted" style="margin-top:0">Rules run only on added lines. Turn off checks that are noisy for your codebase; this is saved in this browser.</p><table class="rules-table"><thead><tr><th><span class="sr-only">On</span></th><th>Rule</th><th>Default</th></tr></thead><tbody>' + cat.map((r) => '<tr><td><input type="checkbox" aria-label="Enable ' + esc(r.id) + '" data-rule="' + esc(r.id) + '"' + (dis.has(r.id) ? '' : ' checked') + '></td><td><b>' + esc(r.title) + '</b><br><span class="mono muted">' + esc(r.id) + '</span>' + (r.cwe ? ' · ' + cweLink(r.cwe) : '') + '<br><span class="small muted">' + esc(r.explain) + '</span></td><td><span class="pill">' + esc(r.severity) + '</span><br><span class="small muted">' + esc(r.category) + '</span></td></tr>').join('') + '</tbody></table>', {
      wide: true, dirty: true, save: () => { settings.disabled = $$('[data-rule]').filter((x) => !x.checked).map((x) => x.dataset.rule); saveSettings(); modal.dirty = false; closeModal(true); setTimeout(() => { derive(); render(); toast(settings.disabled.length ? settings.disabled.length + ' rule(s) turned off.' : 'All rules on.'); }, 0); }
    });
  }
  function openAbout() {
    openModal('How PRSentry works · honest limits', '<ol class="small"><li><b>Parse</b> the unified diff (renames, binary files, “no newline” markers) into exact old/new line numbers.</li><li><b>Rules</b>: ' + R.ruleCatalog().length + ' deterministic checks run on <i>added</i> lines only — secrets, SQL/command injection, eval, unsafe deserialization, XSS sinks, path traversal, SSRF, weak crypto, TLS/CORS/JWT misconfig, floating promises, loose equality, off-by-one loops, swallowed errors, debug leftovers, TODOs, dependency changes, missing tests, and text aimed at AI reviewers.</li><li><b>AI pass (optional)</b>: with your key, the diff is sent in chunks inside a nonce-tagged fence. The model is told it is data, not instructions. Every AI finding must point to an added line or it is dropped as unanchored, then it is merged with rule findings and de-duplicated.</li><li><b>Triage</b> and export: review Markdown with suggestion blocks, the exact GitHub REST payload, SARIF 2.1.0 and JSON.</li></ol><div class="note-box"><b>Limits.</b> Pattern rules have false positives and false negatives: they see one line at a time, do no data-flow analysis and cannot know your framework\u2019s protections. PRSentry is not a replacement for a SAST tool (CodeQL, Semgrep) or a human reviewer. AI review sends code to the provider you choose and can be wrong or manipulated. Demo PRs are fictional; secret-looking values in them are fake. This page never posts to GitHub; the bundled GitHub Action can, with your workflow\u2019s token.</div>');
  }
  function toggleTheme() { const dark = !document.documentElement.classList.contains('dark'); document.documentElement.classList.toggle('dark', dark); try { localStorage.setItem(LS.theme, dark ? 'dark' : 'light'); } catch (e) { /* ignore */ } }

  /* ---------------- boot ---------------- */
  function renderDemos() {
    $('#demos').innerHTML = demos.map((d) => '<button type="button" class="demo" data-demo="' + esc(d.id) + '"><strong>' + esc(d.title) + '</strong><span>#' + d.number + ' · ' + esc(d.author) + ' · ' + esc(demoTag(d.id)) + '</span></button>').join('');
    $$('.demo').forEach((b) => (b.onclick = () => loadDemo(b.dataset.demo)));
  }
  function demoTag(id) { return { 'clean-refactor': 'clean refactor', 'sql-injection': 'SQL injection', 'leaked-secret': 'leaked secret', 'react-xss': 'React XSS', 'async-bug': 'async bugs', 'prompt-injection': 'prompt injection' }[id] || id; }
  async function boot() {
    $('#btn-theme').onclick = toggleTheme; $('#btn-settings').onclick = openSettings; $('#btn-rules').onclick = openRules; $('#btn-about').onclick = openAbout;
    $('#pr-form').onsubmit = fetchPr; $('#btn-paste').onclick = openPaste;
    $('#patch-file').onchange = (e) => { readFile(e.target.files[0]); e.target.value = ''; };
    let depth = 0;
    addEventListener('dragenter', (e) => { if (e.dataTransfer && Array.from(e.dataTransfer.types || []).includes('Files')) { depth++; document.body.classList.add('dragging'); } });
    addEventListener('dragleave', () => { depth = Math.max(0, depth - 1); if (!depth) document.body.classList.remove('dragging'); });
    addEventListener('dragover', (e) => { if (e.dataTransfer && Array.from(e.dataTransfer.types || []).includes('Files')) e.preventDefault(); });
    addEventListener('drop', (e) => { if (!e.dataTransfer || !e.dataTransfer.files.length) return; e.preventDefault(); depth = 0; document.body.classList.remove('dragging'); readFile(e.dataTransfer.files[0]); });
    try { const r = await fetch('./samples/demo-prs.json'); if (!r.ok) throw new Error('HTTP ' + r.status); demos = (await r.json()).prs; renderDemos(); }
    catch (e) { $('#demos').innerHTML = '<p class="small err">Demo PRs could not be loaded (' + esc(e.message) + '). Go online once so they are cached for offline use.</p>'; }
    try { derive(); } catch (e) { state = null; derive(); }
    render();
    const m = /^#demo=([\w-]+)$/.exec(location.hash); if (m && demos.some((d) => d.id === m[1])) { history.replaceState(null, '', location.pathname + location.search); loadDemo(m[1]); }
  }
  window.PRSentryApp = { get state() { return state; }, get findings() { return findings; } };
  boot();
})();
