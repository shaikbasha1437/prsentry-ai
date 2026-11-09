/* PRSentry diff parser: unified diff / git patch / mbox .patch -> files, hunks and numbered lines.
   Handles renames, copies, new/deleted files, mode changes, binary files and "\ No newline at end of file". */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else (root.PRSentry = root.PRSentry || {}).diff = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';
  const HUNK = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@ ?(.*)$/;
  function stripPrefix(p) {
    if (p == null) return null;
    p = String(p).replace(/\t.*$/, '').trim();
    if (p.startsWith('"') && p.endsWith('"')) p = p.slice(1, -1).replace(/\\(.)/g, '$1');
    if (p === '/dev/null') return null;
    return p.replace(/^[ab]\//, '');
  }
  function newFile() {
    return { oldPath: null, newPath: null, path: null, status: 'modified', binary: false, hunks: [], additions: 0, deletions: 0, similarity: null, oldMode: null, newMode: null };
  }
  function finish(f, files) {
    if (!f) return;
    f.path = f.newPath || f.oldPath;
    if (!f.path) return;
    if (f.status === 'modified') {
      if (!f.oldPath && f.newPath) f.status = 'added';
      else if (f.oldPath && !f.newPath) f.status = 'deleted';
      else if (f.oldPath && f.newPath && f.oldPath !== f.newPath) f.status = 'renamed';
    }
    files.push(f);
  }
  /* parse(text) -> { files: [...], meta: { subject, from } } */
  function parse(text) {
    const src = String(text || '').replace(/\r\n?/g, '\n');
    const lines = src.split('\n');
    const files = [];
    const meta = { subject: '', from: '' };
    let f = null; let h = null; let oldNo = 0; let newNo = 0;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!f && !meta.subject && /^Subject: /.test(line)) meta.subject = line.replace(/^Subject: (\[PATCH[^\]]*\] )?/, '');
      if (!f && !meta.from && /^From: /.test(line)) meta.from = line.slice(6);
      if (line.startsWith('diff --git ')) {
        finish(f, files); f = newFile(); h = null;
        const m = /^diff --git (?:"?a\/(.+?)"?) (?:"?b\/(.+?)"?)$/.exec(line);
        if (m) { f.oldPath = m[1]; f.newPath = m[2]; }
        continue;
      }
      if (h) {
        if (line.startsWith('\\')) { const last = h.lines[h.lines.length - 1]; if (last) last.noNewline = true; continue; }
        if (h.remainingOld > 0 || h.remainingNew > 0) {
          const c = line[0];
          if (c === '+') { h.lines.push({ type: 'add', oldNo: null, newNo: newNo, text: line.slice(1) }); newNo++; h.remainingNew--; f.additions++; continue; }
          if (c === '-') { h.lines.push({ type: 'del', oldNo: oldNo, newNo: null, text: line.slice(1) }); oldNo++; h.remainingOld--; f.deletions++; continue; }
          if (c === ' ' || (line === '' && i < lines.length - 1)) { h.lines.push({ type: 'ctx', oldNo: oldNo, newNo: newNo, text: line.slice(1) }); oldNo++; newNo++; h.remainingOld--; h.remainingNew--; continue; }
        }
      }
      const hm = HUNK.exec(line);
      if (hm) {
        if (!f) { f = newFile(); }
        oldNo = +hm[1]; newNo = +hm[3];
        h = { oldStart: +hm[1], oldLines: hm[2] == null ? 1 : +hm[2], newStart: +hm[3], newLines: hm[4] == null ? 1 : +hm[4], header: hm[5] || '', lines: [] };
        h.remainingOld = h.oldLines; h.remainingNew = h.newLines;
        f.hunks.push(h);
        continue;
      }
      if (line.startsWith('--- ')) {
        if (!f || f.hunks.length) { finish(f, files); f = newFile(); }
        h = null;
        const p = stripPrefix(line.slice(4));
        f.oldPath = p; if (p === null) f.status = 'added';
        continue;
      }
      if (line.startsWith('+++ ') && f && !h) {
        const p = stripPrefix(line.slice(4));
        f.newPath = p; if (p === null) f.status = 'deleted';
        continue;
      }
      if (!f) continue;
      let m;
      if ((m = /^rename from (.+)$/.exec(line))) { f.oldPath = stripPrefix(m[1]); f.status = 'renamed'; continue; }
      if ((m = /^rename to (.+)$/.exec(line))) { f.newPath = stripPrefix(m[1]); f.status = 'renamed'; continue; }
      if ((m = /^copy from (.+)$/.exec(line))) { f.oldPath = stripPrefix(m[1]); f.status = 'copied'; continue; }
      if ((m = /^copy to (.+)$/.exec(line))) { f.newPath = stripPrefix(m[1]); f.status = 'copied'; continue; }
      if ((m = /^similarity index (\d+)%/.exec(line))) { f.similarity = +m[1]; continue; }
      if ((m = /^new file mode (\d+)/.exec(line))) { f.status = 'added'; f.newMode = m[1]; continue; }
      if ((m = /^deleted file mode (\d+)/.exec(line))) { f.status = 'deleted'; f.oldMode = m[1]; continue; }
      if ((m = /^old mode (\d+)/.exec(line))) { f.oldMode = m[1]; continue; }
      if ((m = /^new mode (\d+)/.exec(line))) { f.newMode = m[1]; continue; }
      if (/^Binary files .* differ$/.test(line) || line === 'GIT binary patch') {
        f.binary = true;
        const bm = /^Binary files (.+) and (.+) differ$/.exec(line);
        if (bm) { const a = stripPrefix(bm[1]); const b = stripPrefix(bm[2]); if (a === null) f.status = 'added'; if (b === null) f.status = 'deleted'; f.oldPath = a; f.newPath = b; }
        continue;
      }
    }
    finish(f, files);
    for (const file of files) {
      if (file.status === 'added') file.oldPath = null;
      if (file.status === 'deleted') file.newPath = null;
      file.path = file.newPath || file.oldPath;
      for (const hk of file.hunks) { delete hk.remainingOld; delete hk.remainingNew; }
    }
    return { files, meta };
  }
  /* Map of added line numbers per file path -> Set, plus helpers used for anchoring. */
  function addedLines(file) {
    const out = new Map();
    for (const h of file.hunks) for (const l of h.lines) if (l.type === 'add') out.set(l.newNo, l.text);
    return out;
  }
  function newLineMap(file) {
    const out = new Map();
    for (const h of file.hunks) for (const l of h.lines) if (l.newNo != null) out.set(l.newNo, l);
    return out;
  }
  function stats(files) {
    return files.reduce((a, f) => ({ files: a.files + 1, additions: a.additions + f.additions, deletions: a.deletions + f.deletions, binary: a.binary + (f.binary ? 1 : 0) }), { files: 0, additions: 0, deletions: 0, binary: 0 });
  }
  /* Rebuild a unified diff for one file from GitHub's /pulls/:n/files entry (patch has hunks only). */
  function fromGithubFiles(entries) {
    return (entries || []).map((e) => {
      const oldP = e.status === 'added' ? null : (e.previous_filename || e.filename);
      const newP = e.status === 'removed' ? null : e.filename;
      let head = 'diff --git a/' + (oldP || e.filename) + ' b/' + (newP || e.filename) + '\n';
      if (e.status === 'renamed') head += 'rename from ' + oldP + '\nrename to ' + newP + '\n';
      if (e.status === 'added') head += 'new file mode 100644\n';
      if (e.status === 'removed') head += 'deleted file mode 100644\n';
      if (!e.patch) return head + (e.changes ? 'Binary files ' + (oldP ? 'a/' + oldP : '/dev/null') + ' and ' + (newP ? 'b/' + newP : '/dev/null') + ' differ\n' : '');
      return head + '--- ' + (oldP ? 'a/' + oldP : '/dev/null') + '\n+++ ' + (newP ? 'b/' + newP : '/dev/null') + '\n' + e.patch + (e.patch.endsWith('\n') ? '' : '\n');
    }).join('');
  }
  /* Pair del/add runs for side-by-side rendering. Returns rows [{left, right}] per hunk. */
  function sideBySide(hunk) {
    const rows = []; let dels = []; let adds = [];
    const flush = () => { const n = Math.max(dels.length, adds.length); for (let i = 0; i < n; i++) rows.push({ left: dels[i] || null, right: adds[i] || null }); dels = []; adds = []; };
    for (const l of hunk.lines) {
      if (l.type === 'del') { if (adds.length) flush(); dels.push(l); }
      else if (l.type === 'add') adds.push(l);
      else { flush(); rows.push({ left: l, right: l }); }
    }
    flush();
    return rows;
  }
  return { parse, addedLines, newLineMap, stats, fromGithubFiles, sideBySide, stripPrefix };
});
