const { test } = require('node:test');
const assert = require('node:assert/strict');
const { diff } = require('./helpers.cjs');

test('parses a modified file with hunk header, context, add and delete lines', () => {
  const t = 'diff --git a/src/a.js b/src/a.js\nindex 1111111..2222222 100644\n--- a/src/a.js\n+++ b/src/a.js\n@@ -10,3 +10,4 @@ function main() {\n one\n-two\n+TWO\n+three\n four\n';
  const { files } = diff.parse(t);
  assert.equal(files.length, 1);
  const f = files[0];
  assert.equal(f.path, 'src/a.js'); assert.equal(f.status, 'modified'); assert.equal(f.additions, 2); assert.equal(f.deletions, 1);
  assert.equal(f.hunks[0].header, 'function main() {');
  assert.deepEqual(f.hunks[0].lines.map((l) => [l.type, l.oldNo, l.newNo]), [['ctx', 10, 10], ['del', 11, null], ['add', null, 11], ['add', null, 12], ['ctx', 12, 13]]);
});
test('parses renames with similarity and keeps old path', () => {
  const t = 'diff --git a/old/name.py b/new/name.py\nsimilarity index 92%\nrename from old/name.py\nrename to new/name.py\nindex 1..2 100644\n--- a/old/name.py\n+++ b/new/name.py\n@@ -1,2 +1,2 @@\n-x = 1\n+x = 2\n y = 3\n';
  const f = diff.parse(t).files[0];
  assert.equal(f.status, 'renamed'); assert.equal(f.oldPath, 'old/name.py'); assert.equal(f.newPath, 'new/name.py'); assert.equal(f.similarity, 92);
});
test('pure rename without hunks', () => {
  const f = diff.parse('diff --git a/a.txt b/b.txt\nsimilarity index 100%\nrename from a.txt\nrename to b.txt\n').files[0];
  assert.equal(f.status, 'renamed'); assert.equal(f.hunks.length, 0); assert.equal(f.path, 'b.txt');
});
test('binary files are flagged and have no hunks', () => {
  const { files } = diff.parse('diff --git a/logo.png b/logo.png\nnew file mode 100644\nindex 0000000..1234567\nBinary files /dev/null and b/logo.png differ\ndiff --git a/x.bin b/x.bin\nindex 1..2 100644\nGIT binary patch\nliteral 3\nKcmZ?wbv\n\n');
  assert.equal(files.length, 2);
  assert.ok(files[0].binary); assert.equal(files[0].status, 'added'); assert.equal(files[0].path, 'logo.png');
  assert.ok(files[1].binary);
});
test('"No newline at end of file" marks the right line and is not counted', () => {
  const t = '--- a/a.txt\n+++ b/a.txt\n@@ -1 +1 @@\n-old\n\\ No newline at end of file\n+new\n\\ No newline at end of file\n';
  const f = diff.parse(t).files[0];
  assert.equal(f.additions, 1); assert.equal(f.deletions, 1);
  assert.ok(f.hunks[0].lines[0].noNewline); assert.ok(f.hunks[0].lines[1].noNewline);
});
test('new and deleted files via /dev/null', () => {
  const t = 'diff --git a/n.js b/n.js\nnew file mode 100644\n--- /dev/null\n+++ b/n.js\n@@ -0,0 +1,2 @@\n+a\n+b\ndiff --git a/d.js b/d.js\ndeleted file mode 100644\n--- a/d.js\n+++ /dev/null\n@@ -1 +0,0 @@\n-gone\n';
  const [n, d] = diff.parse(t).files;
  assert.equal(n.status, 'added'); assert.equal(n.oldPath, null); assert.equal(n.additions, 2); assert.deepEqual(n.hunks[0].lines.map((l) => l.newNo), [1, 2]);
  assert.equal(d.status, 'deleted'); assert.equal(d.newPath, null); assert.equal(d.path, 'd.js');
});
test('content lines that look like headers (--- / +++) inside hunks are content', () => {
  const t = '--- a/s.sql\n+++ b/s.sql\n@@ -1,2 +1,2 @@\n--- a comment\n++++ plus\n context\n';
  const f = diff.parse(t).files[0];
  assert.equal(diff.parse(t).files.length, 1);
  assert.deepEqual(f.hunks[0].lines.map((l) => [l.type, l.text]), [['del', '-- a comment'], ['add', '+++ plus'], ['ctx', 'context']]);
});
test('plain multi-file unified diff without diff --git headers', () => {
  const t = '--- a/one.c\n+++ b/one.c\n@@ -1 +1 @@\n-a\n+b\n--- a/two.c\n+++ b/two.c\n@@ -1 +1,2 @@\n x\n+y\n';
  const files = diff.parse(t).files;
  assert.deepEqual(files.map((f) => f.path), ['one.c', 'two.c']);
  assert.equal(files[1].hunks[0].lines[1].newNo, 2);
});
test('hunk without counts defaults to 1 and multiple hunks keep numbering', () => {
  const t = '--- a/x\n+++ b/x\n@@ -3 +3 @@\n-a\n+b\n@@ -40,2 +40,3 @@\n k\n+n\n k2\n';
  const f = diff.parse(t).files[0];
  assert.equal(f.hunks.length, 2); assert.equal(f.hunks[0].oldLines, 1); assert.equal(f.hunks[1].lines[1].newNo, 41);
});
test('mbox .patch: subject and author are read, CRLF normalized, signature ignored', () => {
  const t = 'From 1234 Mon Sep 17 00:00:00 2001\r\nFrom: Dev <dev@example.com>\r\nSubject: [PATCH 1/2] Fix the thing\r\n\r\n---\r\n a.js | 1 +\r\n\r\ndiff --git a/a.js b/a.js\r\n--- a/a.js\r\n+++ b/a.js\r\n@@ -1 +1,2 @@\r\n x\r\n+y\r\n-- \r\n2.43.0\r\n';
  const r = diff.parse(t);
  assert.equal(r.meta.subject, 'Fix the thing'); assert.equal(r.meta.from, 'Dev <dev@example.com>');
  assert.equal(r.files.length, 1); assert.equal(r.files[0].additions, 1);
  assert.equal(r.files[0].hunks[0].lines.length, 2);
});
test('quoted paths with spaces', () => {
  const f = diff.parse('diff --git "a/my file.js" "b/my file.js"\n--- "a/my file.js"\n+++ "b/my file.js"\n@@ -1 +1 @@\n-a\n+b\n').files[0];
  assert.equal(f.path, 'my file.js');
});
test('mode-only change', () => {
  const f = diff.parse('diff --git a/run.sh b/run.sh\nold mode 100644\nnew mode 100755\n').files[0];
  assert.equal(f.oldMode, '100644'); assert.equal(f.newMode, '100755'); assert.equal(f.status, 'modified');
});
test('empty or garbage input yields no files', () => {
  assert.deepEqual(diff.parse('').files, []); assert.deepEqual(diff.parse('hello world\nnot a diff').files, []);
});
test('fromGithubFiles rebuilds a parseable diff incl. rename, removed and binary', () => {
  const txt = diff.fromGithubFiles([
    { filename: 'src/b.js', previous_filename: 'src/a.js', status: 'renamed', changes: 2, patch: '@@ -1 +1 @@\n-a\n+b' },
    { filename: 'gone.txt', status: 'removed', changes: 1, patch: '@@ -1 +0,0 @@\n-x' },
    { filename: 'img.png', status: 'added', changes: 0 },
    { filename: 'logo.png', status: 'modified', changes: 5 }
  ]);
  const files = diff.parse(txt).files;
  assert.equal(files[0].status, 'renamed'); assert.equal(files[0].oldPath, 'src/a.js'); assert.equal(files[0].additions, 1);
  assert.equal(files[1].status, 'deleted');
  assert.ok(files.find((f) => f.path === 'logo.png').binary);
});
test('sideBySide pairs deletions with additions', () => {
  const h = diff.parse('--- a/x\n+++ b/x\n@@ -1,3 +1,3 @@\n a\n-b\n-c\n+B\n d\n').files[0].hunks[0];
  const rows = diff.sideBySide(h);
  assert.equal(rows.length, 4);
  assert.equal(rows[1].left.text, 'b'); assert.equal(rows[1].right.text, 'B');
  assert.equal(rows[2].left.text, 'c'); assert.equal(rows[2].right, null);
});
test('addedLines and stats', () => {
  const files = diff.parse('--- a/x\n+++ b/x\n@@ -1 +1,2 @@\n a\n+b\n').files;
  assert.deepEqual([...diff.addedLines(files[0]).entries()], [[2, 'b']]);
  assert.deepEqual(diff.stats(files), { files: 1, additions: 1, deletions: 0, binary: 0 });
});
