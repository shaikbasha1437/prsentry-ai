# PRSentry AI

**A pull request review agent for security issues and bugs.** Paste a GitHub PR, a `.patch`, or try a demo. A deterministic rule engine checks every *added* line for secrets, injection, unsafe APIs and classic bugs with no key and no server. Add your own AI key for a second, fenced review pass. Export a GitHub review (Markdown with `suggestion` blocks), the exact REST payload, SARIF 2.1.0 or JSON. A self-hostable **GitHub Action** runs the same engine in CI.

**Live app:** https://shaikbasha1437.github.io/prsentry-ai/ · **Action:** [`/action`](action) · **Rules:** [docs/RULES.md](docs/RULES.md)

> **Honest limits.** Pattern rules have false positives and false negatives: they look at one added line at a time with a little context, do no data-flow analysis and do not know your framework's protections. PRSentry is **not** a replacement for a SAST tool (CodeQL, Semgrep) or a human reviewer. AI review sends the diff to the provider you choose, and model output can be wrong or manipulated. The web page never posts to GitHub.

## What it does

| Step | Details |
|---|---|
| **Load** | Public GitHub PR URL (metadata + unified diff via the GitHub REST API, which supports CORS; falls back to the per-file patch list for very large diffs), pasted diff, or a dropped/opened `.patch` / `.diff` (incl. `git format-patch` mbox). Optional GitHub token for private repos / higher rate limit. |
| **Parse** | Files, hunks and exact old/new line numbers. Handles renames, copies, new/deleted files, mode changes, binary files and `\ No newline at end of file`. |
| **Rules** | 38 checks on added lines only — see [docs/RULES.md](docs/RULES.md). Each finding has severity (critical/high/medium/low/info), category (security/bug/perf/style/test), CWE where relevant, explanation, code context, confidence, and a suggested fix when one can be generated safely. |
| **AI pass (optional)** | OpenAI, Anthropic (`anthropic-dangerous-direct-browser-access`), Google Gemini, or any OpenAI-compatible endpoint (OpenRouter, Ollama, LM Studio). The diff is sent in ~12k-character chunks inside a nonce-tagged `<untrusted_diff>` fence; the model is told never to follow instructions inside it and to report them. Each AI finding must point at a real **added** line (or quote one) or it is dropped as *unanchored*. AI and rule findings are merged and de-duplicated. |
| **Triage** | Accept, dismiss (with a reason), mark false positive, reopen — each with an undo toast. Filter by severity, category, file and status. Score (0–100), grade and a merge recommendation (approve / comment / request changes) with reasons. |
| **Export** | Review Markdown, GitHub REST payload for `POST /repos/{owner}/{repo}/pulls/{pull_number}/reviews` with `gh` and `curl` examples, SARIF 2.1.0 (validated against the official schema in tests), JSON. Keys are never included. |

### Rule highlights
Hardcoded secrets (AWS key IDs, GitHub tokens, Slack tokens/webhooks, live payment keys, private keys, high-entropy credentials) · SQL built with f-strings / template literals / concatenation / `%` / `.format` / `Sprintf` · command injection (`exec`, `os.system`, `subprocess(..., shell=True)`, `Runtime.exec`, `sh -c`) · `eval` / `new Function` / string `setTimeout` · unsafe deserialization (`pickle`, `yaml.load`, `torch.load`, `ObjectInputStream`, `unserialize`, `BinaryFormatter`) · XSS sinks (`innerHTML`, `dangerouslySetInnerHTML`, `document.write`, `v-html`, `mark_safe`) · path traversal · SSRF · MD5/SHA-1 (high when near passwords) · `Math.random` / `random` for tokens · disabled TLS verification · CORS `*` · JWT `none` / unverified decode · floating promises and `forEach(async …)` · `==` / `== None` / `=== NaN` · `<= length` loops · swallowed errors / bare `except` · `.only` / `.skip` tests · secrets in logs · debug leftovers · TODO/FIXME · invisible bidi/zero-width characters · **text aimed at AI reviewers** (prompt injection) · new / bumped / unpinned / URL dependencies · large files · source changed without tests.

## Demo mode (no key, works offline)
Six original, fictional PRs (`*.example` domains) with deterministic results:

| Demo | Rules result |
|---|---|
| Refactor: extract date helpers | 0 findings → **Approve** (100) |
| Add order search endpoint | 2 × SQL injection (high), missing tests, `!= None` → **Request changes** |
| Wire up billing alerts to Slack | fake AWS key ID + fake Slack webhook (critical), credential, key logged, `debugger`, `console.log`, TODO → **Request changes** |
| Profile bio supports rich text | `dangerouslySetInnerHTML` (high), `innerHTML` (medium) → **Request changes** |
| Send welcome emails after signup | floating promise, `forEach(async)`, `<= length`, empty `catch`, dependency added + major bump → **Comment** |
| Speed up thumbnail generation | comment telling AI reviewers to approve (**prompt injection caught**), `shell=True`, `yaml.load` → **Request changes** |

Three demos also include a **recorded sample AI reply** ("Play sample AI review") so you can see merge, de-duplication and an unanchored (hallucinated-line) finding without a key. No model is called; the UI labels it as a sample.

Every secret-looking value in the demos is fake. The demo JSON stores them with `\u` escapes and the tests build them by concatenation, so no provider-shaped string sits in the repository.

## Privacy
* Rules mode: nothing leaves your browser except the read-only GitHub API calls you trigger by fetching a PR.
* Keys (AI key, GitHub token) are stored only in this browser's `localStorage` (uncheck *Remember keys* to keep them in memory for the tab only) and are sent only to the provider you selected / `api.github.com`. They are never placed in exports, links or the service-worker cache.
* AI mode sends the diff to your provider under your account and its data policy.

## GitHub Action
The action in [`/action`](action) is a dependency-free JavaScript action (`runs.using: node24`; GitHub removed the Node 20 action runtime on 2026-09-23, the code itself runs on Node 20+). It loads the same `js/diff.js`, `js/rules.js` and `js/review.js` as the web app.

```yaml
# .github/workflows/prsentry.yml in your repository
name: PRSentry review
on: { pull_request: { types: [opened, synchronize, reopened] } }
permissions: { contents: read, pull-requests: write, security-events: write }
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: shaikbasha1437/prsentry-ai/action@main   # pin a commit SHA in production
        with:
          mode: rules        # or llm
          fail-on: high      # critical | high | medium | low | info | none
          post-review: true
          upload-sarif: true
```

Full example with the optional LLM step: [docs/prsentry-workflow.example.yml](docs/prsentry-workflow.example.yml).

| Input | Default | Meaning |
|---|---|---|
| `github-token` | `${{ github.token }}` | Reads the PR diff; posts the review / uploads SARIF. |
| `mode` | `rules` | `rules` or `llm` (rules + LLM; sends the diff to your provider). |
| `llm-provider`, `llm-model`, `llm-api-key`, `llm-base-url` | `openai`, provider default, empty, empty | Pass the key from a repository secret. Without a key, `llm` mode falls back to rules with a warning. |
| `max-llm-chunks` | `6` | Upper bound on LLM requests per run. |
| `fail-on` | `high` | Fail the check when an open finding is at or above this severity (`none` never fails). |
| `post-review` | `true` | Create a PR review with inline comments (`REQUEST_CHANGES` / `COMMENT`). If GitHub rejects an inline anchor (422) it retries with a summary-only review. |
| `allow-approve` | `false` | Without it, a clean PR gets `COMMENT` instead of `APPROVE` (repos normally block Actions from approving). |
| `upload-sarif` | `false` | Upload gzipped SARIF to code scanning for `refs/pull/N/head` (needs `security-events: write` and code scanning available for the repo). |
| `sarif-file` | `prsentry.sarif` | Where the SARIF report is written. |
| `max-comments` | `30` | Inline comment cap. |
| `disabled-rules` | empty | Comma-separated rule IDs. |
| `pr-number` | from event | For `workflow_dispatch`. |
| `dry-run` | `false` | Analyse, write SARIF, annotations and the job summary, but never call GitHub write APIs. |

Outputs: `findings`, `recommendation`, `score`, `sarif-file`. Every run also writes `::error` / `::warning` / `::notice` annotations and the review Markdown to the job summary. Fork PRs get a read-only `GITHUB_TOKEN`, so posting the review is skipped with a warning there.

**How it was verified:** see [VERIFICATION.md](VERIFICATION.md). The action is unit-tested with mocked GitHub and LLM APIs and run as a real process against a local mock API. Its rules-only path was also run on a real test PR in this repository with only `GITHUB_TOKEN` (no LLM key) — details in VERIFICATION.md. LLM mode in the action was tested with a mocked endpoint only.

## Posting a review yourself
The web app shows the exact body. Save it as `review.json` and run:

```sh
gh api --method POST /repos/OWNER/REPO/pulls/PR_NUMBER/reviews -H "Accept: application/vnd.github+json" --input review.json
```

## Development
```sh
npm test                    # 180+ Node tests: parser, every rule (positive + negative), anchoring, dedupe, injection fence, SARIF, payload, clients, action
npm run demos               # rebuild samples/demo-prs.json from the fixture sources via real `git diff`
node scripts/build-rules-doc.mjs
python3 -m http.server 8080 # then open http://localhost:8080/
```
The SARIF schema test runs when `ajv` and `.cache/sarif-schema-2.1.0.json` are available locally (`AJV_PATH=/path/to/ajv`); otherwise it is skipped and a structural validator still runs.

Project layout: `index.html`, `styles.css`, `js/app.js` (UI) · `js/diff.js` (parser) · `js/rules.js` (rule engine) · `js/review.js` (AI prompt/anchoring/merge, score, exports) · `js/github.js` (read-only API client) · `js/llm.js` (bring-your-own-key client) · `action/` (GitHub Action) · `samples/demo-prs.json` · `sw.js` (network-first service worker with a versioned cache).

## License
MIT © 2026 shaikbasha1437
