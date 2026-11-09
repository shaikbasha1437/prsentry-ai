# Verification log

Recorded 2026-11-09 (America/Chicago). Everything below was run against the live site at
https://shaikbasha1437.github.io/prsentry-ai/ unless it says otherwise.

## Unit tests (`npm test`)

- **183 passing, 0 failing**, with the official SARIF 2.1.0 JSON-schema check turned on (`AJV_PATH` set).
- Without ajv: 182 pass and 1 is skipped (the schema check).
- The suites cover:
  - the diff parser
  - every rule in the catalog, with one positive and one negative case each
  - LLM prompt fencing, parsing, anchoring and dedupe
  - the bundled demo expectations
  - the GitHub fetch logic (mocked)
  - the Action, including a real subprocess run against a local HTTP mock of the GitHub API

## Browser end-to-end (Playwright, live site)

| Browser | Result |
|---|---|
| Chrome | 127 passed, 0 failed |
| Firefox | 124 passed, 0 failed; the offline-reload check was skipped (see note) |

What the runs covered:

- **Visits:** a fresh visit and a repeat visit, with the service worker in control.
- **Layout:** a 375 px mobile viewport with no horizontal overflow, plus the light and dark themes.
- **Modals:** every modal was closed with X, Cancel, Esc, a backdrop click and browser Back.
- **Unsaved changes:** the discard prompt appears when there are edits.
- **Undo:** every destructive action shows an undo toast.
- **Review flow:** all 6 demo PRs, triage (accept, dismiss, false positive, undo), and the filters.
- **Exports:** Markdown, SARIF (schema-validated), JSON and the review payload.
- **Network:** a mocked GitHub fetch, a mocked LLM review and an offline reload (Chrome).
- **Real fetch:** exactly **one** real public PR fetch (this repo's PR #1), using 1 metadata request and 1 diff request.

Note: Playwright's Firefox `setOffline` throws `NS_ERROR_OFFLINE` before the service worker can answer, so the offline check runs in Chrome only.

## Demo results (rules only, no key)

| Demo | Score | Crit | High | Med | Low | Info | Recommendation |
|---|---|---|---|---|---|---|---|
| clean-refactor | 100 | 0 | 0 | 0 | 0 | 0 | Approve |
| sql-injection | 62 | 0 | 2 | 1 | 1 | 0 | Request changes |
| leaked-secret | 2 | 2 | 2 | 1 | 1 | 1 | Request changes |
| react-xss | 79 | 0 | 1 | 1 | 0 | 0 | Request changes |
| async-bug | 72 | 0 | 0 | 4 | 2 | 0 | Comment |
| prompt-injection | 34 | 0 | 4 | 1 | 0 | 0 | Request changes (injection caught, banner shown) |

## GitHub Action self-test

PR #1 (branch `selftest/rules-only`) ran `.github/workflows/prsentry-selftest.yml` in rules-only mode with `GITHUB_TOKEN`:

- The run succeeded with 7 findings.
- The SARIF upload to code scanning was accepted.
- `github-actions[bot]` posted a **Request changes** review with 6 inline comments (score 39).
- The web app produces the same score, 39, for the same PR.

The LLM mode of the Action was tested only against mocked providers. No real AI key was used anywhere.

## Provider CORS check (fake key, from a browser page)

| Provider | Response | Reaches the browser? |
|---|---|---|
| OpenAI | HTTP 401 | Yes |
| Anthropic (`anthropic-dangerous-direct-browser-access`) | HTTP 401 | Yes |
| Gemini | HTTP 400 | Yes |
| OpenRouter | HTTP 401 | Yes |

All four providers are reachable from the browser and reject the fake key. A successful completion was **not** tested because no real key was used.

## Known limits

- The rule engine matches patterns. It is not a SAST tool and has no data-flow analysis, so it will produce both false positives and false negatives.
- The "sample AI" replies in the demos are canned, not live model output.
