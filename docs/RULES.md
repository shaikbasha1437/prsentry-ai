# PRSentry AI rule catalog

38 deterministic checks. They run only on **added** lines of a diff, one line at a time (plus a few lines of context). They are heuristics: expect false positives and false negatives. They are not a substitute for a SAST tool or human review.

| Rule | Default severity | Category | CWE |
|---|---|---|---|
| [`secret-aws-access-key`](#secret-aws-access-key) Hardcoded AWS access key ID | critical | security | CWE-798 |
| [`secret-github-token`](#secret-github-token) Hardcoded GitHub token | critical | security | CWE-798 |
| [`secret-slack-token`](#secret-slack-token) Hardcoded Slack token or webhook | critical | security | CWE-798 |
| [`secret-stripe-key`](#secret-stripe-key) Hardcoded live payment API key | critical | security | CWE-798 |
| [`secret-private-key`](#secret-private-key) Private key committed | critical | security | CWE-321 |
| [`secret-generic`](#secret-generic) Possible hardcoded credential | high | security | CWE-798 |
| [`hidden-unicode`](#hidden-unicode) Invisible bidirectional/zero-width characters | high | security |  |
| [`prompt-injection`](#prompt-injection) Text that tries to instruct an AI reviewer | high | security | CWE-1427 |
| [`sql-injection`](#sql-injection) SQL built with string interpolation or concatenation | high | security | CWE-89 |
| [`command-injection`](#command-injection) Shell command built from variable input | high | security | CWE-78 |
| [`code-eval`](#code-eval) Dynamic code evaluation | high | security | CWE-95 |
| [`unsafe-deserialization`](#unsafe-deserialization) Unsafe deserialization of untrusted data | high | security | CWE-502 |
| [`xss-sink`](#xss-sink) HTML injection sink (possible XSS) | medium | security | CWE-79 |
| [`path-traversal`](#path-traversal) File path built from request input | high | security | CWE-22 |
| [`ssrf`](#ssrf) Server-side request to a user-supplied URL (SSRF) | medium | security | CWE-918 |
| [`weak-hash`](#weak-hash) Weak hash algorithm (MD5/SHA-1) | medium | security | CWE-328 |
| [`insecure-random`](#insecure-random) Non-cryptographic random used for a secret value | medium | security | CWE-338 |
| [`tls-verify-disabled`](#tls-verify-disabled) TLS certificate verification disabled | high | security | CWE-295 |
| [`cors-wildcard`](#cors-wildcard) CORS allows any origin | medium | security | CWE-942 |
| [`jwt-insecure`](#jwt-insecure) JWT signature not verified / alg none | high | security | CWE-347 |
| [`floating-promise`](#floating-promise) Async call without await (floating promise) | medium | bug |  |
| [`loose-equality`](#loose-equality) Loose equality (==) coerces types | low | bug | CWE-1025 |
| [`off-by-one`](#off-by-one) Likely off-by-one bound | medium | bug | CWE-193 |
| [`swallowed-error`](#swallowed-error) Error caught and silently ignored | medium | bug | CWE-390 |
| [`bare-except`](#bare-except) Bare except catches everything (incl. KeyboardInterrupt) | low | bug | CWE-396 |
| [`focused-or-skipped-test`](#focused-or-skipped-test) Focused or skipped test added | medium | test |  |
| [`sensitive-log`](#sensitive-log) Sensitive value written to logs | high | security | CWE-532 |
| [`debug-leftover`](#debug-leftover) Debug statement left in code | low | style | CWE-489 |
| [`todo-added`](#todo-added) TODO/FIXME added | info | style | CWE-546 |
| [`await-in-loop`](#await-in-loop) Sequential await inside a loop | low | perf |  |
| [`query-in-loop`](#query-in-loop) Database/API call inside a loop (N+1) | low | perf | CWE-1050 |
| [`dependency-added`](#dependency-added) New dependency | low | security |  |
| [`dependency-bump`](#dependency-bump) Dependency version bump | info | security |  |
| [`dependency-unpinned`](#dependency-unpinned) Unpinned or URL dependency | medium | security | CWE-1104 |
| [`missing-tests`](#missing-tests) Source changed without test changes | medium | test |  |
| [`large-file-change`](#large-file-change) Large change in one file | info | perf |  |
| [`large-pr`](#large-pr) Large pull request | info | perf |  |
| [`minified-or-generated`](#minified-or-generated) Very long line added | info | style |  |

Some rules raise or lower severity from context (for example a weak hash next to "password" becomes high; next to "etag" it becomes low; CORS `*` with credentials becomes high).

## secret-aws-access-key

**Hardcoded AWS access key ID** · critical · security · [CWE-798](https://cwe.mitre.org/data/definitions/798.html)

An AWS access key ID was added to source. Anyone with repo access (or a leaked clone) can use it together with its secret. Revoke the key in IAM, then load credentials from the environment, a role, or a secrets manager.

## secret-github-token

**Hardcoded GitHub token** · critical · security · [CWE-798](https://cwe.mitre.org/data/definitions/798.html)

A GitHub personal access / OAuth / app token was added. Revoke it at github.com/settings/tokens and use a secret store or GITHUB_TOKEN in CI.

## secret-slack-token

**Hardcoded Slack token or webhook** · critical · security · [CWE-798](https://cwe.mitre.org/data/definitions/798.html)

A Slack bot/user token or incoming-webhook URL was added. Anyone holding it can post to (or read) the workspace. Revoke it in the Slack app settings and load it from configuration.

## secret-stripe-key

**Hardcoded live payment API key** · critical · security · [CWE-798](https://cwe.mitre.org/data/definitions/798.html)

A live secret key for a payments API was added. Roll the key in the provider dashboard and keep it server-side in a secret store.

## secret-private-key

**Private key committed** · critical · security · [CWE-321](https://cwe.mitre.org/data/definitions/321.html)

A PEM/OpenSSH private key block was added. Treat the key as compromised: generate a new one and store it outside the repository.

## secret-generic

**Possible hardcoded credential** · high · security · [CWE-798](https://cwe.mitre.org/data/definitions/798.html)

A credential-like name is assigned a literal value with high randomness. If it is real, rotate it and read it from the environment or a secret manager instead.

## hidden-unicode

**Invisible bidirectional/zero-width characters** · high · security

The added line contains invisible Unicode control characters (bidi overrides or zero-width marks). They can make code look different from how it runs ("Trojan Source"). Remove them unless they are intentional text content.

## prompt-injection

**Text that tries to instruct an AI reviewer** · high · security · [CWE-1427](https://cwe.mitre.org/data/definitions/1427.html)

This added text reads like an instruction to an AI code reviewer (for example "ignore previous instructions" or "approve this PR"). PRSentry fences the diff as untrusted data and never follows instructions inside it, but a human should confirm why it is here. Treat AI-review verdicts on this PR with extra suspicion.

## sql-injection

**SQL built with string interpolation or concatenation** · high · security · [CWE-89](https://cwe.mitre.org/data/definitions/89.html)

User-controlled values appear to be spliced into a SQL string. An attacker who controls the value can change the query (read other rows, bypass auth, drop tables). Use parameterized queries / prepared statements and let the driver escape values.

## command-injection

**Shell command built from variable input** · high · security · [CWE-78](https://cwe.mitre.org/data/definitions/78.html)

A command string is executed through a shell with a non-constant value. If any part comes from a user, file name, branch name or request, shell metacharacters (; | $( ) let an attacker run arbitrary commands. Call the program directly with an argument array (execFile / spawn without shell / subprocess.run([...])).

## code-eval

**Dynamic code evaluation** · high · security · [CWE-95](https://cwe.mitre.org/data/definitions/95.html)

Evaluating a string as code lets anyone who influences that string run arbitrary code in your process. Parse data with a real parser (JSON.parse, ast.literal_eval) or dispatch through an allow-list of functions.

## unsafe-deserialization

**Unsafe deserialization of untrusted data** · high · security · [CWE-502](https://cwe.mitre.org/data/definitions/502.html)

This deserializer can construct arbitrary objects (and often run code) from its input. If the bytes can come from a user, cache, queue or upload, that is remote code execution. Use a data-only format (JSON, yaml.safe_load) or a signed, schema-validated payload.

## xss-sink

**HTML injection sink (possible XSS)** · medium · security · [CWE-79](https://cwe.mitre.org/data/definitions/79.html)

A value is written into the page as HTML. If any part comes from a user, URL, API or database, it can inject <script> or event-handler markup (stored or reflected XSS). Render text with textContent / JSX children, or sanitize with a vetted library (DOMPurify) before inserting HTML.

## path-traversal

**File path built from request input** · high · security · [CWE-22](https://cwe.mitre.org/data/definitions/22.html)

A filesystem path includes a value that comes from the request. Inputs like "../../etc/passwd" or absolute paths can escape the intended directory. Resolve the final path and check it is still inside an allowed base directory, or map user input to an allow-list of file names.

## ssrf

**Server-side request to a user-supplied URL (SSRF)** · medium · security · [CWE-918](https://cwe.mitre.org/data/definitions/918.html)

The server fetches a URL that comes from the request. Attackers can point it at internal services (cloud metadata at 169.254.169.254, localhost admin ports, private networks). Allow-list hosts and schemes, resolve DNS and block private ranges, and do not follow redirects blindly.

## weak-hash

**Weak hash algorithm (MD5/SHA-1)** · medium · security · [CWE-328](https://cwe.mitre.org/data/definitions/328.html)

MD5 and SHA-1 are broken for collision resistance and far too fast for password storage. Use SHA-256+ for integrity, HMAC for authentication, and a slow password hash (argon2id, bcrypt, scrypt) for passwords.

## insecure-random

**Non-cryptographic random used for a secret value** · medium · security · [CWE-338](https://cwe.mitre.org/data/definitions/338.html)

Math.random()/random.* are predictable pseudo-random generators. Tokens, reset codes, session IDs and salts generated with them can be guessed. Use a CSPRNG: crypto.randomUUID() / crypto.getRandomValues() in JS, the secrets module in Python, SecureRandom in Java, crypto/rand in Go.

## tls-verify-disabled

**TLS certificate verification disabled** · high · security · [CWE-295](https://cwe.mitre.org/data/definitions/295.html)

Turning off certificate verification makes the connection trivially interceptable (anyone on the network path can impersonate the server and read or change traffic). Fix the trust store instead: pass the internal CA bundle (ca: / verify="/path/ca.pem").

## cors-wildcard

**CORS allows any origin** · medium · security · [CWE-942](https://cwe.mitre.org/data/definitions/942.html)

Any website can call this endpoint from a visitor's browser and read the response. Combined with cookies or credentials that is a data-exfiltration hole; even without them it exposes internal APIs. Allow-list the exact origins that need access.

## jwt-insecure

**JWT signature not verified / alg none** · high · security · [CWE-347](https://cwe.mitre.org/data/definitions/347.html)

The token is accepted without checking its signature (or with the "none" algorithm / expiry checks off). Anyone can forge a token with any user ID or role. Always verify with a fixed algorithm allow-list and the expected key, issuer and audience.

## floating-promise

**Async call without await (floating promise)** · medium · bug

This calls an async function but nothing waits for it. Errors become unhandled rejections, and the code after it runs before the work is done (e.g. responding before the record is saved). Await it, return it, or explicitly fire-and-forget with error handling.

## loose-equality

**Loose equality (==) coerces types** · low · bug · [CWE-1025](https://cwe.mitre.org/data/definitions/1025.html)

== and != convert types before comparing ("0" == 0, [] == false, "" == 0 are all true), which hides bugs. Use === / !== unless you deliberately want the x == null check for both null and undefined.

## off-by-one

**Likely off-by-one bound** · medium · bug · [CWE-193](https://cwe.mitre.org/data/definitions/193.html)

Indexes run from 0 to length - 1. Iterating while i <= length (or indexing at [length]) reads one element past the end: undefined in JS, IndexError in Python, an exception in Java/C#.

## swallowed-error

**Error caught and silently ignored** · medium · bug · [CWE-390](https://cwe.mitre.org/data/definitions/390.html)

The error is caught and dropped, so failures disappear without a log, metric or retry, and the code continues in a half-finished state. Log it, re-throw it, or handle the specific error you expect.

## bare-except

**Bare except catches everything (incl. KeyboardInterrupt)** · low · bug · [CWE-396](https://cwe.mitre.org/data/definitions/396.html)

A bare except also catches SystemExit and KeyboardInterrupt and hides programming errors. Catch the specific exceptions you expect, or at least Exception.

## focused-or-skipped-test

**Focused or skipped test added** · medium · test

.only makes the runner skip every other test (CI goes green while most tests never run); .skip/xit/@skip silently drops coverage. Remove it before merging or link an issue explaining why.

## sensitive-log

**Sensitive value written to logs** · high · security · [CWE-532](https://cwe.mitre.org/data/definitions/532.html)

Passwords, tokens, keys or card data in logs end up in log aggregators, support tickets and backups with weaker access control. Log an identifier or a redacted value instead.

## debug-leftover

**Debug statement left in code** · low · style · [CWE-489](https://cwe.mitre.org/data/definitions/489.html)

Debug output and breakpoints left in production code leak internal data into consoles/logs, add noise, and a debugger/breakpoint() call can hang a server. Remove it or use the project logger at an appropriate level.

## todo-added

**TODO/FIXME added** · info · style · [CWE-546](https://cwe.mitre.org/data/definitions/546.html)

A new TODO/FIXME marks unfinished work. Make sure it is tracked (link an issue) so it does not ship as a silent gap.

## await-in-loop

**Sequential await inside a loop** · low · perf

Each iteration waits for the previous request to finish, so N items take N round-trips. If the calls are independent, batch them or run them with Promise.all / asyncio.gather (with a concurrency limit).

## query-in-loop

**Database/API call inside a loop (N+1)** · low · perf · [CWE-1050](https://cwe.mitre.org/data/definitions/1050.html)

A query runs once per loop iteration (the N+1 pattern). With many rows this multiplies latency and database load. Fetch in one query (IN (...), JOIN, select_related/prefetch_related, batch loader).

## dependency-added

**New dependency** · low · security

A new package was added to a manifest.

## dependency-bump

**Dependency version bump** · info · security

A dependency version changed.

## dependency-unpinned

**Unpinned or URL dependency** · medium · security · [CWE-1104](https://cwe.mitre.org/data/definitions/1104.html)

A dependency floats to any version or installs from a URL.

## missing-tests

**Source changed without test changes** · medium · test

Code changed but no tests changed.

## large-file-change

**Large change in one file** · info · perf

Many added lines in one file.

## large-pr

**Large pull request** · info · perf

Many added lines overall.

## minified-or-generated

**Very long line added** · info · style

Generated or minified content.
