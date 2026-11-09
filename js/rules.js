/* PRSentry rule engine: deterministic, offline checks that only fire on ADDED (+) lines of a diff.
   Every rule is a heuristic. Expect false positives and false negatives; this is not a SAST replacement. */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else (root.PRSentry = root.PRSentry || {}).rules = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';
  const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
  const CATEGORIES = ['security', 'bug', 'perf', 'style', 'test'];
  const LANGS = { js: /\.(m?js|cjs|jsx|ts|tsx|mts|cts|vue|svelte)$/i, py: /\.(py|pyw)$/i, java: /\.(java|kt|scala)$/i, go: /\.go$/i, rb: /\.rb$/i, php: /\.php$/i, cs: /\.cs$/i, sh: /\.(sh|bash|zsh)$/i, c: /\.(c|cc|cpp|h|hpp|rs|swift)$/i, tmpl: /\.(html?|jinja2?|j2|erb|ejs|hbs|blade\.php)$/i };
  const TEST_PATH = /(^|\/)(tests?|__tests__|spec|specs|e2e|fixtures?)\/|\.(test|spec)\.[a-z]+$|_test\.(go|py|rb)$|(^|\/)test_[^/]+\.py$|Tests?\.(java|cs|kt)$/i;
  const DOC_PATH = /\.(md|mdx|rst|txt|adoc)$|(^|\/)(docs?|LICENSE|CHANGELOG)/i;
  const LOCK_PATH = /(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Cargo\.lock|go\.sum|Gemfile\.lock|composer\.lock)$/;
  const MIN_PATH = /\.min\.(js|css)$|(^|\/)(dist|build|vendor)\//;

  function langOf(path) { for (const k of Object.keys(LANGS)) if (LANGS[k].test(path)) return k; return null; }
  function isTest(path) { return TEST_PATH.test(path); }
  function isCommentOnly(text, lang) {
    const t = text.trim();
    if (!t) return false;
    if (/^(\/\/|\/\*|\*|<!--|\{#|--\s|;)/.test(t)) return true;
    if (/^#/.test(t) && lang !== 'c' && !/^#!/.test(t) && lang !== 'js' && lang !== 'cs') return true;
    if (lang === 'py' && /^("""|''')/.test(t)) return true;
    return false;
  }
  /* Blank out string literal contents (keeps quotes) so operators inside strings do not match. */
  function stripStrings(text) {
    return text.replace(/(["'`])(?:\\.|(?!\1).)*\1/g, (m, q) => q + ' '.repeat(Math.max(0, m.length - 2)) + q);
  }
  function stripTrailingComment(text, lang) {
    const s = stripStrings(text);
    const i = lang === 'py' || lang === 'rb' || lang === 'sh' ? s.indexOf('#') : s.search(/\/\/(?!\/)/);
    if (i > 0 && !/:\/\//.test(text.slice(Math.max(0, i - 6), i + 2))) return text.slice(0, i);
    return text;
  }
  function entropy(s) {
    const freq = {}; for (const c of s) freq[c] = (freq[c] || 0) + 1;
    let e = 0; for (const k in freq) { const p = freq[k] / s.length; e -= p * Math.log2(p); }
    return e;
  }
  function envName(v) { return String(v).replace(/([a-z0-9])([A-Z])/g, '$1_$2').replace(/[^A-Za-z0-9]+/g, '_').replace(/^_+|_+$/g, '').toUpperCase() || 'SECRET'; }
  const PLACEHOLDER = /^(x{3,}|\*{3,}|\.{3,}|your[_-]|<|\$\{|\{\{|%\(|process\.env|os\.environ|changeme|change[_-]me|placeholder|dummy|redacted|replace[_-]?me|todo|none|null|undefined|true|false|password|secret|token)$|^(your|my|insert|enter)[_-]/i;
  const USER_INPUT = /\b(req|request)\.(query|params|body|args|form|values|GET|POST|json|files|cookies|headers)\b|\bparams\[|\b(location\.(search|hash|href)|window\.name|document\.(URL|referrer|cookie)|searchParams\.get|event\.data|props\.\w+|userInput|user_input|input\(|sys\.argv|process\.argv)/;
  const SENSITIVE = /\b(pass(word|wd)?|pwd|secret|token|api[_-]?key|apikey|authorization|auth[_-]?header|credit[_-]?card|card[_-]?number|cvv|ssn|private[_-]?key|session[_-]?id|cookie)\b/i;

  /* Rule list. test(text, ctx) returns a match object/array or null; fix(text, m, ctx) returns replacement line(s) or null. */
  const RULES = [
    // ---------------- Secrets (run on every text file, comments included) ----------------
    { id: 'secret-aws-access-key', title: 'Hardcoded AWS access key ID', severity: 'critical', category: 'security', cwe: 'CWE-798', confidence: 0.9, scope: 'text', secret: true,
      test: (t) => /\b((?:AKIA|ASIA)[A-Z0-9]{16})\b/.exec(t),
      explain: 'An AWS access key ID was added to source. Anyone with repo access (or a leaked clone) can use it together with its secret. Revoke the key in IAM, then load credentials from the environment, a role, or a secrets manager.',
      fixNote: 'Rotate the key first: removing it from the diff does not remove it from git history.' },
    { id: 'secret-github-token', title: 'Hardcoded GitHub token', severity: 'critical', category: 'security', cwe: 'CWE-798', confidence: 0.9, scope: 'text', secret: true,
      test: (t) => /\b(gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b/.exec(t),
      explain: 'A GitHub personal access / OAuth / app token was added. Revoke it at github.com/settings/tokens and use a secret store or GITHUB_TOKEN in CI.' },
    { id: 'secret-slack-token', title: 'Hardcoded Slack token or webhook', severity: 'critical', category: 'security', cwe: 'CWE-798', confidence: 0.85, scope: 'text', secret: true,
      test: (t) => /\b(xox[abposr]-[A-Za-z0-9-]{10,})|(hooks\.slack\.com\/services\/[A-Za-z0-9/_-]{12,})/.exec(t),
      explain: 'A Slack bot/user token or incoming-webhook URL was added. Anyone holding it can post to (or read) the workspace. Revoke it in the Slack app settings and load it from configuration.' },
    { id: 'secret-stripe-key', title: 'Hardcoded live payment API key', severity: 'critical', category: 'security', cwe: 'CWE-798', confidence: 0.85, scope: 'text', secret: true,
      test: (t) => /\b((?:sk|rk)_live_[A-Za-z0-9]{16,})\b/.exec(t),
      explain: 'A live secret key for a payments API was added. Roll the key in the provider dashboard and keep it server-side in a secret store.' },
    { id: 'secret-private-key', title: 'Private key committed', severity: 'critical', category: 'security', cwe: 'CWE-321', confidence: 0.95, scope: 'text', secret: true,
      test: (t) => /-----BEGIN ((?:RSA|EC|DSA|OPENSSH|ENCRYPTED|PGP) )?PRIVATE KEY( BLOCK)?-----/.exec(t),
      explain: 'A PEM/OpenSSH private key block was added. Treat the key as compromised: generate a new one and store it outside the repository.' },
    { id: 'secret-generic', title: 'Possible hardcoded credential', severity: 'high', category: 'security', cwe: 'CWE-798', confidence: 0.7, scope: 'text', secret: true,
      test: (t) => {
        const m = /\b([A-Za-z0-9_.-]*(?:secret|passw(?:or)?d|pwd|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?key|credentials?)[A-Za-z0-9_]*)\b["']?\s*(?::=|=|:|=>)\s*(["'`])([^"'`\s]{8,})\2/i.exec(t);
        if (!m) return null;
        const v = m[3];
        if (PLACEHOLDER.test(v) || /^\$|\$\{|\{\{|process\.env|os\.environ|getenv|^https?:\/\/[^@]*$|^\/|\.(js|ts|py|json|ya?ml|html|png|svg)$/.test(v)) return null;
        if (/^[a-z_]+$/.test(v) && v.length < 16) return null; // plain words like "access_token" (field names)
        if (/^[A-Z0-9_]+$/.test(v) && /_/.test(v)) return null; // CONSTANT_NAME references
        if (/(type|kind|name|header|field|label|key_name|param|url|path|mode|scope)$/i.test(m[1])) return null;
        if (entropy(v) < 2.8 && v.length < 20) return null;
        return m;
      },
      fix: (t, m, ctx) => {
        const name = envName(m[1]);
        if (ctx.lang === 'js') return t.replace(m[2] + m[3] + m[2], 'process.env.' + name);
        if (ctx.lang === 'py') return t.replace(m[2] + m[3] + m[2], 'os.environ["' + name + '"]');
        if (ctx.lang === 'go') return t.replace(m[2] + m[3] + m[2], 'os.Getenv("' + name + '")');
        return null;
      },
      explain: 'A credential-like name is assigned a literal value with high randomness. If it is real, rotate it and read it from the environment or a secret manager instead.',
      fixNote: 'If this is a test fixture, move it to a clearly fake value or a fixtures file and mark it.' },
    { id: 'hidden-unicode', title: 'Invisible bidirectional/zero-width characters', severity: 'high', category: 'security', cwe: null, confidence: 0.9, scope: 'text',
      test: (t) => /[\u202A-\u202E\u2066-\u2069\u200B-\u200D\u2060\uFEFF]/.exec(t),
      explain: 'The added line contains invisible Unicode control characters (bidi overrides or zero-width marks). They can make code look different from how it runs ("Trojan Source"). Remove them unless they are intentional text content.',
      fix: (t) => t.replace(/[\u202A-\u202E\u2066-\u2069\u200B-\u200D\u2060\uFEFF]/g, '') },
    // ---------------- Prompt injection aimed at AI reviewers ----------------
    { id: 'prompt-injection', title: 'Text that tries to instruct an AI reviewer', severity: 'high', category: 'security', cwe: 'CWE-1427', confidence: 0.85, scope: 'text', comments: true,
      test: (t) => {
        const pats = [/\bignore (?:all |any |the )?(?:previous|prior|above|earlier|preceding) (?:instructions|prompts?|rules|guidelines|context)/i,
          /\bdisregard (?:all |any |the )?(?:previous|prior|above|system|earlier)\b/i,
          /\b(?:note|message|instructions?|attention|hey) (?:to|for) (?:the |any )?(?:ai|llm|gpt|assistant|automated reviewer|ai reviewer|code reviewer|reviewer bot|copilot|model|language model)\b/i,
          /\b(?:you are|act as|pretend to be) (?:now )?(?:an? |the )?(?:ai|llm|helpful assistant|code reviewer|security reviewer|reviewer|security scanner)\b/i,
          /\b(?:approve|lgtm|auto-?approve|mark (?:as )?(?:safe|approved|secure))\b.{0,40}\b(?:this|the) (?:pr|pull request|change|diff|file|code)\b.{0,60}\b(?:ai|llm|bot|reviewer|model|scanner|assistant)\b/i,
          /\b(?:ai|llm|bot|reviewer|model|scanner|assistant)\b.{0,60}\b(?:must|should|will) (?:approve|not (?:report|flag|mention|comment))\b/i,
          /\bdo not (?:report|flag|mention|comment on|warn about) (?:any |this |these |the )?(?:issues?|findings?|vulnerabilit|security|problems?|secrets?|this)/i,
          /\b(?:system|developer) prompt\b/i, /\[\/?(?:INST|SYSTEM)\]|<\|im_start\|>|<\|im_end\|>|<\/?(?:system|assistant)>/i,
          /\brespond (?:only )?with (?:only )?["'`]?(?:lgtm|approved?|no issues)/i, /\bnew instructions?:/i];
        for (const p of pats) { const m = p.exec(t); if (m) return m; }
        return null;
      },
      explain: 'This added text reads like an instruction to an AI code reviewer (for example "ignore previous instructions" or "approve this PR"). PRSentry fences the diff as untrusted data and never follows instructions inside it, but a human should confirm why it is here. Treat AI-review verdicts on this PR with extra suspicion.',
      fix: () => '', fixNote: 'Remove the instruction text; code comments should talk to humans about the code.' },
    // ---------------- Injection ----------------
    { id: 'sql-injection', title: 'SQL built with string interpolation or concatenation', severity: 'high', category: 'security', cwe: 'CWE-89', confidence: 0.8, scope: 'code',
      test: (t) => {
        if (!/["'`]\s*(?:SELECT\s[\s\S]*?\bFROM\b|INSERT\s+INTO\b|UPDATE\s+[\w."`\[\]]+\s+SET\b|DELETE\s+FROM\b|SELECT\s+\*|[^"'`]*\bWHERE\s+[\w."`]+\s*(?:=|LIKE|IN|>|<))/i.test(t) && !/\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^"'`]*\b(?:FROM|INTO|SET|WHERE)\b/i.test(t)) return null;
        const forms = [/`[^`]*\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b[^`]*\$\{[^}]+\}[^`]*`/i, /\bf(["'])(?:(?!\1).)*\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b(?:(?!\1).)*\{[^}]+\}/i,
          /(["'])[^"']*\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|VALUES|AND|OR|LIKE|=)\b[^"']*\1\s*\+\s*[A-Za-z_$][\w$.\[\]()]*/i, /(["'])[^"']*\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b[^"']*%[sdr][^"']*\1\s*%\s*\(?[\w.]/i,
          /(["'])[^"']*\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b[^"']*\{\d*\}[^"']*\1\s*\.format\(/i, /Sprintf\(\s*"[^"]*\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE)\b[^"]*%[svd]/i, /\$"[^"]*\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE)\b[^"]*\{[^}]+\}/i];
        for (const f of forms) { const m = f.exec(t); if (m) return m; }
        return null;
      },
      fix: (t, m, ctx) => {
        // JS template literal -> placeholders + params array
        let mm = /(\w+(?:\.\w+)*\s*\(\s*)`([^`]*)`(\s*\))/.exec(t);
        if (mm && /\$\{/.test(mm[2])) { const params = []; const sql = mm[2].replace(/(['"]?)\$\{([^}]+)\}\1/g, (_, q, e) => { params.push(e.trim()); return '?'; }); return t.replace(mm[0], mm[1] + "'" + sql.replace(/'/g, "\\'") + "', [" + params.join(', ') + ']' + mm[3]); }
        mm = /(\w+(?:\.\w+)*\s*\(\s*)f(["'])(.*?)\2(\s*\))/.exec(t);
        if (mm) { const params = []; const sql = mm[3].replace(/(['"]?)\{([^}]+)\}\1/g, (_, q, e) => { params.push(e.trim()); return '%s'; }); return t.replace(mm[0], mm[1] + mm[2] + sql + mm[2] + ', (' + params.join(', ') + (params.length === 1 ? ',' : '') + ')' + mm[4]); }
        return null;
      },
      explain: 'User-controlled values appear to be spliced into a SQL string. An attacker who controls the value can change the query (read other rows, bypass auth, drop tables). Use parameterized queries / prepared statements and let the driver escape values.',
      fixNote: 'Placeholder style depends on the driver: ? (mysql, sqlite), $1 (pg), %s (psycopg/MySQLdb), :name (SQLAlchemy).' },
    { id: 'command-injection', title: 'Shell command built from variable input', severity: 'high', category: 'security', cwe: 'CWE-78', confidence: 0.75, scope: 'code',
      test: (t, ctx) => {
        const s = stripStrings(t);
        if (ctx.lang === 'py') {
          if (/\bsubprocess\.\w+\(.*\bshell\s*=\s*True/.test(t)) return /\bsubprocess\.\w+\(/.exec(t);
          const m = /\bos\.(system|popen)\(\s*(?!(["'])[^"']*\2\s*\))/.exec(t); if (m) return m;
          return /\bcommands\.getoutput\(/.exec(t);
        }
        if (ctx.lang === 'js') {
          const m = /(?:(?<![\w$.])|\b(?:child_process|childProcess|cp|proc)\.)(exec|execSync)\s*\(\s*(`[^`]*\$\{|["'][^"']*["']\s*\+|[A-Za-z_$][\w$.]*\s*[,)+])/.exec(t);
          if (m && !/\bexec\s*\(\s*(?:\/|[A-Za-z_$][\w$]*(?:Re|Regex|Pattern|RE|_re)\b)/.test(t)) return m;
          if (/\bspawn(?:Sync)?\(.*\bshell\s*:\s*true/.test(s)) return /\bspawn/.exec(t);
          return null;
        }
        if (ctx.lang === 'java') return /Runtime\.getRuntime\(\)\.exec\(\s*(?!"[^"]*"\s*\))/.exec(t) || /new ProcessBuilder\(\s*"(?:sh|bash|cmd)"\s*,\s*"(?:-c|\/c)"/.exec(t);
        if (ctx.lang === 'go') return /exec\.Command(?:Context)?\((?:ctx,\s*)?"(?:sh|bash|cmd)"\s*,\s*"(?:-c|\/c)"/.exec(t);
        if (ctx.lang === 'php') return /\b(shell_exec|system|passthru|exec|popen|proc_open)\s*\(\s*(?!["'][^"']*["']\s*\))/.exec(t);
        if (ctx.lang === 'rb') return /\b(system|exec|%x)\s*\(?\s*["'][^"']*#\{/.exec(t) || /`[^`]*#\{[^}]+\}[^`]*`/.exec(t);
        return null;
      },
      fix: (t, m, ctx) => {
        if (ctx.lang === 'py' && /shell\s*=\s*True/.test(t)) return t.replace(/shell\s*=\s*True/, 'shell=False');
        if (ctx.lang === 'js' && /spawn.*shell\s*:\s*true/.test(t)) return t.replace(/shell\s*:\s*true/, 'shell: false');
        return null;
      },
      explain: 'A command string is executed through a shell with a non-constant value. If any part comes from a user, file name, branch name or request, shell metacharacters (; | $( ) let an attacker run arbitrary commands. Call the program directly with an argument array (execFile / spawn without shell / subprocess.run([...])).',
      fixNote: 'With shell disabled, pass the command as a list of arguments, e.g. subprocess.run(["git", "log", ref]) or execFile("git", ["log", ref]).' },
    { id: 'code-eval', title: 'Dynamic code evaluation', severity: 'high', category: 'security', cwe: 'CWE-95', confidence: 0.8, scope: 'code',
      test: (t, ctx) => {
        const s = stripStrings(t);
        if (ctx.lang === 'py') return /(?<![\w.])(eval|exec)\s*\((?!\s*\))/.exec(s) || /\bcompile\(\s*[A-Za-z_]\w*\s*,/.exec(s);
        if (ctx.lang === 'js') return /(?<![\w$.])eval\s*\(/.exec(s) || /\bnew\s+Function\s*\(/.exec(s) || /\b(setTimeout|setInterval)\s*\(\s*(["'`])/.exec(s) || /\bvm\.run(?:InNewContext|InThisContext|InContext)\(/.exec(s);
        if (ctx.lang === 'php' || ctx.lang === 'rb') return /(?<![\w.$])(eval|instance_eval|class_eval|create_function|assert)\s*\(\s*\$?[A-Za-z_]/.exec(s);
        return null;
      },
      fix: (t, m, ctx) => {
        if (ctx.lang === 'js' && /(?<![\w$.])eval\s*\(/.test(t) && /json|body|data|text|payload|response|str/i.test(t)) return t.replace(/(?<![\w$.])eval\s*\(/, 'JSON.parse(');
        if (ctx.lang === 'py' && /(?<![\w.])eval\s*\(/.test(t)) return t.replace(/(?<![\w.])eval\s*\(/, 'ast.literal_eval(');
        return null;
      },
      explain: 'Evaluating a string as code lets anyone who influences that string run arbitrary code in your process. Parse data with a real parser (JSON.parse, ast.literal_eval) or dispatch through an allow-list of functions.' },
    { id: 'unsafe-deserialization', title: 'Unsafe deserialization of untrusted data', severity: 'high', category: 'security', cwe: 'CWE-502', confidence: 0.8, scope: 'code',
      test: (t, ctx) => {
        if (ctx.lang === 'py') return /\b(?:c?[Pp]ickle|dill|shelve|marshal|jsonpickle)\.(?:loads?|Unpickler|open|decode)\(/.exec(t) || /\byaml\.(?:unsafe_load|full_load)\(/.exec(t) || (/\byaml\.load(?:_all)?\(/.test(t) && !/Loader\s*=\s*(?:yaml\.)?(?:C?SafeLoader|BaseLoader)/.test(t) ? /\byaml\.load(?:_all)?\(/.exec(t) : null) || (/\btorch\.load\(/.test(t) && !/weights_only\s*=\s*True/.test(t) ? /\btorch\.load\(/.exec(t) : null) || /\bpandas\.read_pickle\(|\bpd\.read_pickle\(/.exec(t);
        if (ctx.lang === 'java') return /\bnew\s+ObjectInputStream\(|\.readObject\(\)|\bXMLDecoder\(|enableDefaultTyping\(|new\s+XStream\(/.exec(t);
        if (ctx.lang === 'php') return /\bunserialize\s*\(/.exec(t);
        if (ctx.lang === 'rb') return /\bMarshal\.load\(|\bYAML\.load\((?![^)]*permitted_classes)|\bYAML\.unsafe_load\(/.exec(t);
        if (ctx.lang === 'js') return /\b(?:serialize|node-serialize|funcster)\.unserialize\(|\byaml\.load\(.*schema\s*:\s*\w*(?:DEFAULT_FULL|unsafe)/i.exec(t);
        if (ctx.lang === 'cs') return /\bBinaryFormatter\(|\bNetDataContractSerializer\(|TypeNameHandling\.(?:All|Auto|Objects)/.exec(t);
        return null;
      },
      fix: (t, m, ctx) => {
        if (ctx.lang === 'py' && /\byaml\.load\(/.test(t)) return t.replace(/\byaml\.load\(/, 'yaml.safe_load(');
        if (ctx.lang === 'py' && /\byaml\.(unsafe|full)_load\(/.test(t)) return t.replace(/\byaml\.(unsafe|full)_load\(/, 'yaml.safe_load(');
        if (ctx.lang === 'py' && /\btorch\.load\(/.test(t)) return t.replace(/\btorch\.load\(([^)]*)\)/, (all, a) => 'torch.load(' + a + (a.trim() ? ', ' : '') + 'weights_only=True)');
        return null;
      },
      explain: 'This deserializer can construct arbitrary objects (and often run code) from its input. If the bytes can come from a user, cache, queue or upload, that is remote code execution. Use a data-only format (JSON, yaml.safe_load) or a signed, schema-validated payload.' },
    { id: 'xss-sink', title: 'HTML injection sink (possible XSS)', severity: 'medium', category: 'security', cwe: 'CWE-79', confidence: 0.75, scope: 'code',
      test: (t, ctx) => {
        if (ctx.lang === 'js' || ctx.lang === 'tmpl') {
          let m = /\.(innerHTML|outerHTML)\s*\+?=\s*(.+)$/.exec(t);
          if (m && !/^\s*(["'`])[^"'`$]*\1\s*;?\s*$/.test(m[2])) return m;
          m = /\binsertAdjacentHTML\s*\(|\bdangerouslySetInnerHTML\s*=\s*\{|\bdocument\.write(?:ln)?\s*\(|\bv-html\s*=|\$\([^)]*\)\.(?:html|append|prepend|after|before)\(\s*(?!["'`][^"'`$]*["'`]\s*\))[A-Za-z_$`]|\{\{\{[^}]+\}\}\}|<%-\s*[^%]+%>|\|\s*safe\b|\bbypassSecurityTrust\w*\(/.exec(t);
          return m;
        }
        if (ctx.lang === 'py') return /\bmark_safe\(|\bMarkup\((?!\s*["'][^"']*["']\s*\))|\|\s*safe\b|render_template_string\(/.exec(t);
        if (ctx.lang === 'php') return /\becho\s+\$_(?:GET|POST|REQUEST|COOKIE)\b/.exec(t);
        if (ctx.lang === 'rb') return /\.html_safe\b|\braw\(/.exec(t);
        return null;
      },
      severityFor: (t) => USER_INPUT.test(t) || /\b(query|search|comment|bio|message|name|title|description|content|html|markup)\b/i.test(t) ? 'high' : 'medium',
      fix: (t) => {
        if (/\.innerHTML\s*=/.test(t) && !/</.test(t.split(/innerHTML\s*=/)[1] || '')) return t.replace(/\.innerHTML\s*=/, '.textContent =');
        const m = /dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*([^}]+?)\s*\}\}/.exec(t);
        if (m && !/sanitize/i.test(m[1])) return t.replace(m[0], 'dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(' + m[1] + ') }}');
        return null;
      },
      explain: 'A value is written into the page as HTML. If any part comes from a user, URL, API or database, it can inject <script> or event-handler markup (stored or reflected XSS). Render text with textContent / JSX children, or sanitize with a vetted library (DOMPurify) before inserting HTML.',
      fixNote: 'Sanitizing needs an import (e.g. import DOMPurify from "dompurify"). Prefer plain text rendering if the content does not need markup.' },
    { id: 'path-traversal', title: 'File path built from request input', severity: 'high', category: 'security', cwe: 'CWE-22', confidence: 0.7, scope: 'code',
      test: (t, ctx) => {
        const fileCall = /\b(readFile(?:Sync)?|createReadStream|createWriteStream|writeFile(?:Sync)?|appendFile(?:Sync)?|unlink(?:Sync)?|rm(?:Sync)?|readdir(?:Sync)?|sendFile|download|open|send_file|send_from_directory|FileInputStream|FileReader|File|Path\.of|Paths\.get|os\.remove|shutil\.rmtree|fopen|file_get_contents|include|require_once|os\.path\.join|path\.(?:join|resolve))\s*\(/;
        if (!fileCall.test(t)) return null;
        if (USER_INPUT.test(t) || /\$_(?:GET|POST|REQUEST)\b/.test(t)) return fileCall.exec(t);
        const tainted = ctx.taintedVars(); if (!tainted.length) return null;
        const args = t.slice(t.search(fileCall));
        for (const v of tainted) if (new RegExp('\\b' + v.replace(/[$]/g, '\\$') + '\\b').test(args)) return fileCall.exec(t);
        return null;
      },
      explain: 'A filesystem path includes a value that comes from the request. Inputs like "../../etc/passwd" or absolute paths can escape the intended directory. Resolve the final path and check it is still inside an allowed base directory, or map user input to an allow-list of file names.',
      fixNote: 'Node: const p = path.resolve(BASE, name); if (!p.startsWith(BASE + path.sep)) throw ... | Python: p = (BASE / name).resolve(); p.relative_to(BASE)' },
    { id: 'ssrf', title: 'Server-side request to a user-supplied URL (SSRF)', severity: 'medium', category: 'security', cwe: 'CWE-918', confidence: 0.65, scope: 'code',
      test: (t, ctx) => {
        const call = /\b(fetch|axios(?:\.(?:get|post|put|request))?|got(?:\.(?:get|post))?|needle|superagent\.get|https?\.(?:get|request)|requests\.(?:get|post|put|request|head)|httpx\.(?:get|post|request|AsyncClient\(\)\.get)|urlopen|urllib\.request\.urlopen|http\.Get|http\.NewRequest|HttpClient\.\w+|RestTemplate\.\w+|WebClient\.\w+|open-uri|Net::HTTP\.get|curl_init)\s*\(/;
        if (!call.test(t)) return null;
        if (ctx.lang === 'js' && ctx.isClient) return null;
        const after = t.slice(t.search(call));
        if (USER_INPUT.test(after) && !/^\s*fetch\(\s*["'`]\//.test(after)) return call.exec(t);
        for (const v of ctx.taintedVars()) if (new RegExp('\\(\\s*[`"\']?[^,)]*\\b' + v.replace(/[$]/g, '\\$') + '\\b').test(after)) return call.exec(t);
        return null;
      },
      explain: 'The server fetches a URL that comes from the request. Attackers can point it at internal services (cloud metadata at 169.254.169.254, localhost admin ports, private networks). Allow-list hosts and schemes, resolve DNS and block private ranges, and do not follow redirects blindly.' },
    // ---------------- Crypto / transport / auth ----------------
    { id: 'weak-hash', title: 'Weak hash algorithm (MD5/SHA-1)', severity: 'medium', category: 'security', cwe: 'CWE-328', confidence: 0.75, scope: 'code',
      test: (t) => /\bcreateHash\(\s*["'](md5|sha1)["']|\bhashlib\.(md5|sha1)\(|\bhashlib\.new\(\s*["'](md5|sha1)["']|MessageDigest\.getInstance\(\s*"(MD5|SHA-?1)"|(?<![\w.])(md5|sha1)\s*\(|\bDigest::(MD5|SHA1)\b|\bmd5\.New\(|\bsha1\.New\(|\b(MD5|SHA1)\.Create\(/i.exec(t),
      severityFor: (t, ctx) => /etag|checksum|cache|fingerprint|dedupe|non-?crypto|usedforsecurity\s*=\s*False/i.test(t) ? 'low' : /pass|pwd/i.test(ctx.around(1)) ? 'high' : 'medium',
      cweFor: (t, ctx) => !/etag|checksum|cache|fingerprint/i.test(t) && /pass|pwd/i.test(ctx.around(1)) ? 'CWE-916' : 'CWE-328',
      fix: (t, m, ctx) => {
        if (!/etag|checksum|cache|fingerprint/i.test(t) && /pass|pwd/i.test(ctx.around(1))) return null;
        return t.replace(/(["'])(md5|sha1)\1/i, '$1sha256$1').replace(/\bhashlib\.(md5|sha1)\(/, 'hashlib.sha256(').replace(/"(MD5|SHA-?1)"/, '"SHA-256"');
      },
      explain: 'MD5 and SHA-1 are broken for collision resistance and far too fast for password storage. Use SHA-256+ for integrity, HMAC for authentication, and a slow password hash (argon2id, bcrypt, scrypt) for passwords.',
      fixNote: 'For passwords use bcrypt/argon2 (e.g. bcrypt.hash(password, 12) or argon2.hash(password)) rather than a faster digest.' },
    { id: 'insecure-random', title: 'Non-cryptographic random used for a secret value', severity: 'medium', category: 'security', cwe: 'CWE-338', confidence: 0.7, scope: 'code',
      test: (t, ctx) => {
        const m = ctx.lang === 'js' ? /\bMath\.random\(\)/.exec(t) : ctx.lang === 'py' ? /\brandom\.(random|randint|randrange|choice|choices|getrandbits|sample)\(/.exec(t) : ctx.lang === 'java' ? /\bnew Random\(|\bMath\.random\(\)/.exec(t) : ctx.lang === 'go' ? /\bmath\/rand\b|\brand\.(Intn|Int63|Read)\(/.exec(t) : ctx.lang === 'php' ? /\b(rand|mt_rand|uniqid)\(/.exec(t) : null;
        if (!m) return null;
        return /token|secret|passw|nonce|salt|otp|session|api[_-]?key|reset|invite|verification|csrf|auth|code\b|uuid|\bid\b/i.test(t) ? m : null;
      },
      fix: (t, m, ctx) => {
        if (ctx.lang === 'js') { const c = /Math\.random\(\)\.toString\(\d+\)(?:\.(?:slice|substr|substring)\([^)]*\))*/.exec(t); if (c) return t.replace(c[0], 'crypto.randomUUID()'); }
        if (ctx.lang === 'py') { const c = /''\.join\(\s*random\.choices?\([^)]*\)(?:\s*for[^)]*)?\)|random\.getrandbits\(\d+\)/.exec(t); if (c) return t.replace(c[0], 'secrets.token_urlsafe(32)'); }
        return null;
      },
      explain: 'Math.random()/random.* are predictable pseudo-random generators. Tokens, reset codes, session IDs and salts generated with them can be guessed. Use a CSPRNG: crypto.randomUUID() / crypto.getRandomValues() in JS, the secrets module in Python, SecureRandom in Java, crypto/rand in Go.' },
    { id: 'tls-verify-disabled', title: 'TLS certificate verification disabled', severity: 'high', category: 'security', cwe: 'CWE-295', confidence: 0.9, scope: 'code',
      test: (t) => /\brejectUnauthorized\s*:\s*false|\bverify\s*=\s*False\b|NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*["']?0|\bInsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFY(?:PEER|HOST)\s*,\s*(?:false|0)\b|\bssl\._create_unverified_context\b|\bcheck_hostname\s*=\s*False|\bstrictSSL\s*:\s*false|\bverify_mode\s*=\s*OpenSSL::SSL::VERIFY_NONE|\bCERT_NONE\b|ServerCertificateValidationCallback\s*=.*=>\s*true|\bk(?:ubectl)?.*--insecure-skip-tls-verify|\bcurl\b.*\s(?:-k|--insecure)\b/.exec(t),
      fix: (t) => {
        const r = t.replace(/rejectUnauthorized\s*:\s*false/, 'rejectUnauthorized: true').replace(/\bverify\s*=\s*False\b/, 'verify=True').replace(/InsecureSkipVerify\s*:\s*true/, 'InsecureSkipVerify: false').replace(/strictSSL\s*:\s*false/, 'strictSSL: true').replace(/check_hostname\s*=\s*False/, 'check_hostname = True');
        return r !== t ? r : null;
      },
      explain: 'Turning off certificate verification makes the connection trivially interceptable (anyone on the network path can impersonate the server and read or change traffic). Fix the trust store instead: pass the internal CA bundle (ca: / verify="/path/ca.pem").' },
    { id: 'cors-wildcard', title: 'CORS allows any origin', severity: 'medium', category: 'security', cwe: 'CWE-942', confidence: 0.75, scope: 'code',
      test: (t) => /Access-Control-Allow-Origin["']?\s*[,:]\s*["']\*["']|\borigin\s*:\s*(?:["']\*["']|true\b)|\bcors\(\s*\)|CORS_(?:ORIGIN_ALLOW_ALL|ALLOW_ALL_ORIGINS)\s*=\s*True|allow_origins\s*=\s*\[\s*["']\*["']\s*\]|AllowAnyOrigin\(\)|AllowedOrigins\s*:\s*\[\]string\{\s*"\*"|add_header\s+Access-Control-Allow-Origin\s+["']?\*/.exec(t),
      severityFor: (t, ctx) => /credentials\s*[:=]\s*(true|True)|allow_credentials\s*=\s*True|AllowCredentials/.test(ctx.around(3)) ? 'high' : 'medium',
      fix: (t) => { const r = t.replace(/(origin\s*:\s*)(["'])\*\2/, "$1['https://app.example.com']").replace(/(Access-Control-Allow-Origin["']?\s*,\s*)(["'])\*\2/, '$1$2https://app.example.com$2'); return r !== t ? r : null; },
      explain: 'Any website can call this endpoint from a visitor\'s browser and read the response. Combined with cookies or credentials that is a data-exfiltration hole; even without them it exposes internal APIs. Allow-list the exact origins that need access.' },
    { id: 'jwt-insecure', title: 'JWT signature not verified / alg none', severity: 'high', category: 'security', cwe: 'CWE-347', confidence: 0.8, scope: 'code',
      test: (t, ctx) => {
        const m = /algorithms?\s*[:=]\s*\[?\s*["']none["']|["']alg["']\s*:\s*["']none["']|verify_signature["']?\s*:\s*False|\bjwt\.decode\([^)]*verify\s*=\s*False|\bignoreExpiration\s*:\s*true|\bverify_exp["']?\s*:\s*False/i.exec(t);
        if (m) return m;
        if (ctx.lang === 'js' && /\bjwt\.decode\(/.test(t) && /\b(user|auth|role|admin|claims|payload|session|req\.)/i.test(ctx.around(2)) && !/complete\s*:\s*true/.test(t)) return /\bjwt\.decode\(/.exec(t);
        return null;
      },
      fix: (t, m, ctx) => {
        if (ctx.lang === 'js' && /\bjwt\.decode\(\s*([^,)]+)\s*\)/.test(t)) return t.replace(/\bjwt\.decode\(\s*([^,)]+)\s*\)/, 'jwt.verify($1, process.env.JWT_SECRET, { algorithms: [\'HS256\'] })');
        const r = t.replace(/verify_signature(["']?)\s*:\s*False/, 'verify_signature$1: True').replace(/ignoreExpiration\s*:\s*true/, 'ignoreExpiration: false');
        return r !== t ? r : null;
      },
      explain: 'The token is accepted without checking its signature (or with the "none" algorithm / expiry checks off). Anyone can forge a token with any user ID or role. Always verify with a fixed algorithm allow-list and the expected key, issuer and audience.' },
    // ---------------- Bugs ----------------
    { id: 'floating-promise', title: 'Async call without await (floating promise)', severity: 'medium', category: 'bug', cwe: null, confidence: 0.65, scope: 'code',
      test: (t, ctx) => {
        if (ctx.lang !== 'js' && ctx.lang !== 'py') return null;
        if (/^\s*(await|return|yield|void|throw|export|async|function|def|const|let|var|if|else|for|while|\}|\.|\))/.test(t)) return null;
        if (/\.(then|catch|finally)\(/.test(t)) return null;
        const names = ctx.asyncNames();
        const m = /^\s*((?:this\.|self\.|await\s+)?([A-Za-z_$][\w$]*)\s*\((.*)\))\s*;?\s*$/.exec(t);
        if (m && (names.has(m[2]) || (ctx.lang === 'js' && m[2] === 'fetch'))) return m;
        if (ctx.lang === 'js') { const fe = /\.forEach\(\s*async\b/.exec(t); if (fe) return Object.assign(fe, { isForEach: true }); }
        return null;
      },
      titleFor: (m) => (m.isForEach ? 'forEach with an async callback does not wait' : null),
      fix: (t, m) => (m.isForEach ? null : t.replace(/^(\s*)/, '$1await ')),
      explain: 'This calls an async function but nothing waits for it. Errors become unhandled rejections, and the code after it runs before the work is done (e.g. responding before the record is saved). Await it, return it, or explicitly fire-and-forget with error handling.',
      fixNote: 'For forEach(async ...), use for (const x of items) { await work(x); } or await Promise.all(items.map(work)).' },
    { id: 'loose-equality', title: 'Loose equality (==) coerces types', severity: 'low', category: 'bug', cwe: 'CWE-1025', confidence: 0.6, scope: 'code',
      test: (t, ctx) => {
        const s = stripStrings(stripTrailingComment(t, ctx.lang));
        if (ctx.lang === 'js') {
          const nan = /[=!]==?\s*NaN\b|\bNaN\s*[=!]==?/.exec(s); if (nan) return Object.assign(nan, { nan: true });
          const m = /[^=!<>]([=!]=)(?!=)\s*(?!null\b|undefined\b)([^\s=])/.exec(s); if (m && !/\b(?:null|undefined)\s*[=!]=(?!=)/.test(s.slice(Math.max(0, m.index - 12), m.index + 3))) return m;
          return null;
        }
        if (ctx.lang === 'py') { const m = /([=!]=)\s*None\b/.exec(s); return m ? Object.assign(m, { pyNone: true }) : null; }
        return null;
      },
      titleFor: (m) => (m.nan ? 'Comparison with NaN is always false' : m.pyNone ? 'Compare to None with "is"' : null),
      severityFor: (t, ctx, m) => (m && m.nan ? 'medium' : 'low'),
      categoryFor: (m) => (m && m.pyNone ? 'style' : 'bug'),
      fix: (t, m, ctx) => {
        if (m.nan) { const r = t.replace(/([\w$.\[\]]+)\s*[=!]==?\s*NaN\b/, (a, x) => (/!/.test(a) ? '!' : '') + 'Number.isNaN(' + x + ')'); return r !== t ? r : null; }
        if (m.pyNone) return t.replace(/==\s*None\b/, 'is None').replace(/!=\s*None\b/, 'is not None');
        let done = false; return t.replace(/([^=!<>])([=!]=)(?!=)(\s*)(?!null\b|undefined\b)/, (a, p, op, sp) => { if (done) return a; done = true; return p + op + '=' + sp; });
      },
      explain: '== and != convert types before comparing ("0" == 0, [] == false, "" == 0 are all true), which hides bugs. Use === / !== unless you deliberately want the x == null check for both null and undefined.' },
    { id: 'off-by-one', title: 'Likely off-by-one bound', severity: 'medium', category: 'bug', cwe: 'CWE-193', confidence: 0.7, scope: 'code',
      test: (t, ctx) => {
        if (ctx.lang === 'py') return /\brange\(\s*(?:0\s*,\s*)?len\(([^)]+)\)\s*\+\s*1\s*\)/.exec(t) || /(\w+)\[\s*len\(\s*\1\s*\)\s*\]/.exec(t);
        return /\bfor\s*\([^;]*;\s*[\w$]+\s*<=\s*[\w$.]+\.(?:length|size\(\)|Count|Length|count\(\))\s*;/.exec(t) || /([\w$.]+)\[\s*\1\.length\s*\]/.exec(t);
      },
      fix: (t, m, ctx) => {
        if (ctx.lang === 'py') return t.replace(/\brange\(\s*((?:0\s*,\s*)?)len\(([^)]+)\)\s*\+\s*1\s*\)/, 'range($1len($2))').replace(/(\w+)\[\s*len\(\s*\1\s*\)\s*\]/, '$1[-1]');
        return t.replace(/(;\s*[\w$]+\s*)<=(\s*[\w$.]+\.(?:length|size\(\)|Count|Length|count\(\))\s*;)/, '$1<$2').replace(/([\w$.]+)\[\s*\1\.length\s*\]/, '$1[$1.length - 1]');
      },
      explain: 'Indexes run from 0 to length - 1. Iterating while i <= length (or indexing at [length]) reads one element past the end: undefined in JS, IndexError in Python, an exception in Java/C#.' },
    { id: 'swallowed-error', title: 'Error caught and silently ignored', severity: 'medium', category: 'bug', cwe: 'CWE-390', confidence: 0.75, scope: 'code',
      test: (t, ctx) => {
        if (ctx.lang === 'py') { if (/^\s*except\b[^:]*:\s*(pass|\.\.\.)\s*$/.test(t)) return /except/.exec(t); if (/^\s*except\b[^:]*:\s*$/.test(t) && /^\s*(pass|\.\.\.)\s*$/.test(ctx.next(1))) return /except/.exec(t); return null; }
        return /\bcatch\s*(?:\(\s*[\w$:\s<>]*\s*\))?\s*\{\s*(?:\/\/[^}]*)?\}|\.catch\(\s*(?:\(\s*\w*\s*\)|\w+)\s*=>\s*(?:\{\s*\}|null|undefined|void 0)\s*\)|\.catch\(\s*function\s*\(\s*\w*\s*\)\s*\{\s*\}\s*\)|\bif\s+err\s*!=\s*nil\s*\{\s*\}|\brescue\b[^\n]*;\s*end|_\s*=\s*err\b/.exec(t);
      },
      fix: (t, m, ctx) => {
        if (ctx.lang === 'py' && /:\s*pass\s*$/.test(t)) return t.replace(/except\s*:/, 'except Exception:').replace(/:\s*pass\s*$/, ':  # noqa: handle or re-raise\n' + t.match(/^\s*/)[0] + '    logger.exception("Unexpected error")');
        if (ctx.lang === 'js') { const r = t.replace(/\bcatch\s*\{\s*\}/, 'catch (err) { console.error(err); }').replace(/\bcatch\s*\(\s*([\w$]+)\s*\)\s*\{\s*\}/, 'catch ($1) { console.error($1); }').replace(/\.catch\(\s*\(\s*\w*\s*\)\s*=>\s*\{\s*\}\s*\)/, '.catch((err) => console.error(err))'); return r !== t ? r : null; }
        return null;
      },
      explain: 'The error is caught and dropped, so failures disappear without a log, metric or retry, and the code continues in a half-finished state. Log it, re-throw it, or handle the specific error you expect.' },
    { id: 'bare-except', title: 'Bare except catches everything (incl. KeyboardInterrupt)', severity: 'low', category: 'bug', cwe: 'CWE-396', confidence: 0.7, scope: 'code',
      test: (t, ctx) => (ctx.lang === 'py' && /^\s*except\s*:/.test(t) && !/:\s*(pass|\.\.\.)\s*$/.test(t) && !/^\s*(pass|\.\.\.)\s*$/.test(ctx.next(1)) ? /except/.exec(t) : null),
      fix: (t) => t.replace(/except\s*:/, 'except Exception:'),
      explain: 'A bare except also catches SystemExit and KeyboardInterrupt and hides programming errors. Catch the specific exceptions you expect, or at least Exception.' },
    { id: 'focused-or-skipped-test', title: 'Focused or skipped test added', severity: 'medium', category: 'test', cwe: null, confidence: 0.85, scope: 'code',
      test: (t) => /\b(?:describe|it|test|context)\.(only|skip)\s*\(|\b(?:fit|fdescribe|xit|xdescribe|xtest)\s*\(|@pytest\.mark\.skip\b|@unittest\.skip\b|@Disabled\b|@Ignore\b|\bt\.Skip\(/.exec(t),
      fix: (t) => { const r = t.replace(/\b(describe|it|test|context)\.(only|skip)\s*\(/, '$1(').replace(/\b(?:f|x)(it|describe|test)\s*\(/, '$1('); return r !== t ? r : null; },
      explain: '.only makes the runner skip every other test (CI goes green while most tests never run); .skip/xit/@skip silently drops coverage. Remove it before merging or link an issue explaining why.' },
    // ---------------- Hygiene / style ----------------
    { id: 'sensitive-log', title: 'Sensitive value written to logs', severity: 'high', category: 'security', cwe: 'CWE-532', confidence: 0.7, scope: 'code',
      test: (t) => { const m = /\b(console\.(?:log|info|debug|warn|error)|print|logger?\.\w+|logging\.\w+|log\.\w+|System\.out\.println|fmt\.Print\w*|puts)\s*\((.*)$/.exec(t); if (!m) return null; const args = m[2].replace(/(["'`])(?:\\.|(?!\1).)*\1/g, (s) => (/\$\{|\{[^}]+\}/.test(s) ? s : '""')); return SENSITIVE.test(args) ? m : null; },
      fix: () => '',
      explain: 'Passwords, tokens, keys or card data in logs end up in log aggregators, support tickets and backups with weaker access control. Log an identifier or a redacted value instead.' },
    { id: 'debug-leftover', title: 'Debug statement left in code', severity: 'low', category: 'style', cwe: 'CWE-489', confidence: 0.6, scope: 'code', skipTests: true,
      test: (t, ctx) => {
        if (/^\s*debugger\s*;?\s*$/.test(t)) return Object.assign(/debugger/.exec(t), { strong: true });
        if (/\b(?:i?pdb\.set_trace|breakpoint)\(\)|\bbinding\.pry\b|\bbyebug\b|\bvar_dump\(|\bdd\(/.test(t)) return Object.assign(/\S+/.exec(t), { strong: true });
        if (ctx.lang === 'js' && !/(^|\/)(scripts?|bin|cli)\//.test(ctx.path)) return /\bconsole\.(log|debug|trace|dir|table)\(/.exec(t);
        if (ctx.lang === 'java') return /\bSystem\.out\.print(?:ln)?\(|\.printStackTrace\(\)/.exec(t);
        if (ctx.lang === 'py' && !/(^|\/)(scripts?|bin|cli|manage\.py|__main__)/.test(ctx.path) && /^\s*print\(/.test(t)) return Object.assign(/print\(/.exec(t), { weak: true });
        return null;
      },
      severityFor: (t, ctx, m) => (m && m.strong ? 'medium' : 'low'),
      confidenceFor: (m) => (m && m.strong ? 0.9 : m && m.weak ? 0.4 : 0.6),
      fix: () => '',
      explain: 'Debug output and breakpoints left in production code leak internal data into consoles/logs, add noise, and a debugger/breakpoint() call can hang a server. Remove it or use the project logger at an appropriate level.' },
    { id: 'todo-added', title: 'TODO/FIXME added', severity: 'info', category: 'style', cwe: 'CWE-546', confidence: 0.9, scope: 'text', comments: true,
      test: (t, ctx) => (DOC_PATH.test(ctx.path) ? null : /\b(TODO|FIXME|HACK|XXX)\b[:(]?/.exec(t)),
      explain: 'A new TODO/FIXME marks unfinished work. Make sure it is tracked (link an issue) so it does not ship as a silent gap.' },
    // ---------------- Performance ----------------
    { id: 'await-in-loop', title: 'Sequential await inside a loop', severity: 'low', category: 'perf', cwe: null, confidence: 0.5, scope: 'code',
      test: (t, ctx) => { if (ctx.lang !== 'js' && ctx.lang !== 'py') return null; if (!/^\s*(?:const|let|var|[\w$.]+\s*=|return\s+)?\s*await\s+/.test(t) && !/=\s*await\s+/.test(t)) return null; return ctx.inLoop() ? /await/.exec(t) : null; },
      explain: 'Each iteration waits for the previous request to finish, so N items take N round-trips. If the calls are independent, batch them or run them with Promise.all / asyncio.gather (with a concurrency limit).' },
    { id: 'query-in-loop', title: 'Database/API call inside a loop (N+1)', severity: 'low', category: 'perf', cwe: 'CWE-1050', confidence: 0.5, scope: 'code',
      test: (t, ctx) => (/\.(query|execute|findOne|findById|findUnique|objects\.get|objects\.filter|get_object_or_404|select|fetchone)\(|\bdb\.\w+\(|\bcursor\.execute\(/.test(t) && ctx.inLoop() ? /\.(\w+)\(/.exec(t) : null),
      explain: 'A query runs once per loop iteration (the N+1 pattern). With many rows this multiplies latency and database load. Fetch in one query (IN (...), JOIN, select_related/prefetch_related, batch loader).' }
  ];

  /* Dependency manifest checks (added/bumped/unpinned). */
  function dependencyFindings(file, hunkCtx) {
    const out = [];
    const p = file.path; const base = p.split('/').pop();
    const kinds = { 'package.json': 'npm', 'requirements.txt': 'pip', 'go.mod': 'go', 'Cargo.toml': 'cargo', Gemfile: 'gem', 'pyproject.toml': 'pip', 'composer.json': 'composer' };
    const eco = kinds[base] || (/requirements[\w.-]*\.txt$/.test(base) ? 'pip' : null);
    if (!eco) return out;
    for (const h of file.hunks) {
      const removed = new Map();
      const parse = (text) => {
        let m;
        if (eco === 'npm' || eco === 'composer') { m = /^\s*"(@?[\w.\-/]+)"\s*:\s*"([^"]*)"\s*,?\s*$/.exec(text); if (m && !/^(name|version|description|main|module|type|license|author|private|scripts?|test|build|start|homepage|repository|engines|node|php)$/.test(m[1]) && /^[\^~<>=*\dvlgfhn]|^latest$|^(git|github|https?|file|link):/.test(m[2])) return { name: m[1], ver: m[2] }; return null; }
        if (eco === 'pip') { if (/^\s*(#|-|$)/.test(text)) return null; m = /^\s*([A-Za-z0-9][\w.\-\[\]]*)\s*((?:==|>=|<=|~=|!=|>|<)\s*[\w.*]+)?/.exec(text); if (base === 'pyproject.toml') { m = /^\s*"([A-Za-z0-9][\w.\-\[\]]*)\s*((?:==|>=|<=|~=|>|<)[^"]*)?"\s*,?\s*$/.exec(text); } return m ? { name: m[1], ver: (m[2] || '').replace(/\s/g, '') } : null; }
        if (eco === 'go') { m = /^\s*(?:require\s+)?([\w.\-]+\.[\w]+\/[\w.\-/]+)\s+(v[\w.\-+]+)/.exec(text); return m ? { name: m[1], ver: m[2] } : null; }
        if (eco === 'cargo') { m = /^\s*([\w-]+)\s*=\s*(?:"([^"]+)"|\{.*version\s*=\s*"([^"]+)")/.exec(text); return m && !/^(name|version|edition|authors|description|license)$/.test(m[1]) ? { name: m[1], ver: m[2] || m[3] } : null; }
        if (eco === 'gem') { m = /^\s*gem\s+["']([\w\-]+)["'](?:\s*,\s*["']([^"']+)["'])?/.exec(text); return m ? { name: m[1], ver: m[2] || '' } : null; }
        return null;
      };
      for (const l of h.lines) if (l.type === 'del') { const d = parse(l.text); if (d) removed.set(d.name, d.ver); }
      for (const l of h.lines) {
        if (l.type !== 'add') continue;
        const d = parse(l.text); if (!d) continue;
        const section = eco === 'npm' ? sectionOf(h, l) : '';
        if (eco === 'npm' && section && !/dependencies/i.test(section)) continue;
        const unpinned = /^(\*|latest|x)$|^>=?[^<]*$/.test(d.ver) || (eco === 'pip' && !d.ver);
        const remote = /^(git|github|https?|file|link):|^git\+/.test(d.ver);
        const base = { file: p, line: l.newNo, cwe: null, confidence: 0.9, category: 'security' };
        if (remote) out.push(Object.assign({}, base, { ruleId: 'dependency-unpinned', severity: 'medium', cwe: 'CWE-829', title: 'Dependency installed from a URL/git ref: ' + d.name, explanation: d.name + ' is installed from "' + d.ver + '" instead of a registry version. That bypasses registry integrity checks and can change underneath you. Pin to a published version or a full commit SHA.' }));
        else if (unpinned) out.push(Object.assign({}, base, { ruleId: 'dependency-unpinned', severity: eco === 'pip' && !d.ver ? 'low' : 'medium', cwe: 'CWE-1104', title: 'Unpinned dependency: ' + d.name, explanation: d.name + ' has no upper bound ("' + (d.ver || 'any version') + '"), so a new (possibly compromised or breaking) release is picked up automatically. Pin an exact or caret/tilde range and commit the lockfile.' }));
        if (removed.has(d.name)) {
          const from = removed.get(d.name); if (from === d.ver) continue;
          const major = (v) => (/(\d+)/.exec(v || '') || [])[1];
          const isMajor = major(from) && major(d.ver) && major(from) !== major(d.ver);
          out.push(Object.assign({}, base, { ruleId: 'dependency-bump', severity: isMajor ? 'low' : 'info', category: isMajor ? 'bug' : 'security', title: (isMajor ? 'Major version bump: ' : 'Dependency bump: ') + d.name + ' ' + (from || '?') + ' → ' + (d.ver || '?'), explanation: (isMajor ? 'A major version change can include breaking API changes. ' : '') + 'Check the changelog/release notes of ' + d.name + ' and confirm the lockfile changed with it.' }));
        } else if (!unpinned && !remote) {
          out.push(Object.assign({}, base, { ruleId: 'dependency-added', severity: 'low', title: 'New dependency: ' + d.name + (d.ver ? ' ' + d.ver : ''), explanation: 'A new third-party package enters the supply chain. Check that it is maintained, the name is spelled right (typosquatting), the license fits, and that it is really needed.' }));
        }
      }
    }
    return out;
  }
  function sectionOf(h, line) {
    const idx = h.lines.indexOf(line);
    for (let i = idx; i >= 0; i--) { const m = /^\s*"(\w*[Dd]ependencies|scripts|engines|overrides|resolutions|devDependencies|peerDependencies|optionalDependencies|config|[a-zA-Z]+)"\s*:\s*\{/.exec(h.lines[i].text); if (m) return m[1]; }
    return /dependencies/i.test(h.header) ? 'dependencies' : '';
  }

  /* Build per-file context helpers (new-side lines from hunks: added + context). */
  function fileContext(file) {
    const lang = langOf(file.path);
    const rows = []; // ordered new-side lines
    for (const h of file.hunks) for (const l of h.lines) if (l.newNo != null) rows.push(l);
    const byNo = new Map(rows.map((l, i) => [l.newNo, i]));
    let asyncCache = null; let taintCache = null;
    const allText = rows.map((r) => r.text);
    return {
      lang, path: file.path, rows, isTest: isTest(file.path),
      isClient: /(^|\/)(components?|pages|app|client|frontend|public|src\/ui|views?)\/|\.(jsx|tsx|vue|svelte)$/.test(file.path) && !/(^|\/)(api|server|routes|handlers?|controllers?)\//.test(file.path),
      line(no) { const i = byNo.get(no); return i == null ? '' : rows[i].text; },
      window(no, before, after) { const i = byNo.get(no); if (i == null) return { before: [], after: [] }; return { before: rows.slice(Math.max(0, i - before), i), after: rows.slice(i + 1, i + 1 + after) }; },
      asyncNames() {
        if (asyncCache) return asyncCache;
        asyncCache = new Set();
        for (const t of allText) {
          let m; const re = /\basync\s+function\s*\*?\s*([A-Za-z_$][\w$]*)|\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*async\b|^\s*(?:static\s+|public\s+|private\s+)*async\s+([A-Za-z_$][\w$]*)\s*\(|\basync\s+def\s+([A-Za-z_]\w*)/g;
          while ((m = re.exec(t))) asyncCache.add(m[1] || m[2] || m[3] || m[4]);
        }
        return asyncCache;
      },
      taintedVars() {
        if (taintCache) return taintCache;
        taintCache = [];
        for (const t of allText) {
          let m = /\b(?:const|let|var)\s+\{([^}]+)\}\s*=\s*(?:req|request)\.(?:query|params|body)/.exec(t);
          if (m) m[1].split(',').forEach((v) => { const n = v.split(':').pop().split('=')[0].trim(); if (n) taintCache.push(n); });
          m = /\b(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*=\s*.*(?:\b(?:req|request)\.(?:query|params|body|args|form|GET|POST|json|values)\b|searchParams\.get|\$_(?:GET|POST|REQUEST))/.exec(t);
          if (m && !/^(if|for|while)$/.test(m[1])) taintCache.push(m[1]);
          m = /^\s*def\s+\w+\(([^)]*)\)/.exec(t);
          if (m && /\b(?:path|url|filename|file_name|name|target)\b/.test(m[1]) && /@(?:app|router|bp|blueprint)\.(?:route|get|post)/.test(allText.join('\n'))) m[1].split(',').map((x) => x.split(/[:=]/)[0].trim()).filter((x) => /path|url|file|name|target/.test(x)).forEach((x) => taintCache.push(x));
        }
        return taintCache;
      },
      inLoop(no) {
        return false;
      }
    };
  }

  function severityRank(s) { const i = SEVERITIES.indexOf(s); return i < 0 ? 5 : i; }
  function hashId(s) { let h = 2166136261; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return (h >>> 0).toString(36); }

  /* analyze(parsedFiles, opts) -> findings. opts.disabled: Set of rule IDs; opts.largeFile (default 400). */
  function analyze(files, opts) {
    const o = Object.assign({ largeFile: 400, largePr: 1000, disabled: new Set() }, opts || {});
    const disabled = o.disabled instanceof Set ? o.disabled : new Set(o.disabled || []);
    const findings = [];
    const push = (f) => { if (disabled.has(f.ruleId)) return; f.source = f.source || 'rules'; f.id = f.id || hashId([f.ruleId, f.file, f.line, f.title].join('|')); findings.push(f); };
    let total = 0;
    for (const file of files) {
      if (file.binary || file.status === 'deleted' || !file.newPath) continue;
      total += file.additions;
      if (LOCK_PATH.test(file.path)) continue;
      const ctx = fileContext(file);
      const minified = MIN_PATH.test(file.path);
      for (const f of dependencyFindings(file)) push(Object.assign(f, { snippet: snippetFor(ctx, f.line) }));
      if (!minified) {
        for (const h of file.hunks) {
          for (let li = 0; li < h.lines.length; li++) {
            const l = h.lines[li];
            if (l.type !== 'add') continue;
            const text = l.text;
            if (text.length > 2000) continue;
            const comment = isCommentOnly(text, ctx.lang);
            const lineCtx = Object.assign(Object.create(ctx), {
              around: (n) => { const w = ctx.window(l.newNo, n, n); return w.before.map((r) => r.text).concat([text], w.after.map((r) => r.text)).join('\n'); },
              next: (n) => { const w = ctx.window(l.newNo, 0, n); return w.after.length >= n ? w.after[n - 1].text : ''; },
              inLoop: () => { const w = ctx.window(l.newNo, 6, 0); const ind = /^\s*/.exec(text)[0].length; for (let i = w.before.length - 1; i >= 0; i--) { const bt = w.before[i].text; if (!bt.trim()) continue; const bi = /^\s*/.exec(bt)[0].length; if (bi < ind && /^\s*(?:for\b(?!\s+await)|while\b|\w[\w.]*\.(?:forEach|map)\()/.test(bt)) return !/\bfor\s+await\b/.test(bt); if (bi < ind && /^\s*(?:(?:async\s+)?function|def|class|async def)\b|=>\s*\{\s*$/.test(bt) && !/\.(?:forEach|map)\(/.test(bt)) return false; } return false; }
            });
            let secretHit = false;
            for (const r of RULES) {
              if (disabled.has(r.id)) continue;
              if (r.scope === 'code' && (!ctx.lang || DOC_PATH.test(file.path))) continue;
              if (comment && r.scope === 'code') continue;
              if (r.skipTests && ctx.isTest) continue;
              if (r.id === 'secret-generic' && secretHit) continue;
              let m = null;
              try { m = r.test(text, lineCtx); } catch (e) { m = null; }
              if (!m) continue;
              if (r.secret) secretHit = true;
              let fixText = null;
              try { fixText = r.fix ? r.fix(text, m, lineCtx) : null; } catch (e) { fixText = null; }
              const sev = r.severityFor ? r.severityFor(text, lineCtx, m) : r.severity;
              let confidence = r.confidenceFor ? r.confidenceFor(m) : r.confidence;
              if (ctx.isTest && r.category === 'security') confidence = Math.min(confidence, 0.45);
              const placeholder = r.secret && /EXAMPLE|FAKE|DUMMY|NOT[-_]?REAL|SAMPLE|0000000000/i.test(m[0] + text);
              if (placeholder) confidence = Math.min(confidence, 0.6);
              push({
                ruleId: r.id, title: (r.titleFor && r.titleFor(m)) || r.title, severity: sev, category: (r.categoryFor && r.categoryFor(m)) || r.category, cwe: r.cweFor ? r.cweFor(text, lineCtx) : r.cwe,
                file: file.path, line: l.newNo, column: (m.index || 0) + 1, match: String(m[0]).slice(0, 120),
                explanation: r.explain + (placeholder ? ' (The value looks like a placeholder/example, so confidence is lowered; confirm it is not real.)' : '') + (ctx.isTest && r.category === 'security' ? ' (Found in a test file, so it may be intentional test data.)' : ''),
                fix: fixText != null && fixText !== text ? { replacement: fixText, note: r.fixNote || '' } : r.fixNote ? { replacement: null, note: r.fixNote } : null,
                confidence, snippet: snippetFor(ctx, l.newNo)
              });
            }
          }
        }
      }
      if (file.additions > o.largeFile) push({ ruleId: 'large-file-change', title: 'Large change in one file (' + file.additions + ' added lines)', severity: 'info', category: 'perf', cwe: null, file: file.path, line: firstAdded(file), explanation: 'Reviews of very large diffs miss more defects. Consider splitting generated code, moves and behaviour changes into separate PRs.', confidence: 0.9, snippet: snippetFor(ctx, firstAdded(file)) });
      const long = ctx.rows.find((r) => r.type === 'add' && r.text.length > 1000);
      if (long && !minified) push({ ruleId: 'minified-or-generated', title: 'Very long line added (generated or minified?)', severity: 'info', category: 'style', cwe: null, file: file.path, line: long.newNo, explanation: 'A line over 1,000 characters was added. Generated or minified files are hard to review; commit the source and build it, or mark the file as generated (.gitattributes linguist-generated).', confidence: 0.6, snippet: snippetFor(ctx, long.newNo) });
    }
    // PR-level: changed source without tests.
    const src = files.filter((f) => !f.binary && f.newPath && f.additions > 0 && langOf(f.path) && langOf(f.path) !== 'tmpl' && !isTest(f.path) && !DOC_PATH.test(f.path) && !MIN_PATH.test(f.path) && !/(^|\/)(scripts?|migrations?|config|\.github)\/|\.config\.[a-z]+$|\.d\.ts$/.test(f.path));
    const tests = files.filter((f) => isTest(f.path) && f.status !== 'deleted');
    const meaningful = src.filter((f) => f.hunks.some((h) => h.lines.some((l) => l.type === 'add' && l.text.trim() && !isCommentOnly(l.text, langOf(f.path)))));
    if (meaningful.length && !tests.length) {
      const f0 = meaningful[0];
      push({ ruleId: 'missing-tests', title: 'Source changed without test changes', severity: 'medium', category: 'test', cwe: null, file: f0.path, line: firstAdded(f0), explanation: meaningful.length + ' source file' + (meaningful.length === 1 ? '' : 's') + ' changed (' + meaningful.slice(0, 4).map((f) => f.path).join(', ') + (meaningful.length > 4 ? ', ...' : '') + ') but no test files were added or updated. Add a test that fails without this change, or explain in the PR why it is not testable.', confidence: 0.7, snippet: snippetFor(fileContext(f0), firstAdded(f0)), prLevel: true });
    }
    if (total > o.largePr) push({ ruleId: 'large-pr', title: 'Large pull request (' + total + ' added lines)', severity: 'info', category: 'perf', cwe: null, file: (files.find((f) => f.additions) || {}).path || '', line: null, explanation: 'Large PRs get shallower reviews. Consider splitting into smaller, independently reviewable changes.', confidence: 0.9, prLevel: true });
    findings.sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || a.file.localeCompare(b.file) || (a.line || 0) - (b.line || 0));
    return findings;
  }
  function firstAdded(file) { for (const h of file.hunks) for (const l of h.lines) if (l.type === 'add') return l.newNo; return null; }
  function snippetFor(ctx, no) {
    if (no == null) return null;
    const w = ctx.window(no, 2, 2);
    const row = (r) => ({ no: r.newNo, type: r.type, text: r.text });
    return { before: w.before.map(row), line: { no, type: 'add', text: ctx.line(no) }, after: w.after.map(row) };
  }
  function ruleCatalog() {
    return RULES.map((r) => ({ id: r.id, title: r.title, severity: r.severity, category: r.category, cwe: r.cwe, explain: r.explain })).concat([
      { id: 'dependency-added', title: 'New dependency', severity: 'low', category: 'security', cwe: null, explain: 'A new package was added to a manifest.' },
      { id: 'dependency-bump', title: 'Dependency version bump', severity: 'info', category: 'security', cwe: null, explain: 'A dependency version changed.' },
      { id: 'dependency-unpinned', title: 'Unpinned or URL dependency', severity: 'medium', category: 'security', cwe: 'CWE-1104', explain: 'A dependency floats to any version or installs from a URL.' },
      { id: 'missing-tests', title: 'Source changed without test changes', severity: 'medium', category: 'test', cwe: null, explain: 'Code changed but no tests changed.' },
      { id: 'large-file-change', title: 'Large change in one file', severity: 'info', category: 'perf', cwe: null, explain: 'Many added lines in one file.' },
      { id: 'large-pr', title: 'Large pull request', severity: 'info', category: 'perf', cwe: null, explain: 'Many added lines overall.' },
      { id: 'minified-or-generated', title: 'Very long line added', severity: 'info', category: 'style', cwe: null, explain: 'Generated or minified content.' }
    ]);
  }
  return { RULES, SEVERITIES, CATEGORIES, analyze, ruleCatalog, langOf, isTest, isCommentOnly, stripStrings, entropy, severityRank, hashId, fileContext };
});
