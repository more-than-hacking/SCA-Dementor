# Dementor 2.0 — Roadmap & Plan of Action

---

## What the Tool Does Today (v1.x)

A **hybrid static reachability engine** — symbol-aware grep narrows candidates, a
tree-sitter call graph builds cross-file evidence, and an LLM makes the final
function-level reachability + exploitability judgment grounded on that evidence.
This is well past "regex import detection."

**Verification pipeline:**
1. **Version match** — exact version via lockfiles / manifests
2. **OSV check** — query the Open Source Vulnerabilities database
3. **Vulnerable-symbol extraction** — `extract_vulnerable_symbols_from_osv()` parses the
   advisory to pull the *specific* vulnerable function/class symbols (scored, with
   denylists for generic verbs), not just the package name
4. **Symbol-aware presence** — find candidate files/snippets where those symbols appear
   (distribution↔import aliasing handled, e.g. PyYAML→yaml; test files excluded)
5. **Cross-file caller slicing** — tree-sitter (`callgraph.build_caller_slice`) traces
   callers from *other files* into the sink so untrusted input flowing in from elsewhere
   is visible (`reachability_scan.py:1106`)
6. **LLM reachability gate** — one CVE-aware call per candidate: "is the library used AND
   is the *specific* vulnerable function reached, and is there an active exploit path?",
   with verdict reconciliation (precise tracer authoritative over coarse scan)

**Per-CVE flow trace + visualization** — `gather_flow_candidates` → `build_reachability_paths`
→ `trace_reachability_flow_llm` produce a grounded, anti-hallucination-validated evidence
chain (declared → imported → called → reachable) rendered as a flowchart per CVE.

**Triage context:**
- **Exposure classification** (`exposure.py`) — internet-facing vs internal, client-side
  (browser-shipped) detectability, AI-judged from Dockerfile EXPOSE / k8s / controllers / frontend
- **Priority model** (P1/P2/P3) — client-side external detectability outranks reachability;
  backend = strict severity × reachability
- **Token/cost tracking** per scan via the Claude CLI usage/cost fields

**Supported languages**: Python, Java (Maven + Gradle), JavaScript/TypeScript, Go (tree-sitter)
**LLM backends**: Claude CLI in-pod (subscription, no API cost), or API keys (Anthropic/OpenAI/Gemini)
**Output**: `vulnerability_report_confirmed.json` — only findings that pass the gates
**Dashboard**: Flask web UI — SSE log streaming, Reachability tab, Repositories tab
(org-wide PAT fetch, per-repo scan/status, FP / accepted-risk workflow), PR creation,
exposure/priority badges, per-CVE flow visualization

---

## What Is Currently Missing / Broken

### Coverage Gaps

**Transitive dependencies — the #1 blind spot**
The tool only parses direct dependencies from manifest files (`requirements.txt`, `pom.xml`, `package.json`, etc.).
In practice, most real-world CVEs live in *transitive* (indirect) dependencies — deps of deps.
Example: `requirements.txt` has `requests==2.28.0`. That pulls in `urllib3==1.26.7` which has a CVE.
Dementor currently misses that entirely. No transitive dep = no scan = no detection.

**Missing language parsers**
`Languages.yaml` lists Rust, Ruby, PHP, .NET as supported — but none of those have dependency parsers implemented:
- Rust: `Cargo.toml` + `Cargo.lock` exist in config but no parser
- Ruby: `Gemfile` + `Gemfile.lock` — no parser
- PHP: `composer.json` + `composer.lock` — no parser
- .NET/C#: `*.csproj`, `packages.config`, `NuGet.lock` — `nuget_parser.py` exists in `latest_version_parsers/` but no dep parser in `parsers/`

**Reachability is function-level now — but two depth gaps remain**
*(This section previously claimed reachability was pure regex. That is no longer true —
the tool extracts the specific vulnerable symbol, matches the function, builds a cross-file
caller slice, and the LLM judges function-level reachability. The real remaining gaps are
about **depth** and **trigger mechanism**.)*

- **Deep call chains into library internals** — the cross-file slice catches *your* callers
  into the sink, but does not trace arbitrarily deep *inside* dependency code
  (`your code → A → B → C → vulnerableGadget`, several hops inside `node_modules`/site-packages).
  The LLM compensates from the snippet; it is not a deterministic deep call graph. Transitive
  *call chains* are therefore handled approximately, not soundly.
- **The LLM is the final arbiter** — the function-level verdict ultimately rests on an LLM
  call, not a sound data-flow proof. Excellent for recall and reasoning, but it means "zero-FP"
  is really *low-FP*, not *provably* zero. Residual FP/FN is possible.

**Case B — autonomous / load-triggered reachability is not modeled**
Today's reachability roots are effectively "where the vulnerable symbol appears + its callers."
That captures **Case A** (your code calls the vuln, directly or transitively). It misses **Case B** —
where the library runs vulnerable code *independently of any call from your code*:
- import-time / module-load side effects
- static initializers / constructors
- background threads, timers, schedulers
- framework auto-wiring (DI beans, Spring auto-config, Express middleware, auto-registered
  Jackson deserializers)

For Case B, *presence + load ≈ reachable* — no explicit call exists to trace. Dementor has
no "unconditionally reachable / load-triggered" verdict class and does not root the call graph
at implicit entrypoints. This is the minority of CVEs but the highest-miss-risk class.

**Layer-3 (OS / base-image) libraries are invisible**
The tool scans *source*, so libraries that only exist in the container image — base-image OS
packages (openssl, glibc, zlib) and anything installed at build time — are never seen. A CVE
that lives in the image but not the repo (e.g. a transitive npm dep materialized only in
`node_modules`, or a Debian package from `FROM`) is missed entirely. See **image ingestion** below.

---

### Prioritization Is Weak

**Severity signal is qualitative and low-quality**
Current severity comes from `database_specific.severity` in OSV — a string like "MODERATE" or "HIGH".
This is the lowest-quality signal available. No CVSS score, no numerical comparison, no exploitability context.

**No EPSS score**
EPSS (Exploit Prediction Scoring System) from FIRST.org gives a probability (0.0–1.0) that a CVE will be exploited in the next 30 days.
A CRITICAL CVE with EPSS=0.001 is very different from one with EPSS=0.87.
Not having this means every CRITICAL looks equally urgent — which leads to alert fatigue.

**No CISA KEV check**
CISA publishes a list of CVEs being actively exploited in the wild right now.
If a finding is in CISA KEV, it is not a theoretical risk — it is being exploited today.
Currently there is no check against this list at all.

**Single vulnerability source (OSV only)**
OSV is well-curated but has coverage gaps. The tool does not query:
- GitHub Advisory Database (GHSA) — different coverage, especially for JavaScript/npm
- NVD (NIST) — the authoritative source for CVSS scores
This means some real vulnerabilities are simply never found.

---

### No Historical Memory

**Everything is flat JSON, rewritten every scan**
Results live in `vulnerability_report_live_verified.json` and `vulnerability_report_confirmed.json`.
Every scan overwrites these. There is no:
- Record of when a vulnerability was first seen
- Trending (is the org's vuln count going up or down?)
- SLA tracking (this CRITICAL has been open 47 days — breach)
- Diff: "these 2 are new, these 5 were already known"

**No new-vs-existing differentiation**
CI/CD pipelines need to know: did this PR *introduce* a new vulnerability, or is it pre-existing debt?
Currently impossible because there is no baseline to compare against.

---

### No CI/CD Integration

The tool runs as a standalone server or CLI. There is no:
- GitHub Actions workflow to run on PRs
- SARIF output (the format GitHub Code Scanning understands natively — findings appear in the PR Security tab)
- Pass/fail status that blocks merges

This means the tool is something a security team runs occasionally rather than something baked into every developer's workflow.

---

### No Policy Engine

No way to configure:
- "Fail if any CRITICAL vulnerability with EPSS > 0.5"
- "This repo is exempt from CVE-2021-44228 until 2026-06-01 (risk accepted, tracked in JIRA-123)"
- "Only alert on vulns with a fix available"
- "Don't alert on dev-only dependencies"

Everything is all-or-nothing — no nuance, no risk acceptance workflow.

---

### Supply Chain Risk Beyond CVEs

**No license scanning**
The tool scans for security vulnerabilities but not license risk.
A dependency using GPL or AGPL has legal/compliance implications for commercial products.
This is typically the #2 ask after vulnerability scanning in any enterprise SCA tool.

**No supply chain integrity signals**
- No typosquatting detection (is `reqests` a typo of `requests` in a manifest?)
- No package health signals (unmaintained packages, abandoned repos, suspicious maintainer changes)
- No dependency confusion attack detection (internal package name colliding with public registry name)

---

### No SBOM Output

No CycloneDX or SPDX output. These are the standard formats for "here is everything in my software."
Required for:
- US Government / DoD contracts (Executive Order 14028)
- Enterprise customers who ask "what's in your software?"
- Feeding into other tools (Dependency-Track, etc.)

---

### No Notifications

When a scan finds something critical, you have to log into the dashboard to see it.
No Slack, no Teams, no email, no Jira ticket creation.

---

### Performance Bottlenecks

**Reachability phase is sequential**
Phase 3 in `pipeline_zero_fp.py:208` is a plain `for entry in to_process:` loop.
OSV fetching already uses `ThreadPoolExecutor` with 30 workers.
Reachability never got the same treatment — it runs one entry at a time.
For orgs with 100+ potential vulns this is the main bottleneck.

**No incremental scanning**
Every scan re-clones, re-parses, and re-queries everything from scratch.
No caching of OSV responses. No hash-based skip for unchanged dep files.

---

## Milestone 1 — Core Coverage (Fix the Blind Spots)

### 1.1 Transitive Dependency Resolution — ✅ largely DONE (`transitive_resolver.py`)
- ✅ **Lockfile-based (offline, default-on):** npm (`package-lock.json`/`npm-shrinkwrap.json`),
  Python (`Pipfile.lock`, `poetry.lock`). Pure-Python, deterministic, CI-safe.
- ✅ **Tool-based (opt-in `DEMENTOR_TOOL_RESOLVE=1`):** Maven (`mvn dependency:tree`) and Go
  (`go list -m all`) — live-verified, with `DEMENTOR_TOOL_TIMEOUT`. Parsers unit-tested.
- Resolved graph feeds the existing OSV pipeline at the Phase-2 chokepoint; each dep tagged
  `dep_type=direct|transitive`.
- **Remaining:** Gradle (`gradle dependencies`); plain `requirements.txt` without a lockfile
  (would need `pip install --dry-run --report`).

### 1.2 Missing Language Parsers
- **Rust** — `Cargo.toml` + `Cargo.lock` → crates.io ecosystem
- **Ruby** — `Gemfile` + `Gemfile.lock` → RubyGems ecosystem
- **PHP** — `composer.json` + `composer.lock` → Packagist ecosystem
- **.NET/C#** — `*.csproj`, `packages.config`, `NuGet.lock` → NuGet ecosystem

### 1.3 AST-Based Reachability — ✅ largely DONE, with follow-ups
- ✅ tree-sitter call graph (`callgraph.py`) for Python/Java/Go/JS — qualified-symbol
  matching, cross-file caller slicing, grounded flow-path trace with anti-hallucination validation
- ✅ leverages `extract_vulnerable_symbols_from_osv()` symbols for real call-site matching
- **Follow-up A — deep intra-library chains**: trace several hops *inside* dependency code,
  not just your-code → sink. Today the LLM bridges the gap from the snippet; make it graph-backed.
- **Follow-up B — Case B roots (autonomous reachability)**: also root the call graph at
  *implicit* entrypoints — module top-level / import-time code, static initializers,
  constructors, and registered framework callbacks (annotations, middleware, DI beans).
  Add an **`unconditionally_reachable`** verdict class: if the vuln runs at load / on a
  background thread / via framework wiring, `loaded ≈ reachable` with no explicit call.
- **Follow-up C — import-alias parity in the call graph** — ✅ DONE. Both paths now resolve
  import aliases across Python/JS/TS/Go: the production grep path via `_detect_import_aliases`
  (`import jwt as _jwt`, `const _ = require('lodash')`, `import y "path"`, `from m import f as g`),
  and the deterministic `callgraph.py` via `_alias_bare_names` (symbol aliases; module aliases
  already matched by trailing call name). Benchmark `py_aliased_import` flipped to a supported
  passing case. *Remaining gap (documented):* call-through-a-variable (`fn = yaml.load; fn(s)`)
  needs data-flow tracking — now the benchmark's `py_var_indirection` known-gap entry.

### 1.4 Container Image Ingestion
- Repo-oriented today; add a first-class "scan this image" path so Dementor scans **what
  deployment actually runs** (and what scanners like Wiz see), not just the source repo.
- Pull image by digest → extract the app filesystem (e.g. buildpack `/workspace`, or
  `node_modules` / site-packages layers) → run the existing pipeline on it.
- Trace image → source: read SLSA/Cloud Build provenance for git repo + commit; fall back
  to the extracted source when the image was deployed ad-hoc (`gcloud run deploy --source`,
  no git link).
- Surfaces transitive deps and build-time-only libraries that never appear in the manifest.

---

## Milestone 2 — Smarter Prioritization

### 2.1 CVSS v3 Score + Vector
- Fetch numerical CVSS v3 base score + attack vector from NVD or OSV
- Enables proper sorting and policy thresholds

### 2.2 EPSS Score
- Query FIRST.org EPSS API per CVE
- Add `epss_score` and `epss_percentile` to each finding
- Use as primary sort key in dashboard (high EPSS = fix first)

### 2.3 CISA KEV Check
- Daily-cached fetch of CISA KEV JSON catalog
- Flag any finding whose CVE ID appears in KEV as `actively_exploited: true`
- Auto-elevate priority regardless of CVSS score

### 2.4 Multi-Source Vulnerability DBs
- Add GitHub Advisory Database (GHSA) alongside OSV
- Pull CVSS scores from NVD when OSV doesn't have them
- Merge + deduplicate across sources

---

## Milestone 3 — CI/CD Integration

### 3.1 GitHub Actions Workflow
- Reusable workflow: scan on every PR, fail if new CRITICAL/HIGH vulns introduced
- Input parameters: severity threshold, EPSS threshold, block on CISA KEV

### 3.2 SARIF Output
- Standard format for GitHub Code Scanning
- Findings appear in the PR "Security" tab natively — no separate dashboard needed for devs

### 3.3 New-vs-Existing Vuln Diff
- Requires baseline snapshot (Milestone 4)
- CI only fails on newly introduced vulns, not pre-existing debt
- Output: `new_findings[]`, `resolved_findings[]`, `existing_findings[]`

---

## Milestone 4 — Persistence & History

### 4.1 Database Backend
- Replace flat JSON files with SQLite (self-hosted) or Postgres (scale)
- Schema: `repos`, `scans`, `findings`, `waivers`, `snapshots`
- Migrate existing `scan_jobs.jsonl` into DB on first run

### 4.2 Historical Trending
- Track vuln counts over time per repo and org-wide
- Dashboard graphs: total open, by severity, by ecosystem
- "Critical count this month: 12 → 4 (67% reduction)"

### 4.3 SLA Tracking
- Record first-seen date per finding
- Configurable SLA thresholds (e.g. CRITICAL ≤ 7 days, HIGH ≤ 30 days)
- SLA breach report for engineering leads

---

## Milestone 5 — Policy Engine

### 5.1 Policy-as-Code (YAML)
```yaml
policies:
  - name: block-critical-exploited
    condition: severity == CRITICAL and epss > 0.5
    action: fail
  - name: cisa-kev-always-block
    condition: cisa_kev == true
    action: fail
  - name: no-fix-warn
    condition: fix_available == false
    action: warn
```

### 5.2 Waivers / Exceptions
- Risk-accept a specific CVE in a specific repo with expiry date + ticket reference
- Waived findings skip CI gate but remain visible in dashboard with waiver metadata

---

## Milestone 6 — Supply Chain Risk

### 6.1 License Scanning
- Detect GPL, AGPL, LGPL, copyleft licenses in dependency tree
- Configurable blocked license list per policy
- Flag compliance risk separately from security risk

### 6.2 Typosquatting Detection
- Compare all package names against a curated popular-package list
- Flag anything within edit-distance 1-2 of a popular package

### 6.3 Package Health Signals
- Unmaintained: last release > 2 years
- Abandoned: repo archived or deleted upstream
- Suspicious: recent maintainer transfer or ownership change
- Unpinned: wildcard `*` or `latest` version in manifest

---

## Milestone 7 — SBOM Generation

### 7.1 CycloneDX Output
- Generate CycloneDX JSON/XML from dependency graph
- Required for government/enterprise compliance (EO 14028)
- Feeds into Dependency-Track for continuous monitoring

### 7.2 SPDX Output
- ISO 5962:2021 SPDX format
- Required by Linux Foundation projects and some enterprise customers

---

## Milestone 8 — Notifications & Integrations

### 8.1 Slack / Teams Webhooks
- Notify on: new CRITICAL finding, CISA KEV match, SLA breach
- Per-repo channel routing (team ownership mapping)

### 8.2 Jira Auto-Ticket Creation
- One ticket per confirmed finding: CVE ID, EPSS, CVSS, affected repos, fix recommendation
- Link to waiver workflow if risk-accepting

### 8.3 Email Digest
- Daily/weekly summary per repo owner or team
- Configurable: new findings only, or full open list

---

## Milestone 9 — Performance

### 9.1 Parallel Reachability
- `pipeline_zero_fp.py:208` — sequential `for` loop → `ThreadPoolExecutor` (same pattern as OSV fetch)
- Expected: 10–30x speedup for orgs with many potential vulns

### 9.2 Incremental Scanning
- Hash dep files — skip re-parse if unchanged since last scan
- Cache OSV responses by `(package, version, ecosystem)` with TTL
- Only re-run reachability on files modified since last scan

---

## Milestone 10 — LLM Quality

### 10.1 Chain-of-Thought Reachability Prompting
- Current: single YES/NO prompt
- Better: structured multi-step reasoning:
  1. Is the vulnerable function actually called (not just the library imported)?
  2. Is there sanitization or mitigation in the call path?
  3. What is the realistic attack scenario?
  4. What is the business impact?
- Richer evidence attached to findings, not just a boolean

### 10.2 Container / Docker Image Scanning
- Currently scans Dockerfiles for library usage
- Add actual image layer scanning via Trivy or Grype
- Catches base image vulnerabilities (`FROM ubuntu:20.04` etc.)
- Complements 1.4 (image ingestion): Trivy/Grype for OS-package CVEs, Dementor's reachability
  engine for the application-dependency CVEs found in the extracted app filesystem

### 10.3 Free / Keyless LLM Path (no mandatory paid API)
- **Why**: Dementor's "free, open alternative to pricey enterprise SCA" promise must hold
  end-to-end. Vuln data is already free/keyless (OSV.dev), but the reachability AI layer needs
  an LLM — the only credential anywhere. Close that hole.
- **Local model support (Ollama)** — run reachability AI with a local code-tuned model, zero
  paid dependency. Wire as another `llm_client` provider.
- **Keyless graceful degradation** — OSV + vulnerable-symbol detection + tree-sitter call graph
  must produce useful output with **no LLM configured**; AI is an *enhancement gate*, not a hard
  requirement. Reachability falls back to symbol/call-site presence when no LLM is available.
- Existing free option to document: keyless Claude CLI subscription (`claude_session`).

---

## Data Sources & Originality (architecture note — not a wrapper)

Dementor consumes public CVE feeds but is **not** a wrapper around another SCA tool. The
distinction matters for positioning (and for the Black Hat Arsenal submission — see `BLACKHAT.md`):

```
DATA LAYER (commodity — every SCA tool uses it)  →  OSV.dev (free, open, keyless)
                                                    [later: GHSA + NVD — Milestone 2.4]
ANALYSIS LAYER (Dementor's original engine)      →  vulnerable-symbol extraction · tree-sitter
                                                    call graph · cross-file slicing · AI-grounded
                                                    (anti-hallucination) reachability · exposure ×
                                                    reachability prioritization · fixed-version guidance
```

OSV answers "is this *package* version vulnerable"; it cannot answer "is the vulnerable
*function* reachable in this code." That analysis layer is the original contribution.
Consuming a public *data feed* ≠ wrapping a *tool* (cf. Trivy, Grype, dependency-check —
all consume the same feeds).

---

## Phase 2 — Dynamic Reachability (eBPF Runtime Sensor)

> Static-first remains the core (it is CI-friendly and *proves* unreachability — runtime
> never can). This is a **confirmation plane**, not a replacement, added once the static
> engine is mature.

### P2.1 Runtime Sensor
- Lightweight eBPF sensor (k8s DaemonSet), built on **Cilium Tetragon** (or Tracee/Falco) —
  do not hand-roll raw eBPF.
- Observes, per process, language-agnostically: **which packages/libraries are actually
  loaded into memory**, network connections (confirms real internet exposure), and
  syscall/file/exec activity.

### P2.2 Hybrid Verdict (correlate static ↔ runtime)
| Static verdict | Runtime signal | Combined verdict |
|---|---|---|
| Reachable | package loaded under traffic | ✅ **CONFIRMED** (highest confidence) |
| Reachable | never loaded | ⚠️ latent / likely dead path |
| Unreachable | loaded | 🔍 investigate — static missed dynamic dispatch |
| Uncertain (dynamic dispatch) | loaded + called | resolves the uncertainty static couldn't |

- Especially decisive for **Case B** (1.3 Follow-up B) and **Layer-3 OS libs**, where static
  is weakest but "is it loaded?" is a one-shot runtime answer.

### P2.3 Granularity caveat (design constraint)
- eBPF gives **package / file / network / syscall** granularity cheaply and universally.
- **Function-level** runtime tracing needs uprobes — workable for compiled languages
  (Go, Rust, native libs) but not for interpreted ones (Node/Python), which require a
  per-language **IAST agent** (a separate, later track).
- ⇒ Static reachability stays the most precise *function-level* signal Dementor has;
  eBPF confirms *package-level* loading. (This is the same limit Wiz's runtime sensor hits.)

### P2.4 Deployment reality
- Needs a privileged sensor, Linux 5.x+ kernel, running **in the cluster** (staging/prod) —
  **not CI-friendly**. Static = PR-time plane; dynamic = runtime-observability plane.
  Both write to the same finding store.

---

## Research — Cross-Boundary Reachability ("Hop Check Everywhere")

> **Problem.** The call graph traces hops up to `max_depth=7`, but only within *first-party
> code*. Skipped dirs (`node_modules`, `site-packages`, `vendor`, `target`) mean the trace
> **stops at the library boundary**. So `your code → A() → B() → C() → D()` is fully traced
> only while A/B/C are *yours*; if B/C/D live *inside* the dependency, those hops are invisible.
> It works when the advisory's vulnerable symbol sits **on** the boundary (the `A()` your code
> calls) and misses when it sits **behind** it (a deep library-internal `D()`), unless the LLM
> bridges from the advisory text.
>
> **Goal.** Not just "is the version vulnerable" but "is a vulnerable *function* actually on a
> reachable call path" — including hops *inside* dependencies.

### Two distinct sub-problems (need different tools)
1. **Hop *across* the library boundary** → a **static** problem.
2. **Confirm the vulnerable function actually *executes*** → a **dynamic** problem.

### Method × language matrix (what actually works)
| Goal | Method | Java | Go / native | Python | Node/JS |
|---|---|---|---|---|---|
| Hop into library (static) | Selective library indexing (parse the installed pkg) | ✅ | ✅ | ✅ | ⚠️ dynamic dispatch |
| Hop into library (static, deterministic) | Whole-program call graph (bytecode/SSA) | ✅ WALA/Soot | ✅ `go/callgraph` | ⚠️ pycg (weak) | ❌ too dynamic |
| Confirm function *called* (runtime) | **eBPF uprobes** | ❌ JIT, not native symbol | ✅ | ❌ | ❌ |
| Confirm package *loaded* (runtime) | **eBPF** (mmap/open) | ✅ | ✅ | ✅ | ✅ |
| Confirm function *called* (runtime) | **IAST agent** | ✅ `-javaagent` | n/a | ✅ `sys.monitoring` 3.12+ | ✅ async-hooks |

> **Key finding:** eBPF gives *function-level* confirmation **only for compiled languages**
> (Go/Rust/C). For Java/Python/Node — most of our stack, and the `basic-ftp` (Node) case —
> eBPF only confirms the **package is loaded**, not that the vulnerable function ran.
> Function-level runtime proof in interpreted languages needs an **IAST agent**, not eBPF.

### Layered design (research → build order)
- **Layer 1 — Selective library indexing (STATIC, do first).** When a finding's vulnerable
  symbol is *behind* the boundary, parse **just that one installed package version** (from
  `node_modules`/site-packages, or the extracted image — ties to 1.4) into the same tree-sitter
  index so the reverse-walk continues past `A()` into `B → C → D`. Targeted (only CVE-bearing
  packages, not all of `node_modules`), bounded by `max_depth`, no infra needed. *Highest leverage,
  lowest risk — extends the existing engine. This is the concrete next step for hop-everywhere.*
- **Layer 2 — Whole-program call graphs where static shines.** Java bytecode (WALA/Soot/
  java-callgraph) and Go (`go/callgraph`, RTA/CHA) resolve into dependency code natively →
  deterministic cross-boundary. Skip JS/Python here (too dynamic).
- **Layer 3 — Runtime confirmation (Phase 2), language-aware.**
  - eBPF/Tetragon — *everywhere*: package-loaded + network/exposure; *function-level* only Go/native.
  - IAST agents — function-level runtime in interpreted langs: Java `-javaagent`, Python
    `sys.monitoring`, Node `diagnostics_channel`/async-hooks.

### Open questions to investigate
- How often does `extract_vulnerable_symbols_from_osv()` land *on* the boundary API vs.
  *behind* it? (Determines how big the Layer-1 gap actually is in practice.)
- Prebuilt "public API → vulnerable internal function" reachability maps per advisory — does an
  open-source corpus exist (GitHub vuln-function data, OpenSSF, academic call-graph DBs), or
  must we precompute via Layer 2?
- Recursion/cost ceiling for Layer 1 when a vulnerable package is large or deeply nested.
- IAST overhead + coverage (only-executed-paths) tradeoffs per language.
- Integrity check of each library also should be one modlue so this tool acts as 360 security of SCA packages
- SBOM Tool

### Precision & upgrade enhancements (identified in field testing)
- **Symbol extraction from fix-commit diffs.** OSV advisories link the fixing PR/commit; parsing
  that diff yields the *exact* changed functions = the true vulnerable API — more precise than
  prose mining or NVD (NVD/CPE has no function-level data). Best accuracy upgrade for reachability.
- **AI validates the deterministic upgrade.** In AI scans, have the LLM sanity-check the
  registry-verified safe-upgrade version (breaking-change notes, whether it truly clears the CVEs).
- **Registry upgrade verification for Maven & Go** (npm + PyPI already verified against the
  live registry; Maven/Go currently fall back to the OSV fix target, marked `verified:false`).
- **Optional NVD/CVSS enrichment**, keyed by OSV's CVE IDs — for authoritative CVSS vectors in
  compliance reporting (not for detection/reachability — OSV is more precise there).
---

## Build Order (Priority)

*(✅ already shipped this cycle: AST/tree-sitter reachability (1.3 core), parallel
reachability (9.1), exposure + priority model, cost tracking, repo-management UI.)*

| # | What | Why First | Effort |
|---|------|-----------|--------|
| 1 | Transitive deps (1.1) | Biggest coverage gap — most CVEs live in transitive deps; this is what would catch the `basic-ftp`-style finding | Medium |
| 2 | EPSS + CISA KEV (2.2, 2.3) | One API call each, transforms prioritization immediately; lets us flag actively-exploited (Log4Shell-class) CVEs | Low |
| 3 | Case B reachability (1.3 Follow-up B) | Implicit-entrypoint roots + `unconditionally_reachable` verdict — closes the highest-miss-risk class | High |
| 4 | Image ingestion (1.4) | Scan what deployment actually runs; surfaces transitive + build-time-only libs | Medium |
| 5 | Deep intra-library chains (1.3 Follow-up A) | Graph-backed multi-hop, less LLM bridging — biggest precision leap | High |
| 6 | SARIF + GitHub Actions (3.1, 3.2) | Puts the tool in every developer's PR workflow | Medium |
| 7 | Multi-source DBs + CVSS (2.1, 2.4) | GHSA/NVD coverage + numeric CVSS for policy thresholds | Medium |
| 8 | DB backend (4.1) | Unlocks history, SLA, vuln diff — everything downstream depends on it | Medium |
| 9 | Missing parsers (1.2) | Rust/Ruby/PHP/.NET common in enterprise stacks | Medium |
| 10 | Policy engine (5.1, 5.2) | Enterprise requirement for adoption | Medium |
| 11 | Container layer scanning (10.2) | Trivy/Grype for OS-package CVEs, pairs with image ingestion | Medium |
| 12 | SBOM (7.1, 7.2) | Compliance checkbox; easy once dep graph is solid | Low |
| 13 | Supply chain (6.x) | Differentiator beyond pure CVE scanning | Medium |
| 14 | Notifications (8.x) | Nice to have once finding quality is high | Low |
| 15 | LLM chain-of-thought (10.1) | Quality improvement on an already-working feature | Medium |
| **P2** | **Dynamic eBPF (Phase 2)** | **Runtime confirmation plane — after static is mature; needs in-cluster sensor** | **High** |
