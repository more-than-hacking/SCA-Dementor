# Dementor — SCA Scanner

**The CVEs that actually reach your code.**

> Part of the **More Than Hacking (MTH)** Dementor toolset. Prefer a pipeline/CLI? See the
> lightweight companion: [**SCA-Dementor-CLI**](https://github.com/more-than-hacking/SCA-Dementor-CLI).
> This is the reachability-aware dashboard edition — call-graph reachability + optional AI triage.

**Reachability-aware Software Composition Analysis.** Most SCA tools drown you in "critical"
CVEs for libraries you barely touch. Dementor answers the only question that matters:
**is the vulnerable code actually reachable in *your* code — and can it be exploited?**

It runs in **two modes**:

- **Normal scan** *(default, no API key, free)* — deterministic reachability using a
  tree-sitter call graph + symbol analysis. Tells you whether a known-vulnerable function is
  actually **called** in your code (`latent` → `imported-unused` → `reachable`).
- **AI scan** *(bring your own LLM key)* — everything Normal does, **plus** an AI layer that
  judges *exploitability*: is untrusted input reaching the call, is it mitigated, is it a real
  active exploit? Turns "64 scary criticals" into "the 6 that actually matter, with evidence."

Fully open-source. Vulnerability data (OSV, EPSS, CISA KEV) is **keyless and free**. The AI
layer is **bring-your-own-key** — free on Google Gemini's free tier, or a few cents at scale.

---

## How it decides (the layers)

| Layer | Needs a key? | Answers |
|---|---|---|
| **1. Detection** — dependency parse + exact-version match against [OSV](https://osv.dev), including **transitive** deps (lockfiles) | ❌ | *Which vulnerable libraries are present?* |
| **2. Prioritization** — [EPSS](https://www.first.org/epss/) exploit-probability + [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | ❌ | *Which CVEs are actually being exploited in the wild?* |
| **3. Reachability** — tree-sitter call graph + vulnerable-symbol matching | ❌ | *Is the vulnerable function on a real call path in my code?* |
| **4. Exploitability** — CVE-aware LLM analysis, mitigation-aware | ✅ (AI scan) | *Reachable **and** exploitable — with a proof chain and mitigations.* |

Layers 1–3 are **deterministic facts**. Layer 4 is **AI-assisted judgment** — non-deterministic
and meant for human review. That separation is deliberate: we never present a guess as a fact.

---

## Quick start (Docker)

```bash
git clone <your-repo-url> dementor
cd dementor
cp .env.example .env            # then edit .env
docker compose up --build
# open http://localhost:5000
```

Minimum `.env` for a **Normal scan** (no AI):
```bash
GITHUB_TOKEN=ghp_your_token_here     # repo (private) or public_repo; read:org for whole-org scans
ORG_NAME=your-github-org
```
Add these to unlock the **AI scan** (bring your own key — Gemini free tier works):
```bash
LLM_PROVIDER=gemini                  # gemini | openai | anthropic
LLM_API_KEY=your_key                 # https://aistudio.google.com/apikey
LLM_MODEL=gemini-2.5-flash
```
See [`.env.example`](.env.example) for all options (rate-limit backoff, worker count, pricing overrides).

> **No key? No problem.** Normal mode does full detection + prioritization + deterministic
> reachability with zero API calls. The AI scan is purely additive.

### Run without Docker
```bash
pip install -r requirements.txt
python server.py                     # http://localhost:5000  (PORT=5050 to change)
```

---

## Getting repos in — GitHub *or* local upload

| Source | How |
|---|---|
| **GitHub** | Config tab → save token + org → **Fetch all from GitHub**, or scan by `owner/repo` / URL |
| **Local upload** | Repositories tab → **Upload repo(s)** → pick one or more **`.zip`** files (no GitHub, no token needed) |

Uploaded repos are extracted locally (zip-slip protected), marked **local**, and scanned exactly
like cloned repos — great for scanning code you can't or won't push to GitHub.

---

## Using the dashboard

1. **Config** — token + org (optional), pick **Scan mode**: *Normal* (default) or *AI scan*.
2. **Repositories** — fetch from GitHub or upload `.zip`s; **Scan** / **Re-scan** each; pin **Keep**
   to retain a clone; **Clear findings** (keeps clone) or **Delete repo** (removes clone + findings).
3. **Scans** — live streaming log per job; **Stop** a running scan anytime; history persists across restarts.
4. **Results** — findings ranked by reachability + threat intel; per-row **Delete**; click a row for
   the evidence: the vulnerable line highlighted, the call path, mitigations, and CVE details.
5. **Reachability** — the exploitable findings with their data-flow paths.

### What the reachability verdict means

| Verdict | Meaning |
|---|---|
| **Latent** | Declared in a manifest but not imported/used in code |
| **Imported-unused** | Library is used, but the *vulnerable* function isn't called |
| **Reachable** | The vulnerable function is actually called (deterministic) |
| **Active exploit** *(AI scan only)* | Reachable **and** a triggering condition is present, no mitigation |

---

## Disk & retention

- **Git clones are freed after each scan by default** (findings stay in the report; a re-scan
  re-clones). Keeps disk small — matters in Docker.
- **Pin "Keep"** on any repo to retain its source (for the flow view + fast re-scans).
- **Uploaded repos are always kept** — their files are the only copy.

---

## Supported languages / ecosystems

| Language | Manifests | Transitive resolution | Call graph |
|---|---|---|---|
| Python | `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `pyproject.toml` | ✅ lockfiles | ✅ |
| Node.js | `package.json`, `package-lock.json` (v1/v2/v3) | ✅ lockfiles | ✅ |
| Java (Maven) | `pom.xml` | ✅ `mvn dependency:tree` (opt-in) | ✅ |
| Go | `go.mod`, `go.sum` | ✅ `go list -m all` (opt-in) | ✅ |

Tool-based transitive resolution (Maven/Go) is opt-in via `DEMENTOR_TOOL_RESOLVE=1`. All ecosystems
get CVE data from OSV. Infrastructure files (Dockerfiles, shell, CI YAML) are also scanned.

---

## Architecture

```
dependency_parser  →  OSV match (+ transitive)  →  EPSS/KEV enrich
                                 │
                         reachability_scan
                    ┌────────────┴─────────────┐
              Normal (no AI)              AI scan (LLM)
        tree-sitter call graph      + exploitability / mitigation
        + symbol matching             judgment on the reachable set
                    └────────────┬─────────────┘
                          reconciled verdict  →  dashboard
```

Key modules: [`server.py`](dementor_sca/server.py) (Flask API + SSE), [`scan_runner.py`](dementor_sca/scan_runner.py)
(background orchestrator), [`reachability_scan.py`](dementor_sca/reachability_scan.py) (detection + deterministic/AI reachability),
[`callgraph.py`](dementor_sca/callgraph.py) (tree-sitter call graph), [`pipeline_zero_fp.py`](dementor_sca/pipeline_zero_fp.py)
(OSV + symbol extraction), [`threat_intel.py`](dementor_sca/threat_intel.py) (EPSS/KEV), [`transitive_resolver.py`](dementor_sca/transitive_resolver.py).

---

## Testing

```bash
for t in tests/test_*.py; do python "$t"; done      # 15 test suites
python benchmark/run_benchmark.py                   # reachability micro-benchmark
```
The benchmark is a **curated micro-benchmark** of the *deterministic* engine (no LLM): 14 hand-written
cases across Python/JS/Java/Go — 8 genuinely reachable, 6 latent — run through the real tree-sitter
call graph. On this controlled set it separates reachable from latent with no false positives/negatives
(vs a naive "flag-everything" baseline at ~57% precision). It is a demonstration of the engine on
constructed cases, **not** a claim of perfect accuracy on arbitrary real-world code; it also **documents
a known gap it misses** (variable/data-flow aliasing) rather than hiding it.

---

## Honest limitations

- **Deterministic reachability is symbol-driven.** When an advisory names the vulnerable function
  (most do), Normal mode pinpoints it precisely. When OSV lists *no* function name, Normal mode can
  only confirm the library is imported — the **AI scan** reads the CVE description to fill that gap.
- **The AI exploitability verdict is non-deterministic** and can occasionally over- or under-claim.
  It is meant to *prioritize for a human*, not to replace review. The underlying facts (detection,
  version match, call-path) are deterministic and reproducible.
- **No runtime/dynamic analysis** (eBPF/IAST) yet — reachability is static. See `ROADMAP.md`.

---

## Configuration reference

| Env var | Purpose | Default |
|---|---|---|
| `GITHUB_TOKEN`, `ORG_NAME` | GitHub access | — |
| `LLM_PROVIDER` / `LLM_API_KEY` / `LLM_MODEL` / `LLM_API_URL` | AI scan (BYO key) | gemini / — / gemini-2.5-flash |
| `PORT` | Server port | 5000 |
| `REACHABILITY_WORKERS` | Parallel reachability workers | 4 |
| `LLM_MAX_RETRIES` / `LLM_BACKOFF_BASE` / `LLM_BACKOFF_MAX` | Rate-limit backoff | 5 / 2 / 60 |
| `DEMENTOR_TOOL_RESOLVE` | Enable Maven/Go transitive resolution | off |
| `DEMENTOR_MAX_UPLOAD_MB` | Max uploaded repo size | 500 |

Credentials can also live in `config/org_config.yaml` (gitignored); env vars take precedence.

---

## License

**MIT** — see [`LICENSE`](LICENSE). © More Than Hacking (MTH) — Yaswanth Sivadanam. Third-party
dependency licenses (all MIT-compatible; no GPL/AGPL) are documented in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md). Vulnerability data © their respective sources
(OSV, FIRST/EPSS, CISA).
