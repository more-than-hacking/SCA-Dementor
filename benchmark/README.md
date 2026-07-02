# Dementor Reachability Benchmark

The **scoreboard** for Dementor's core claim: *naive SCA flags every vulnerable library that's
present; Dementor tells you which ones are actually **reachable** — cutting false positives
without losing real findings.*

## What it measures

For a set of labeled projects, where ground truth (reachable vs. latent) is known **by
construction**, it computes:

- **Reachability recall** — of the truly-reachable vulns, how many Dementor confirms reachable.
- **Reachability precision** — of those it flags reachable, how many really are.
- **False-positive cut** — of naive SCA's false alarms (vulnerable version present but *not*
  reached), how many Dementor correctly suppresses.
- **Transitive detection** — whether transitive-only libs (in the lockfile, not the manifest)
  are surfaced at all.

## Why it's honest / reproducible

- **Deterministic & offline.** It exercises only the *deterministic* engine — the tree-sitter
  call graph (`build_reachability_paths`) and the lockfile transitive resolver. **No LLM, no
  network.** Anyone gets the same numbers. (The LLM layer refines further and can be benchmarked
  separately once a provider is configured.)
- **Ground truth by construction.** Each fixture is a tiny project where we *know* whether the
  vulnerable function is genuinely on a reachable call path.
- **Naive baseline = "flag everything present"** — exactly what ordinary version-match SCA does
  (100% recall, poor precision). Dementor's value is the precision gain at no recall loss.

## Current result (14 cases — Python, JavaScript, Java, Go)

```
Reachability recall    : 100.0%
Reachability precision : 100.0%
Naive SCA precision    :  57.1%   (flags everything present)
Dementor precision     : 100.0%
False-positive cut     : 100.0%   (6/6 latent findings suppressed)
Transitive detection   : 2/2      (lodash surfaced from package-lock.json)

Known limitations (NOT in headline):
  py_var_indirection     MISSED (expected — documented gap) [variable/data-flow aliasing]
```

Includes alias-resolved cases (`from yaml import load as L`, `import {defaultsDeep as dd}`) which
were previously a known gap and now pass after call-graph alias support.

Modeled on real CVEs: PyYAML `yaml.load` (CVE-2020-14343), lodash `defaultsDeep`
(CVE-2019-10744), SnakeYAML `load` (CVE-2022-1471), gopkg.in/yaml.v2 `Unmarshal` (CVE-2019-11254).
Cases cover: direct reachable, multi-hop (3 hops), latent-because-only-safe-function-used,
latent-because-never-imported, transitive-reachable, transitive-present-but-unused — across all
four supported languages. A `KNOWN_GAP_CASES` bucket reports patterns the static core misses
today (e.g. aliased imports) separately, so the headline isn't cherry-picked.

## Honest scope (what this is NOT, yet)

- It's a **controlled** set (6 fixtures), not a large real-world corpus. It proves the *mechanism*
  separates reachable from latent cleanly; it is **not** a claim of 100% accuracy on arbitrary code.
- It measures the **static** reachability decision. The deep-library-internals and Case-B
  (autonomous) gaps documented in `ROADMAP.md` are not yet exercised here.
- **Next step to make it bulletproof:** add real-world repos with known CVEs (e.g. pinned
  vulnerable versions of popular libs) and hand-label reachability, growing `CASES`.

## Run

```bash
python benchmark/run_benchmark.py
```

Add a case = append a dict to `CASES` in `run_benchmark.py` (fixtures are inline; no external files).
