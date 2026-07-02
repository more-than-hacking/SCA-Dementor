"""Transitive dependency resolution — expand direct deps with their full resolved graph.

Most real-world CVEs live in *transitive* dependencies (deps of deps). The manifest parsers
(`requirements.txt`, `package.json`, `pom.xml`, …) only see *direct* deps, so those CVEs are
invisible. This module expands the direct-dep list by reading **lockfiles** that sit next to
each manifest — lockfiles already pin the entire resolved tree (direct + transitive).

Design choices (deliberate, for an open-source tool that must "just work"):
- **Lockfile-based, pure-Python, offline.** No `npm install` / `mvn` / network needed — fast,
  deterministic, reproducible, and safe to run in CI without a build toolchain.
- **Graceful degradation.** If no lockfile is present for a manifest, we leave that manifest's
  deps untouched (direct-only) rather than fail. AI-style "enhancement, not a hard gate."
- **Non-destructive.** Every original dep is preserved and tagged `dep_type="direct"`; newly
  discovered deps are appended with `dep_type="transitive"`.

Resolution strategy by ecosystem:
- **Lockfile-based (offline, always on):** npm (package-lock.json / npm-shrinkwrap.json),
  Python (Pipfile.lock, poetry.lock).
- **Tool-based (opt-in via `DEMENTOR_TOOL_RESOLVE=1`, needs the build tool + network):** Maven
  (`mvn dependency:tree`) and Go (`go list -m all`). Off by default so normal scans stay fast and
  offline; enable for Java/Go-heavy internal scans. `DEMENTOR_TOOL_TIMEOUT` bounds each call.
- **Not yet:** Gradle (`gradle dependencies`) — follow-up. (Go is also partially covered offline
  because modern `go.mod` lists `// indirect` deps that the go parser already reads.)
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)

# Maven/Gradle/Go have no universal lockfile — resolving their transitive graph means invoking
# the build tool (network + build), which is slow. Off by default so normal scans stay fast and
# offline; enable for Java/Go-heavy internal scans with DEMENTOR_TOOL_RESOLVE=1.
_TOOL_RESOLVE = os.getenv("DEMENTOR_TOOL_RESOLVE", "").lower() in ("1", "true", "yes")
_TOOL_TIMEOUT = int(os.getenv("DEMENTOR_TOOL_TIMEOUT", "180"))


def resolve_transitive_deps(deps: list) -> list:
    """Expand a list of direct deps with transitive deps found in adjacent lockfiles.

    Input/output dep dict shape (matches the manifest parsers):
        {"ecosystem": "npm", "file": "/abs/package.json", "library": "foo",
         "version": "1.2.3", "resolved": "1.2.3", ...}

    Returns the original deps (tagged `dep_type="direct"`) plus any transitive deps
    (tagged `dep_type="transitive"`, with `lockfile` set), deduped by
    (ecosystem, library, version). Original deps always win a dedupe collision.
    """
    if not deps:
        return deps

    # Tag every incoming dep as direct (don't clobber an explicit tag).
    for d in deps:
        d.setdefault("dep_type", "direct")

    # Index existing deps so we never duplicate or override a direct dep.
    seen: dict = {}  # (ecosystem, library, version) -> dep
    direct_names: dict = {}  # (ecosystem, library) -> True  (for marking lockfile entries)
    for d in deps:
        eco = (d.get("ecosystem") or "").lower()
        key = (eco, d.get("library"), d.get("version"))
        seen[key] = d
        direct_names[(eco, d.get("library"))] = True

    # Group direct deps by (ecosystem, manifest directory) so we find the right lockfile.
    groups: dict = {}
    for d in deps:
        eco = (d.get("ecosystem") or "").lower()
        f = d.get("file") or ""
        manifest_dir = str(Path(f).parent) if f else ""
        groups.setdefault((eco, manifest_dir), []).append(d)

    transitive: list = []
    for (eco, manifest_dir), group in groups.items():
        resolver = _RESOLVERS.get(eco)
        if resolver is None or not manifest_dir:
            continue
        try:
            entries = resolver(Path(manifest_dir))
        except Exception as e:  # never let resolution break a scan
            log.debug("transitive: %s resolver failed in %s: %s", eco, manifest_dir, e)
            continue
        if not entries:
            continue

        # The manifest file these transitive deps belong to (use the group's first dep's file).
        manifest_file = group[0].get("file", "")
        added = 0
        for name, version, lockfile, meta in entries:
            if not name or not version:
                continue
            key = (eco, name, version)
            if key in seen:
                continue  # already a direct dep (or already added)
            is_direct = (eco, name) in direct_names  # same pkg, different version → still transitive
            new_dep = {
                "ecosystem": eco,
                "file": manifest_file,
                "library": name,
                "version_constraint": version,
                "version": version,
                "resolved": version,
                "dep_type": "direct" if is_direct else "transitive",
                "lockfile": lockfile,
            }
            if meta.get("dev"):
                new_dep["dev"] = True
            seen[key] = new_dep
            transitive.append(new_dep)
            added += 1
        if added:
            log.info("transitive: +%d deps from %s (%s)", added, Path(entries[0][2]).name, eco)

    if transitive:
        n_trans = sum(1 for d in transitive if d.get("dep_type") == "transitive")
        log.info("Transitive resolution: %d direct → %d total (+%d transitive)",
                 len(deps), len(deps) + len(transitive), n_trans)
    return deps + transitive


# ---------------------------------------------------------------------------
# npm — package-lock.json (lockfileVersion 1, 2, 3) and npm-shrinkwrap.json
# ---------------------------------------------------------------------------

def _resolve_npm(manifest_dir: Path):
    """Return [(name, version, lockfile_path, meta), …] for an npm project."""
    for lock_name in ("package-lock.json", "npm-shrinkwrap.json"):
        lock = manifest_dir / lock_name
        if lock.is_file():
            break
    else:
        return []

    try:
        data = json.loads(lock.read_text("utf-8", "ignore"))
    except Exception as e:
        log.debug("transitive: cannot parse %s: %s", lock, e)
        return []

    out: list = []
    lock_str = str(lock)

    # lockfileVersion 2/3: flat "packages" map keyed by install path.
    packages = data.get("packages")
    if isinstance(packages, dict):
        for path, info in packages.items():
            if not path or "node_modules/" not in path:
                continue  # "" is the root project; non-node_modules are workspaces
            if not isinstance(info, dict):
                continue
            version = info.get("version")
            if not version or info.get("link"):
                continue
            # Package name = path component after the LAST "node_modules/".
            name = path.split("node_modules/")[-1]
            out.append((name, version, lock_str, {"dev": bool(info.get("dev"))}))
        return out

    # lockfileVersion 1: nested "dependencies" tree.
    deps = data.get("dependencies")
    if isinstance(deps, dict):
        _walk_npm_v1(deps, lock_str, out)
    return out


def _walk_npm_v1(deps: dict, lock_str: str, out: list):
    for name, info in deps.items():
        if not isinstance(info, dict):
            continue
        version = info.get("version")
        if version:
            out.append((name, version, lock_str, {"dev": bool(info.get("dev"))}))
        nested = info.get("dependencies")
        if isinstance(nested, dict):
            _walk_npm_v1(nested, lock_str, out)


# ---------------------------------------------------------------------------
# Python — Pipfile.lock (JSON) and poetry.lock (TOML)
# ---------------------------------------------------------------------------

def _resolve_python(manifest_dir: Path):
    out: list = []
    pipfile_lock = manifest_dir / "Pipfile.lock"
    if pipfile_lock.is_file():
        out.extend(_resolve_pipfile_lock(pipfile_lock))
    poetry_lock = manifest_dir / "poetry.lock"
    if poetry_lock.is_file():
        out.extend(_resolve_poetry_lock(poetry_lock))
    return out


def _resolve_pipfile_lock(lock: Path):
    try:
        data = json.loads(lock.read_text("utf-8", "ignore"))
    except Exception as e:
        log.debug("transitive: cannot parse %s: %s", lock, e)
        return []
    out: list = []
    lock_str = str(lock)
    for section, is_dev in (("default", False), ("develop", True)):
        for name, info in (data.get(section) or {}).items():
            if not isinstance(info, dict):
                continue
            version = (info.get("version") or "").lstrip("=")  # "==2.28.0" -> "2.28.0"
            if version:
                out.append((name, version, lock_str, {"dev": is_dev}))
    return out


def _resolve_poetry_lock(lock: Path):
    toml_load = _toml_loader()
    if toml_load is None:
        log.debug("transitive: no TOML parser available for %s (need py3.11+ or tomli)", lock)
        return []
    try:
        with open(lock, "rb") as f:
            data = toml_load(f)
    except Exception as e:
        log.debug("transitive: cannot parse %s: %s", lock, e)
        return []
    out: list = []
    lock_str = str(lock)
    for pkg in data.get("package", []):
        name, version = pkg.get("name"), pkg.get("version")
        is_dev = pkg.get("category") == "dev"  # poetry <1.5; newer uses groups
        if name and version:
            out.append((name, version, lock_str, {"dev": is_dev}))
    return out


def _toml_loader():
    """Return a `load(fileobj)` TOML parser: stdlib tomllib (3.11+) or tomli, else None."""
    try:
        import tomllib  # py3.11+
        return tomllib.load
    except ModuleNotFoundError:
        try:
            import tomli
            return tomli.load
        except ModuleNotFoundError:
            return None


# ---------------------------------------------------------------------------
# Maven — `mvn dependency:tree` (no universal lockfile). Tool-invoked, opt-in.
# ---------------------------------------------------------------------------

def _parse_maven_tree(output: str):
    """Parse `mvn dependency:tree` text output → [(group:artifact, version, marker, meta), …].

    Lines look like `[INFO] +- org.yaml:snakeyaml:jar:1.30:compile`. We extract
    groupId:artifactId and the version, skipping the root project line (no tree connector)."""
    out, seen = [], set()
    gav = re.compile(r"([\w.\-]+):([\w.\-]+):[\w.\-]+:([\w.\-]+)(?::[\w.\-]+)?")
    for line in output.splitlines():
        if "+-" not in line and "\\-" not in line:
            continue  # skip the root project line (and non-tree noise)
        m = gav.search(line)
        if not m:
            continue
        lib = f"{m.group(1)}:{m.group(2)}"
        ver = m.group(3)
        key = (lib, ver)
        if key not in seen:
            seen.add(key)
            out.append((lib, ver, "mvn dependency:tree", {}))
    return out


def _resolve_maven(manifest_dir: Path):
    if not _TOOL_RESOLVE or not shutil.which("mvn") or not (manifest_dir / "pom.xml").is_file():
        return []
    try:
        # NOTE: do NOT pass -q — quiet mode suppresses the [INFO] tree lines the parser reads.
        r = subprocess.run(
            ["mvn", "-B", "org.apache.maven.plugins:maven-dependency-plugin:tree",
             "-DoutputType=text"],
            cwd=str(manifest_dir), capture_output=True, text=True, timeout=_TOOL_TIMEOUT,
        )
    except Exception as e:
        log.debug("transitive: mvn dependency:tree failed in %s: %s", manifest_dir, e)
        return []
    return _parse_maven_tree((r.stdout or "") + "\n" + (r.stderr or ""))


# ---------------------------------------------------------------------------
# Go — `go list -m all` (go.mod lists direct + // indirect; this gets the full set).
# ---------------------------------------------------------------------------

def _parse_go_list(output: str):
    """Parse `go list -m all` → [(module, version, marker, meta), …]. Lines are
    `module version`; the main module (first line, no version) is skipped. `=>` replace
    directives take the replacement version."""
    out, seen = [], set()
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue  # main module line (no version)
        mod, ver = parts[0], parts[1]
        if "=>" in parts:  # replace: module v1 => other v2  → use the effective tail
            tail = parts[parts.index("=>") + 1:]
            if len(tail) >= 2:
                mod, ver = tail[0], tail[1]
        if not re.match(r"v\d", ver):
            continue
        key = (mod, ver)
        if key not in seen:
            seen.add(key)
            out.append((mod, ver, "go list -m all", {}))
    return out


def _resolve_go(manifest_dir: Path):
    if not _TOOL_RESOLVE or not shutil.which("go") or not (manifest_dir / "go.mod").is_file():
        return []
    try:
        r = subprocess.run(
            ["go", "list", "-m", "all"],
            cwd=str(manifest_dir), capture_output=True, text=True, timeout=_TOOL_TIMEOUT,
            env={**os.environ, "GOFLAGS": "-mod=mod"},
        )
    except Exception as e:
        log.debug("transitive: go list -m all failed in %s: %s", manifest_dir, e)
        return []
    return _parse_go_list(r.stdout or "")


# Ecosystem (lowercase, as emitted by the parsers) -> resolver fn.
# Lockfile-based (offline, always on): npm, pypi.  Tool-based (opt-in via DEMENTOR_TOOL_RESOLVE): maven, go.
_RESOLVERS = {
    "npm": _resolve_npm,
    "pypi": _resolve_python,
    "maven": _resolve_maven,
    "go": _resolve_go,
}
