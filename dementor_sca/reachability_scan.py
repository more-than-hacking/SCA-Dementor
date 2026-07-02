# reachability_scan.py
import os
import logging
import subprocess
import re
import sys
import threading
from pathlib import Path
from typing import List, Pattern, Dict, Union
from urllib.parse import urlparse
from collections import OrderedDict
from github import Github, GithubException
import shutil

from dementor_sca import REPO_ROOT
from dementor_sca.llm_client import chat as _llm_chat
from dementor_sca.callgraph import build_caller_slice

# Cross-file call-graph slicing (tree-sitter). On by default; DEMENTOR_CROSSFILE=0 disables.
_CROSSFILE_ENABLED = os.getenv("DEMENTOR_CROSSFILE", "1").strip() not in ("0", "false", "no")

# --- Constants for Reachability Scan ---

# Source-code file extensions — used for import-pattern matching
CODE_EXTS = {".js", ".ts", ".jsx", ".tsx", ".py", ".go", ".java", ".kt", ".php", ".rb", ".c", ".cpp", ".h"}

# Ecosystem → source-file extensions. Reachability for a dependency must only search files of
# ITS OWN language — otherwise an npm package (e.g. `request`) matches Python `request`/`requests`
# in a .py file (different library, different ecosystem) and shows unrelated code as "usage".
_ECOSYSTEM_EXTS = {
    "npm":       {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue"},
    "pypi":      {".py", ".pyi"},
    "maven":     {".java", ".kt", ".kts", ".scala", ".groovy"},
    "go":        {".go"},
    "nuget":     {".cs", ".vb", ".fs"},
    "rubygems":  {".rb", ".erb", ".rake"},
    "packagist": {".php"},
    "cargo":     {".rs"},
    "crates.io": {".rs"},
    "hex":       {".ex", ".exs"},
    "pub":       {".dart"},
}


def _ecosystem_code_exts(ecosystem: str):
    """Extensions to restrict reachability search to, for a dependency's ecosystem. None if
    the ecosystem is unknown (then all code files are searched, as before)."""
    return _ECOSYSTEM_EXTS.get((ecosystem or "").strip().lower())

# Infrastructure / config files that can also reference a library name (e.g. Dockerfile CMD, shell scripts,
# requirements.txt, YAML pipelines, Makefiles…). These are scanned with a simpler bare-word search.
INFRA_NAMES = {
    "dockerfile", "dockerfile.dev", "dockerfile.prod", "dockerfile.test",
    "docker-compose.yml", "docker-compose.yaml",
    "makefile",
}
INFRA_EXTS  = {".sh", ".bash", ".zsh", ".fish", ".yaml", ".yml", ".toml", ".cfg", ".ini", ".env",
               ".txt",   # requirements.txt, constraints.txt
               ".conf", ".config", ".properties",
               ".mk", ".dockerfile",}

SKIP_DIRS = {".git", "node_modules", "dist", "build", "target", ".idea", "__pycache__", ".vscode", ".venv", "env", "vendor", "spec", "docs",
             # test code is not production-reachable — don't base reachability on mocked tests
             "test", "tests", "testing", "__tests__", "specs"}


def _is_test_file(file_path: Path) -> bool:
    """Test files by name convention (covers tests outside a tests/ dir)."""
    n = file_path.name
    stem = file_path.stem
    return (n.endswith(("Test.java", "Tests.java", "IT.java", "_test.go", "_test.py"))
            or stem.startswith(("Test", "test_"))
            or ".test." in n or ".spec." in n)


_CONFIG_EXTS = {".properties", ".yml", ".yaml", ".xml", ".conf", ".config", ".ini", ".env", ".toml"}


def _file_relevance(file_path: Path, hits: list, symbols) -> int:
    """Rank a matched file so the per-library LLM cap analyses the most likely-vulnerable
    files FIRST — never skipping the important one due to walk order:
        +100  the file actually contains a CVE symbol (e.g. sslmode, readObject)
        +30   config file (JDBC/SCRAM/TLS settings live here for config-driven CVEs)
        +20   source code
    """
    score = 0
    text = " ".join((h.get("context_snippet") or "") for h in hits).lower()
    for s in (symbols or []):
        tok = s.replace("::", ".").split(".")[-1].strip().lower()
        if len(tok) > 2 and tok in text:
            score += 100
            break
    ext = file_path.suffix.lower()
    if ext in _CONFIG_EXTS:
        score += 30
    elif ext in CODE_EXTS:
        score += 20
    return score


def _centered_snippet(text: str, pos: int, max_chars: int = 8000) -> str:
    """Return a window of `text` centered on `pos` (the match location), so the actual
    vulnerable usage is included even in large files — instead of blindly truncating to
    the first `max_chars` (which would miss a call 8000 chars down)."""
    if len(text) <= max_chars:
        return text
    half = max_chars // 2
    start = max(0, pos - half)
    end = min(len(text), start + max_chars)
    start = max(0, end - max_chars)
    chunk = text[start:end]
    head = "" if start == 0 else f"... [window around match — chars {start}–{end} of {len(text)} total]\n"
    tail = "" if end == len(text) else "\n... [truncated]"
    return head + chunk + tail

# Per-repo file list cache so we don't re-walk the same repo for every library (speeds up multi-library scans).
_FILE_LIST_CACHE: OrderedDict[str, List[Path]] = OrderedDict()
_FILE_LIST_CACHE_MAX = 32
_FILE_LIST_LOCK = threading.Lock()

# Cap how many LOW-SIGNAL files per library get sent to the LLM (early-exit on exploitable).
# High-signal files (those containing a CVE symbol, score >= 100) are analysed up to _HARD_MAX
# regardless, so the file holding the real vulnerable usage is never skipped. Raised to 10 so
# small/medium repos are analysed in full (no scary "5 of N" on a 7-file library). Override with
# env MAX_LLM_FILES_PER_LIBRARY; lower it to speed up very large scans.
_MAX_LLM_FILES_PER_LIBRARY = int(os.getenv("MAX_LLM_FILES_PER_LIBRARY", "10"))

API_CLONED_REPOS_PARENT = REPO_ROOT / "SCA_CLONED_REPOS"

ENABLE_SELECTIVE_DEBUG_REACHABILITY = False # Set to False by default

# Ensure the parent directory for cloned repositories exists when this script is imported
API_CLONED_REPOS_PARENT.mkdir(parents=True, exist_ok=True)

# --- URL Validation Helper ---
def validate_git_url(url: str) -> bool:
    """Validates that a URL is properly formatted for Git operations."""
    try:
        result = urlparse(url)
        return all([result.scheme in ('http', 'https'), result.netloc])
    except:
        return False

# --- Helper Functions for Reachability Scan ---

# Distribution name → import/module name, for ecosystems where they differ.
# The manifest/OSV reports the *distribution* name (e.g. "PyYAML") but source code
# imports the *module* name (e.g. "yaml"). Without this mapping the library-presence
# grep fails and the CVE is silently dropped as "not used". Extend as needed.
_KNOWN_IMPORT_ALIASES = {
    "pyyaml": ["yaml"],
    "beautifulsoup4": ["bs4"],
    "scikit-learn": ["sklearn"],
    "pillow": ["PIL"],
    "opencv-python": ["cv2"],
    "opencv-python-headless": ["cv2"],
    "python-dateutil": ["dateutil"],
    "msgpack-python": ["msgpack"],
    "protobuf": ["google.protobuf"],
    "setuptools": ["setuptools", "pkg_resources"],
    "attrs": ["attr", "attrs"],
    "pyjwt": ["jwt"],
    "pycryptodome": ["Crypto"],
    "pymongo": ["pymongo", "bson", "gridfs"],
}


def _import_aliases(library: str) -> set:
    """Candidate import/module names for a distribution name.

    Combines a curated table with conservative heuristics (case, common
    python-/-python affixes, dash→underscore/removed). Helps the presence grep
    survive distribution≠module mismatches. Errs toward a few extra precise
    terms; the downstream LLM gate filters any false positives.
    """
    aliases = set()
    lib = (library or "").strip()
    if not lib or ":" in lib:  # skip Maven coordinates
        return aliases
    low = lib.lower()
    aliases.update(_KNOWN_IMPORT_ALIASES.get(low, []))
    # Heuristic transforms
    base = low
    if base.startswith("python-"):
        base = base[len("python-"):]
    if base.endswith("-python"):
        base = base[:-len("-python")]
    for cand in {base, base.replace("-", "_"), base.replace("-", "")}:
        if cand and cand != low:
            aliases.add(cand)
    return {a for a in aliases if a}


def _module_prefixes_from_symbols(symbols) -> set:
    """Leading module token from dotted CVE symbols (e.g. 'yaml' from 'yaml.load').

    Vulnerable symbols often encode the real import name, so they recover the
    module even when the distribution name doesn't match."""
    prefixes = set()
    for s in (symbols or []):
        s = (s or "").strip()
        if "." in s:
            head = s.split(".", 1)[0]
            if head and head.isidentifier():
                prefixes.add(head)
    return prefixes


def _generate_package_prefixes(group_id: str, artifact_id: str, library: str, symbols=None) -> set:
    """
    Generates potential package prefixes. For Maven/Java libraries, it includes
    iterative parent package paths. For all other languages, it considers the
    full library path plus import-name aliases (distribution≠module) and module
    prefixes recovered from CVE symbols.
    """
    potential_package_prefixes = set()

    # Always include the full library string as the primary search term
    if library:
        potential_package_prefixes.add(library)

    # Import-name aliases + symbol-derived module prefixes (non-Maven ecosystems).
    potential_package_prefixes.update(_import_aliases(library))
    potential_package_prefixes.update(_module_prefixes_from_symbols(symbols))

    # Heuristic to determine if it's likely a Maven/Java library
    # 1. Primary: Presence of a colon (groupId:artifactId)
    # 2. Secondary: If no colon, but groupId looks like a Java package (dots, no slashes)
    is_maven_java_lib = False
    if ':' in library:
        is_maven_java_lib = True
    elif '.' in group_id and '/' not in library and re.match(r'^[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)*$', group_id, re.IGNORECASE):
        # This regex checks for valid Java-like package names (e.g., com.example.foo)
        is_maven_java_lib = True
    

    if is_maven_java_lib:
        # Apply the original Java/Maven specific prefix generation logic (iterative breaking down of package names)
        # This includes group_id segments, artifact_id combinations, and raw artifact_id.

        if group_id:
            current_package_parts = group_id.split('.')
            for i in range(len(current_package_parts)):
                prefix = ".".join(current_package_parts[:i+1])
                if prefix:
                    potential_package_prefixes.add(prefix)
            if len(current_package_parts) > 1 and current_package_parts[-1] in ["boot", "core", "api", "web", "mvc", "spring"]:
                potential_package_prefixes.add(".".join(current_package_parts[:-1]))

        if group_id and artifact_id:
            cleaned_artifact_id = re.sub(r'-(core|api|web|mvc|starter|spring)$', '', artifact_id, flags=re.IGNORECASE)
            # Ensure it's meaningful before adding. Avoid e.g. "foo" from "foo-bar" if group_id is also "foo"
            if cleaned_artifact_id and (cleaned_artifact_id != artifact_id or not group_id.endswith(cleaned_artifact_id.replace('-', '.'))):
                combined_prefix_1 = f"{group_id}.{cleaned_artifact_id.replace('-', '')}"
                combined_prefix_2 = f"{group_id}.{cleaned_artifact_id.replace('-', '.')}"
                
                for prefix_candidate in [combined_prefix_1, combined_prefix_2]:
                    if prefix_candidate:
                        parts = prefix_candidate.split('.')
                        for i in range(len(parts)):
                            sub_prefix = ".".join(parts[:i+1])
                            if sub_prefix:
                                potential_package_prefixes.add(sub_prefix)
        
        if artifact_id: # Useful for class names, etc.
            potential_package_prefixes.add(artifact_id)
            potential_package_prefixes.add(artifact_id.replace('-', '.'))

    # For all other languages, only the full 'library' path (already added at the beginning) is considered.
    # This fulfills the "ignore and try to match the full path" requirement for non-Java/Maven libraries.

    # Remove any empty strings and ensure uniqueness
    return {p for p in potential_package_prefixes if p}


def build_patterns_reachability(tokens: List[str], library: str) -> List[Pattern]:
    """
    Builds regex patterns for library usage in reachability scan.
    Includes common import/require patterns and token-specific patterns,
    now dynamically inferring namespaces including parent packages.
    """
    built_patterns = []

    library_parts = library.split(':')
    group_id = library_parts[0] if len(library_parts) > 0 else library
    artifact_id = library_parts[1] if len(library_parts) > 1 else library

    # Dynamically infer relevant package namespaces, including parent packages.
    # Pass the CVE symbol tokens so import-name aliases / module prefixes are covered.
    potential_package_prefixes = _generate_package_prefixes(group_id, artifact_id, library, symbols=tokens)

    # Prepare these prefixes for regex
    # Escape dots and slashes for regex, and sort to match longer/more specific patterns first
    unique_escaped_prefixes = sorted(
        [re.escape(p) for p in potential_package_prefixes if p], # escape everything now
        key=len,
        reverse=True
    )

    if unique_escaped_prefixes:
        namespace_or_group = "|".join(unique_escaped_prefixes)

        # 1. Flexible generic import/mention pattern using dynamically inferred namespaces
        # Uses both word boundaries for direct mentions and more flexible matching for import statements
        built_patterns.append(re.compile(
            rf"(?:require|import|from|use)\s+.*?(?:"
            rf"['\"]?(?:{namespace_or_group})['\"]?|" # Matches quoted or unquoted namespace in imports
            rf"\b(?:{namespace_or_group})\b" # Matches word boundary for direct code usage
            rf")"
        ))

        # 2. Java-specific import patterns (still useful for accuracy, apply if it's a Java-like prefix)
        for ns_pattern in unique_escaped_prefixes:
            # FIX: Changed re.unescape to check for escaped slashes directly
            # If the pattern looks like a Java package path (contains escaped dots '\.')
            # AND does NOT contain escaped forward slashes ('\/'), then it's likely a Java import.
            if r'\.' in ns_pattern and r'\\/' not in ns_pattern:
                built_patterns.append(re.compile(rf"import\s+{ns_pattern}\b;"))
                built_patterns.append(re.compile(rf"import\s+{ns_pattern}\.[*];"))


    # --- Original Specific Log4j usage patterns (still crucial for direct method calls) ---
    # These are kept separate because they target specific class/method names, not just package prefixes
    if "log4j" in library.lower() or "org.apache.logging.log4j" in library.lower():
        built_patterns.append(re.compile(
            r"(?:LogManager|org\.apache\.logging\.log4j(?::core)?\.LogManager)\.getLogger\s*\(.*?\)"
        ))
        built_patterns.append(re.compile(
            r"\b(?:logger|log)\.(?:error|warn|info|debug|fatal|trace)\s*\([^)]*?\w+\s*\)"
        ))

    # Original Specific Derby JDBC patterns
    if "derby" in library.lower() or "org.apache.derby" in library.lower():
        built_patterns.append(re.compile(r"jdbc:derby:", re.IGNORECASE))
        built_patterns.append(re.compile(
            r"Class\.forName\((?:\"|')org\.apache\.derby\.jdbc\.(?:EmbeddedDriver|ClientDriver|EmbeddedXADataSource|ClientXADataSource|BasicClientDriver|BasicEmbeddedDriver|AutoloadedDriver)[^\)'\"]*(?:\"|')\)"
        ))

    # 3. Patterns based on specific vulnerability symbols/tokens (original logic)
    for t in tokens:
        if not t:
            continue
        built_patterns.append(re.compile(re.escape(t))) # Exact match for token

        # For symbols with dots (e.g., 'Class.method'), also try matching just the last part
        parts = t.split('.')
        if len(parts) > 1:
            method_or_field_name = parts[-1]
            built_patterns.append(re.compile(rf"\b{re.escape(method_or_field_name)}\b\s*[:=\(]")) # Matches `method:` or `method=` or `method(`
            if len(parts) >= 2:
                last_two_parts = r'\.'.join(re.escape(p) for p in parts[-2:])
                built_patterns.append(re.compile(rf"\b{last_two_parts}\b")) # Matches `Class.method` with word boundaries

        # Also check for constructor calls
        if parts:
            class_name = parts[-1]
            built_patterns.append(re.compile(rf"new\s+\b{re.escape(class_name)}\b\s*\(.*?\)"))

    # Ensure uniqueness of patterns to avoid redundant searches
    unique_patterns_str = set()
    final_patterns = []
    for p in built_patterns:
        if p.pattern not in unique_patterns_str:
            unique_patterns_str.add(p.pattern)
            final_patterns.append(p)

    return final_patterns

def _is_scannable(file_path: Path) -> bool:
    """Return True if this file should be included in the reachability scan.

    Includes:
      • Source-code files  (CODE_EXTS)
      • Infrastructure / config files that can reference library names
        — Dockerfiles, shell scripts, YAML pipelines, Makefiles, requirements.txt, etc.
    """
    name  = file_path.name.lower()
    ext   = file_path.suffix.lower()
    return (
        ext in CODE_EXTS
        or ext in INFRA_EXTS
        or name in INFRA_NAMES
        or name.startswith("dockerfile")      # Dockerfile, Dockerfile.prod, …
    )


def scan_repo_files_reachability(repo_root: Path) -> List[Path]:
    """Recursively finds all relevant files in a repository for reachability scan.

    Scans source-code files (imports/calls) AND infrastructure files
    (Dockerfiles, shell scripts, YAML, Makefiles, requirements.txt, etc.)
    so that libraries referenced via CLI invocation or config are not missed.
    """
    all_files = []
    for dirpath, dirnames, filenames in os.walk(repo_root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            fp = Path(dirpath) / fname
            if _is_scannable(fp) and not _is_test_file(fp):
                all_files.append(fp)

    logging.debug(f"scan_repo_files: {len(all_files)} scannable files in {repo_root}")
    return all_files


def _get_repo_files_cached(repo_path: Path) -> List[Path]:
    """Return list of scannable files for a repo, using a per-repo cache so we walk each repo only once."""
    key = str(repo_path.resolve())
    with _FILE_LIST_LOCK:
        if key in _FILE_LIST_CACHE:
            # Move to end for LRU (OrderedDict)
            _FILE_LIST_CACHE.move_to_end(key)
            return _FILE_LIST_CACHE[key]
        files = scan_repo_files_reachability(repo_path)
        _FILE_LIST_CACHE[key] = files
        _FILE_LIST_CACHE.move_to_end(key)
        if len(_FILE_LIST_CACHE) > _FILE_LIST_CACHE_MAX:
            _FILE_LIST_CACHE.popitem(last=False)
        return files


def _detect_import_aliases(text: str, ext: str, anchors: set):
    """Local names bound to the library in THIS file, so aliased calls are not missed.

    Returns (module_aliases, symbol_aliases):
      - module_aliases  → used as `alias.method(...)`   (import x as y / const y=require('x') / import y from 'x')
      - symbol_aliases  → used bare as `alias(...)`      (from x import f as g / import {f as g} from 'x')
    `anchors` = the library's module/package name(s) as they appear in import statements.
    Covers Python, JS/TS, Go (Java imports are always qualified — no aliasing to track)."""
    anchors = {a for a in anchors if a and len(a) > 1}
    mod_aliases, sym_aliases = set(), set()
    if not anchors:
        return mod_aliases, sym_aliases
    alt = "|".join(sorted((re.escape(a) for a in anchors), key=len, reverse=True))
    if ext == ".py":
        for m in re.finditer(rf"(?m)^\s*import\s+(?:{alt})(?:\.\w+)*\s+as\s+(\w+)", text):
            mod_aliases.add(m.group(1))
        for m in re.finditer(rf"(?m)^\s*from\s+(?:{alt})\b[^\n]*?\bimport\b(.+)", text):
            for part in m.group(1).split(","):
                if " as " in part:
                    sym_aliases.add(part.split(" as ")[-1].strip().strip("()"))
    elif ext in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
        for m in re.finditer(rf"(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*['\"](?:{alt})['\"]\s*\)", text):
            mod_aliases.add(m.group(1))
        for m in re.finditer(rf"import\s+(?:\*\s+as\s+)?(\w+)\s+from\s+['\"](?:{alt})['\"]", text):
            mod_aliases.add(m.group(1))
        for m in re.finditer(rf"import\s*\{{([^}}]*)\}}\s*from\s+['\"](?:{alt})['\"]", text):
            for part in m.group(1).split(","):
                if " as " in part:
                    sym_aliases.add(part.split(" as ")[-1].strip())
    elif ext == ".go":
        for m in re.finditer(rf'(?m)^\s*(?:import\s+)?([A-Za-z]\w*)\s+"[^"]*(?:{alt})[^"]*"', text):
            if m.group(1) not in ("import", "_"):
                mod_aliases.add(m.group(1))
    _ok = lambda s: {a for a in s if a and a.isidentifier()}
    return _ok(mod_aliases), _ok(sym_aliases)


# Dependency-declaration files: a library appearing here is DECLARED, not USED. Lowercased.
_DEP_MANIFEST_FILES = {
    "pom.xml", "build.gradle", "build.gradle.kts", "package.json", "package-lock.json",
    "npm-shrinkwrap.json", "yarn.lock", "go.mod", "go.sum", "pipfile", "pipfile.lock",
    "poetry.lock", "setup.py", "setup.cfg", "pyproject.toml", "composer.json", "composer.lock",
    "gemfile", "gemfile.lock", "cargo.toml", "cargo.lock",
}


def grep_library_usage_reachability(file_path: Path, library: str, patterns: List[Pattern], symbols=None) -> List[Dict]:
    """
    Searches a file for library usage.

    For SOURCE-CODE files (.py, .js, .java …) the existing import-pattern logic runs.
    For INFRASTRUCTURE files (Dockerfile, shell scripts, YAML, Makefiles …) a simpler
    bare-word match is used — if the library name (or artifact id) appears anywhere in the
    file the full file content is handed to the LLM to judge the context.
    """
    usages = []

    try:
        text = file_path.read_text("utf-8", errors="ignore")
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {e}")
        return usages

    library_parts = library.split(':')
    group_id    = library_parts[0] if len(library_parts) > 0 else ""
    artifact_id = library_parts[1] if len(library_parts) > 1 else library

    # ── Infra files: bare-word match only ────────────────────────────────────
    # Dockerfiles, shell scripts, YAML, Makefiles etc. never contain Python/Java
    # import statements, but they CAN exec the library binary (e.g. `gunicorn`)
    # or reference it in a pip install / CMD line.
    # Dependency MANIFESTS only DECLARE a library — a match there is the declaration, NOT usage.
    # Counting it as usage made e.g. Pillow read as is_used=True with only requirements.txt as
    # "evidence", even though it is never imported. Manifests must not produce usage hits.
    _name_lc = file_path.name.lower()
    if _name_lc in _DEP_MANIFEST_FILES or (_name_lc.startswith("requirements") and _name_lc.endswith(".txt")):
        return usages

    is_infra = not (file_path.suffix.lower() in CODE_EXTS)
    if is_infra:
        # Search for the artifact id (e.g. "gunicorn") as a whole word (case-insensitive)
        search_name = artifact_id.lower()
        _m = re.search(rf"\b{re.escape(search_name)}\b", text, re.IGNORECASE)
        if _m:
            snippet = _centered_snippet(text, _m.start(), 8000)  # window around the match
            usages.append({
                "file":            str(file_path),
                "line":            1,
                "context_snippet": snippet,
                "pattern_matched": f"bare-word '{search_name}' in {file_path.name}",
                "file_type":       "infra",   # AI prompt hint
            })
        return usages

    # ── Source-code files: import-pattern logic (original) ───────────────────
    is_selective_debug_target = ENABLE_SELECTIVE_DEBUG_REACHABILITY and file_path.name in os.getenv("TARGET_DEBUG_FILE_REACHABILITY_NAME", "")

    potential_package_prefixes = _generate_package_prefixes(group_id, artifact_id, library, symbols=symbols)

    search_terms_for_initial_check = set()
    for p in potential_package_prefixes:
        if p:
            search_terms_for_initial_check.add(re.escape(p))

    library_present_in_file = False
    if search_terms_for_initial_check:
        combined_search_regex_terms = sorted(list(search_terms_for_initial_check), key=len, reverse=True)
        combined_search_regex = r"(?i)\b(?:" + "|".join(combined_search_regex_terms) + r")\b"
        combined_search_regex_flexible_import = r"(?i)(?:import|from|require|use)\s+.*?(?:" + "|".join(combined_search_regex_terms) + r")"

        if re.search(combined_search_regex, text) or re.search(combined_search_regex_flexible_import, text):
            library_present_in_file = True
    else:
        escaped_group_id = re.escape(group_id).replace('.', r'\.')
        if group_id and (re.search(rf"\b{escaped_group_id}\b", text) or re.search(rf"{re.escape(group_id)}[:.]", text)):
            library_present_in_file = True
        elif artifact_id and re.search(rf"\b{re.escape(artifact_id)}\b", text, re.IGNORECASE):
            library_present_in_file = True


    if not library_present_in_file:
        if is_selective_debug_target:
            logging.debug(f"DEBUG_REACH: Initial check: Library '{library}' NOT found in {file_path}. Skipping detailed pattern search.")
        return usages

    # When the library is present, send a snippet centered on the actual match. For large
    # files this WINDOWS around the usage (instead of truncating to the head) so a call
    # 8000 chars down isn't missed. Cap at 8000 chars to keep the prompt reasonable.
    MAX_FILE_CHARS = 8000

    # The library's OWN import module/package name(s) — _import_aliases (canonical, e.g.
    # PyJWT->jwt) + artifact_id (the npm/Go package name). NOT the broader symbol-derived
    # prefixes, which can be noisy (PyJWT's OSV text yields json/hashlib/hmac) and would
    # mis-center the window on an unrelated `json.load(`/`.get(` call.
    own_modules = {m for m in (set(_import_aliases(library)) | {artifact_id, group_id}) if m and len(m) > 1}
    # Multi-language alias detection (Python / JS / TS / Go): catch `import jwt as _jwt`,
    # `const _ = require('lodash')`, `import * as x`, `from x import f as g`, `yaml "path"`, etc.
    mod_aliases, sym_aliases = _detect_import_aliases(text, file_path.suffix.lower(), own_modules)
    qmods = own_modules | mod_aliases
    vuln_methods = {(s.replace("::", ".").split(".")[-1] or "").strip() for s in (symbols or [])}
    vuln_methods = {t for t in vuln_methods if len(t) > 2}

    # Center the window on the actual vulnerable USAGE (a call to a CVE symbol), not the
    # import at the top — otherwise a large file's window would miss the call far below.
    first_match = None
    # 0a) PREFER a QUALIFIED call: <module|alias>.<vuln_method>(  — precise; avoids centering on a
    #     generic `.get(`/`.load(` elsewhere that buried the real `_jwt.decode()` (PyJWT false-neg).
    if qmods and vuln_methods:
        qa = "|".join(sorted((re.escape(q) for q in qmods), key=len, reverse=True))
        ma = "|".join(sorted((re.escape(t) for t in vuln_methods), key=len, reverse=True))
        m = re.search(rf"\b(?:{qa})\.(?:{ma})\s*\(", text)
        if m:
            first_match = m.start()
    # 0b) bare call to a symbol-alias: `from x import f as g; g(...)` / `import {f as g}`.
    if sym_aliases:
        sa = "|".join(sorted((re.escape(q) for q in sym_aliases), key=len, reverse=True))
        m = re.search(rf"\b(?:{sa})\s*\(", text)
        if m and (first_match is None or m.start() < first_match):
            first_match = m.start()
    if first_match is None:
        for s in (symbols or []):                  # 1) a CALL to a vulnerable symbol: tok(
            tok = (s.replace("::", ".").split(".")[-1] or "").strip()
            if len(tok) > 2:
                m = re.search(rf"\b{re.escape(tok)}\s*\(", text)
                if m and (first_match is None or m.start() < first_match):
                    first_match = m.start()
    if first_match is None:                        # 2) any vulnerable symbol mention (qualified first)
        for s in sorted([s for s in (symbols or []) if s and len(s) > 2], key=lambda x: ("." not in x)):
            m = re.search(re.escape(s), text)
            if m:
                first_match = m.start()
                break
    if first_match is None:                        # 3) fall back to the earliest pattern match
        for pat in patterns:
            m = pat.search(text)
            if m and (first_match is None or m.start() < first_match):
                first_match = m.start()

    if first_match is not None:
        first_line = text.count("\n", 0, first_match) + 1
        usages.append({
            "file": str(file_path),
            "line": first_line,
            "context_snippet": _centered_snippet(text, first_match, MAX_FILE_CHARS),
            "pattern_matched": "library usage detected — file window sent for analysis",
        })
        if is_selective_debug_target:
            logging.debug(f"DEBUG_REACH: Pattern matched in {file_path} at line {first_line}; sending file window to LLM.")
    # No fallback "Generic Import" hit — if no code pattern matched, the library is not actively used here.

    return usages

def _analyse_code_usage(snippet: str, library: str, all_symbols: List[str], file_type: str = "code") -> Dict:
    """
    Single LLM call — pure file analysis, no CVE knowledge injected.

    Works for both source-code files (Python/Java/JS …) and infrastructure files
    (Dockerfile, shell scripts, YAML, Makefile …).

    `file_type` is either "code" (default) or "infra".
    """
    symbols_hint = f"\nKnown sensitive API symbols for this library: {', '.join(all_symbols[:20])}." if all_symbols else ""

    if file_type == "infra":
        context_block = f"""You are a senior application security engineer doing a reachability review.

The file below is an INFRASTRUCTURE file (Dockerfile, shell script, YAML pipeline, Makefile, or similar).
It references the library/tool `{library}`.{symbols_hint}

Your task: determine how `{library}` is referenced in this file and whether the usage creates a runtime security risk.

Infrastructure-specific guidance:
- A CMD / ENTRYPOINT / RUN / exec line that launches `{library}` as a server or process means the library IS actively used at runtime.
- A pip install / apt-get / COPY line only means the library is installed, not necessarily executed with user-controlled input.
- If the library is invoked with flags that expose a port or accept network traffic (e.g. `--bind`, `--port`) that is meaningful runtime exposure.
- "VULNERABLE_API_USED = YES" means the library binary/daemon is actively launched or called, not just installed.
- "USER_INPUT_IN_ARGS = YES" means arguments to that invocation come from env vars, user-supplied values, or external config.
- "EXPLOIT_WITHOUT_USER_INPUT = YES" means the library is auto-started and its known vulnerability can trigger without any user input.

**Full file content:**
{snippet}"""
    else:
        context_block = f"""You are a senior application security engineer doing a reachability review.

The full source file below contains code that references the library `{library}`.{symbols_hint}

Your task: read the ENTIRE file and decide whether the library is actively used in a way that creates a security risk.
Do NOT assume CVE details — judge purely from what the code actually does.

Focus on:
1. Which API methods/functions from `{library}` are actually CALLED anywhere in the file? (not just imported or declared)
2. Do any arguments to those calls come from user input, HTTP requests, CLI args, env vars, file reads, or any external/untrusted source?
3. Could the library's functionality be exploited even WITHOUT user input (e.g. auto-triggered on load, config-driven, deserialization)?
4. If the library is only declared in a manifest (pom.xml, requirements.txt) but never called in code — it is NOT used.

**Full source file:**
{snippet}"""

    prompt = f"""{context_block}

**Respond with EXACTLY this format — one value per line, no extra text:**
APIS_CALLED: comma-separated API method/function calls or CLI invocations observed, or NONE
VULNERABLE_API_USED: YES or NO  (YES = library is actively called/launched, not just installed or imported)
USER_INPUT_IN_ARGS: YES or NO  (YES = any argument to those calls/invocations is user/externally controlled)
INPUT_SOURCE: one-line description of where input comes from, or N/A
EXPLOIT_WITHOUT_USER_INPUT: YES or NO  (YES = library can be exploited without user input, e.g. auto-started server, config-driven deserialization)
ACTIVE_EXPLOIT: YES or NO  (YES = VULNERABLE_API_USED=YES AND (USER_INPUT_IN_ARGS=YES OR EXPLOIT_WITHOUT_USER_INPUT=YES))
USAGE_SUMMARY: one sentence — what the file does with `{library}` and why it is or is not a security risk
"""
    _EMPTY: Dict = {
        "apis_called": [],
        "vulnerable_api_used": False,
        "user_input_in_args": False,
        "input_source": "N/A",
        "exploit_without_user_input": False,
        "active_exploit": False,
        "usage_summary": "",
        "raw": "",
    }
    try:
        response = _llm_chat(prompt)
        result: Dict = {**_EMPTY, "raw": response}
        for raw_line in response.split("\n"):
            line = raw_line.strip()
            key, _, val = line.partition(":")
            key = key.strip().upper()
            val = val.strip()
            if key == "APIS_CALLED":
                result["apis_called"] = [a.strip() for a in val.split(",") if a.strip() and a.strip().upper() != "NONE"]
            elif key == "VULNERABLE_API_USED":
                result["vulnerable_api_used"] = val.upper().startswith("YES")
            elif key == "USER_INPUT_IN_ARGS":
                result["user_input_in_args"] = val.upper().startswith("YES")
            elif key == "INPUT_SOURCE":
                result["input_source"] = val
            elif key == "EXPLOIT_WITHOUT_USER_INPUT":
                result["exploit_without_user_input"] = val.upper().startswith("YES")
            elif key == "ACTIVE_EXPLOIT":
                result["active_exploit"] = val.upper().startswith("YES")
            elif key == "USAGE_SUMMARY":
                result["usage_summary"] = val
        return result
    except Exception as e:
        logging.error(f"LLM code analysis failed: {type(e).__name__}: {e}")
        return {**_EMPTY, "usage_summary": "Reachability analysis unavailable — the AI provider could not be reached (see server logs).", "raw": str(e)}


# Stage 2 can be toggled off for A/B comparison: DEMENTOR_CVE_STAGE=0
_CVE_STAGE_ENABLED = os.getenv("DEMENTOR_CVE_STAGE", "1").strip() not in ("0", "false", "no")


def trace_reachability_flow_llm(candidates_data: dict) -> dict:
    """
    Trace the EXACT call path from your code to the vulnerable sink using AI — but
    grounded: the LLM may only use functions/calls present in the provided real source,
    and every node it returns is VALIDATED against that source (hallucinated nodes are
    dropped). This resolves name-collisions (which `getLabelImage()` is really called?)
    that pure name-matching gets wrong.

    Input: output of callgraph.gather_flow_candidates.
    Returns {sink_function, sink_file, sink_symbol, paths, ai_verified}.
    """
    import json as _json

    sink_fn = candidates_data["sink_function"]
    sink_file = candidates_data["sink_file"]
    sink_symbol = candidates_data["sink_symbol"]
    sink_line = candidates_data.get("sink_line", 0)
    candidates = candidates_data.get("candidates", [])

    # Ground truth: the sink alone is always a valid (1-node) path from tree-sitter.
    base = {"sink_function": sink_fn, "sink_file": sink_file, "sink_symbol": sink_symbol,
            "sink_line": sink_line,
            "paths": [[{"function": sink_fn, "file": sink_file, "line": 0, "is_sink": True}]],
            "ai_verified": False}
    if not candidates or len(candidates) <= 1:
        return base

    valid = {(c["function"], c["file"]) for c in candidates}
    fn_to_file = {}
    for c in candidates:
        fn_to_file.setdefault(c["function"], c["file"])

    funcs_block = "\n\n".join(
        f"--- {c['file']}::{c['function']}()  (line {c['line']}) ---\n{c['source']}" for c in candidates
    )
    prompt = f"""You are tracing the EXACT call path to a vulnerable function in real code.

The vulnerable sink is `{sink_file}::{sink_fn}()`, which calls the vulnerable API `{sink_symbol}`.

Below are real function definitions from the codebase. Using ONLY the calls that
literally appear in these bodies — and resolving the receiver type from the code where
possible — output the actual call path(s) that reach `{sink_fn}()` from a top-level
entry function (one not called by any other function shown).

STRICT RULES (no hallucination):
- Use ONLY functions shown below. Never invent a function, file, or call.
- If a caller does not actually call into the chain in its shown body, exclude it.
- If no real caller exists in the provided code, return just the sink as a single path.
- Each node must be a function shown below.

FUNCTIONS:
{funcs_block}

Respond with ONLY a JSON object (no prose, no markdown fences):
{{"paths": [[{{"function": "<name>", "file": "<file>"}}, ... , {{"function": "{sink_fn}", "file": "{sink_file}"}}]]}}
Each path is ordered entry → … → sink. Include at most 4 paths."""

    try:
        resp = _llm_chat(prompt).strip()
        if resp.startswith("```"):
            resp = resp.split("```", 2)[1].lstrip("json").strip() if "```" in resp[3:] else resp.strip("`")
        # Extract the outermost JSON object.
        start, end = resp.find("{"), resp.rfind("}")
        data = _json.loads(resp[start:end + 1]) if start >= 0 and end > start else {}
    except Exception as e:
        logging.warning("flow trace LLM parse failed: %s", e)
        return base

    line_of = {(c["function"], c["file"]): c["line"] for c in candidates}
    out_paths = []
    for path in (data.get("paths") or [])[:4]:
        clean = []
        for node in path:
            fn = (node or {}).get("function", "").strip()
            file = (node or {}).get("file", "").strip() or fn_to_file.get(fn, "")
            # Anti-hallucination: node must be a real provided function.
            if (fn, file) not in valid and fn not in fn_to_file:
                continue
            if (fn, file) not in valid:
                file = fn_to_file.get(fn, file)
            clean.append({"function": fn, "file": file,
                          "line": line_of.get((fn, file), 0),
                          "is_sink": (fn == sink_fn and file == sink_file)})
        # Path must actually end at the sink.
        if clean and clean[-1]["is_sink"]:
            out_paths.append(clean)

    if not out_paths:
        return base
    return {"sink_function": sink_fn, "sink_file": sink_file, "sink_symbol": sink_symbol,
            "sink_line": sink_line, "paths": out_paths, "ai_verified": True}


# Ultra-generic method names that appear on countless objects — matching a bare '.name()' on
# these produces false reachability (e.g. Java `.length()` is everywhere). Never match on these
# alone, even if an advisory names them.
# Language/module builtins — NEVER a library's vulnerable API. Matching a bare 'require('/'import('
# is always a false positive (no CVE is "you called require"). Skipped unconditionally — zero
# false-negative risk.
_LANG_BUILTINS = {
    "require", "import", "export", "exports", "module", "define", "include", "use", "using", "from",
}
# Ultra-generic method names on countless objects (Java `.length()`, JS `.get()`…). A BARE match
# is a false positive — but a real library vuln CAN be one of these (e.g. a cache's `.get()`), so
# we still match them when QUALIFIED by the library's own module/alias (e.g. `mylib.get(`). That
# preserves true positives without the noise — no blanket false-negatives.
_GENERIC_CALL_NAMES = {
    "length", "size", "get", "set", "put", "add", "remove", "close", "open", "read", "write",
    "tostring", "equals", "hashcode", "name", "value", "valueof", "format", "print", "println",
    "empty", "build", "run", "call", "apply", "accept", "next", "hasnext", "iterator", "clone",
    "copy", "clear", "start", "stop", "init", "toarray", "tolist", "keys", "values", "items",
}


def _symbols_called_in_snippet(snippet: str, symbols, aliases=()) -> List[str]:
    """Regex fallback: which CVE symbols appear as a CALL in the snippet. Used for deterministic
    mode when the tree-sitter call graph is unavailable (infra files, unsupported languages).

    Precision rules (avoid the `require(`/`length(` false positives without losing real vulns):
      • language builtins (require/import/…) → never matched;
      • a QUALIFIED symbol `A.b` → matched as `A.b(`;
      • a bare GENERIC method (get/length/…) → matched ONLY when qualified by the library's own
        module/alias (`<alias>.method(`), never bare;
      • a bare SPECIFIC symbol (readObject, full_load, …) → matched bare `name(`.
    """
    called = []
    alias_pat = "|".join(re.escape(a) for a in (aliases or []) if a) or None
    for s in (symbols or []):
        parts = str(s).replace("::", ".").split(".")
        last = (parts[-1] or "").strip()
        if len(last) < 3 or last.lower() in _LANG_BUILTINS:
            continue
        # Qualified symbol `A.b` → match the qualified call exactly.
        if len(parts) >= 2 and parts[-2]:
            if re.search(r"\b" + re.escape(parts[-2]) + r"\." + re.escape(last) + r"\s*\(", snippet):
                called.append(s)
                continue
        if last.lower() in _GENERIC_CALL_NAMES:
            # generic method → require a library-alias qualifier; never match bare.
            if alias_pat and re.search(r"\b(?:" + alias_pat + r")\.\s*" + re.escape(last) + r"\s*\(", snippet):
                called.append(s)
            continue
        # specific bare symbol → a bare call is safe enough.
        if re.search(r"\b" + re.escape(last) + r"\s*\(", snippet):
            called.append(s)
    return called


def _deterministic_usage(snippet: str, library: str, all_symbols: List[str],
                         file_type: str, cslice) -> Dict:
    """Static (no-AI) reachability verdict for one hit — the engine behind 'Normal scan'.

    Matches the _analyse_reachability schema but sets only what STATIC analysis can PROVE:
      • vulnerable_api_used / vulnerable_function_reached — a known-vulnerable CVE sink is
        actually CALLED here (tree-sitter call graph via `cslice`, else a regex fallback).
    Exploitability (active_exploit / user_input / mitigation) is NOT decidable without AI,
    so it stays False and the summary says so. Normal-mode reachability caps at "reachable";
    the AI scan is what promotes a reachable finding to a confirmed active exploit.
    """
    result = {
        "apis_called": [], "vulnerable_api_used": False, "user_input_in_args": False,
        "input_source": "N/A", "exploit_without_user_input": False, "active_exploit": False,
        "vulnerable_function_reached": False, "matched_symbol": "", "confidence": "low",
        "mitigation": "", "usage_summary": "", "raw": "deterministic",
        "analysis_mode": "deterministic",
    }

    sink_called, matched, confidence = False, "", "low"
    # Strongest signal: tree-sitter found a real call to a CVE sink (AST, not text).
    if cslice is not None and getattr(cslice, "sink_function", ""):
        sink_called = True
        matched = cslice.sink_function
        confidence = "high" if getattr(cslice, "caller_count", 0) > 0 else "medium"
    else:
        # Fallback: regex — a CVE symbol is called in the snippet (infra / unsupported lang).
        regex_called = _symbols_called_in_snippet(snippet, all_symbols, _import_aliases(library))
        if regex_called:
            sink_called, matched, confidence = True, regex_called[0], "medium"
            result["apis_called"] = regex_called

    if sink_called:
        result["vulnerable_api_used"] = True
        result["vulnerable_function_reached"] = True
        result["matched_symbol"] = matched
        result["confidence"] = confidence
        if not result["apis_called"] and matched:
            result["apis_called"] = [matched]
        reach_note = ""
        if cslice is not None and getattr(cslice, "caller_count", 0) > 0:
            reach_note = (f" (reachable via {cslice.caller_count} caller(s) across "
                          f"{len(cslice.files_involved)} file(s))")
        result["usage_summary"] = (
            f"Static analysis: the vulnerable API `{matched}` from `{library}` is called in "
            f"code{reach_note}. Exploitability (inputs/mitigations) not assessed in Normal "
            f"mode — run an AI scan to confirm whether it's an active exploit."
        )
    else:
        result["confidence"] = "medium"
        result["usage_summary"] = (
            f"Static analysis: `{library}` is imported/referenced, but no call to a known "
            f"vulnerable API was found here. Run an AI scan for deeper judgment."
        )
    return result


def _analyse_reachability(snippet: str, library: str, vulns: List[Dict], all_symbols: List[str], file_type: str = "code") -> Dict:
    """
    Combined SINGLE-CALL reachability analysis (CVE-aware).

    Does the work of both _analyse_code_usage (is the library used?) and
    _confirm_cve_reachability (is the SPECIFIC vulnerable function reached?) in ONE
    LLM call — sending the file content only once. Halves tokens and latency versus
    running the two stages separately. Returns the union of both result schemas.
    """
    # CVE context — only the fields that matter, trimmed to keep tokens low.
    cve_lines = []
    for v in (vulns or [])[:6]:
        ids = ", ".join(v.get("cve_ids") or []) or v.get("osv_id", "") or "unknown"
        syms = [s for s in (v.get("vulnerability_usage_analysis") or []) if s and s.lower() != library.lower()]
        summary = (v.get("summary") or "").strip()
        details = (v.get("details") or "").strip().replace("\n", " ")[:300]
        sym_str = ", ".join(syms[:12]) if syms else "(no specific function named)"
        cve_lines.append(f"- {ids} [{v.get('severity','?')}]: {summary} | vulnerable symbols: {sym_str} | {details}")
    cve_block = "\n".join(cve_lines) if cve_lines else "(no CVE detail available)"
    file_kind = "INFRASTRUCTURE file (Dockerfile/shell/YAML/Makefile)" if file_type == "infra" else "source file"

    prompt = f"""You are a senior application security engineer doing a reachability review.

The {file_kind} below references the library `{library}`, which has these known vulnerabilities:
{cve_block}

Read the ENTIRE file and judge — from what the code ACTUALLY does — whether the library
is used and whether the SPECIFIC vulnerable code path above is reached (directly or via a
wrapper defined here). Merely importing or installing the library is NOT "used"/"reached".
If the advisory names no specific function, judge by the behaviour it describes.

CRITICAL — consider MITIGATIONS before declaring an active exploit. The vulnerable API may be
reached but NEUTRALIZED for the SPECIFIC CVE by code visible in this file. Examples:
- JWT algorithm-confusion CVE, but `algorithms=[...]` is pinned to a fixed list → mitigated.
- Deserialization CVE, but a safe loader / `SafeLoader` / allow-list of types is used → mitigated.
- Injection/SSRF CVE, but the dangerous argument is a HARDCODED trusted constant (not attacker
  input), or input is validated / escaped / allow-listed before the call → mitigated.
- Credential-leak / SSRF / redirect CVE that depends on the request TARGET (host/URL), but the
  host is a HARDCODED trusted endpoint (e.g. api.github.com) and only a path/query PARAMETER is
  user-controlled → the host-based vulnerability is NOT exposed → mitigated.
Only credit a mitigation that genuinely neutralizes the NAMED vulnerability, judged from the code
shown — never assume one that isn't visible. A reached-but-mitigated path is NOT an active exploit.

ALSO — some CVEs need a FURTHER triggering condition that must be VISIBLE in the code to be a real
exploit. In particular, INFORMATION-DISCLOSURE / data-leak CVEs where the affected object only
leaks if it is SERIALIZED, persisted, logged, returned over an API, or otherwise EXPOSED: merely
CREATING or USING that object (e.g. fitting a model that stores tokens in an attribute) is REACHED
but is NOT an active exploit unless that exposure is visible here. If the triggering/exposure
condition is not shown, set ACTIVE_EXPLOIT=NO and name the missing condition in USAGE_SUMMARY.

**File content:**
{snippet}

**Respond with EXACTLY this format — one value per line, no extra text:**
APIS_CALLED: comma-separated API calls/invocations observed, or NONE
VULNERABLE_API_USED: YES or NO  (library actively called/launched, not just imported)
USER_INPUT_IN_ARGS: YES or NO  (any argument is user/externally controlled)
INPUT_SOURCE: one-line where input comes from, or N/A
EXPLOIT_WITHOUT_USER_INPUT: YES or NO  (auto-triggered / config-driven exploit)
MITIGATION: one-line mitigation visible in the code that neutralizes THIS CVE, or NONE
ACTIVE_EXPLOIT: YES or NO  (YES only if VULNERABLE_API_USED=YES AND (USER_INPUT_IN_ARGS=YES OR EXPLOIT_WITHOUT_USER_INPUT=YES) AND MITIGATION=NONE)
VULNERABLE_FUNCTION_REACHED: YES or NO  (the SPECIFIC vulnerable API/path above is actually invoked here)
MATCHED_SYMBOL: the exact vulnerable function/API observed, or NONE
CONFIDENCE: HIGH or MEDIUM or LOW
USAGE_SUMMARY: one sentence — what the file does with `{library}`, the mitigation (if any), and why it is/ isn't a risk
"""
    _EMPTY = {
        "apis_called": [], "vulnerable_api_used": False, "user_input_in_args": False,
        "input_source": "N/A", "exploit_without_user_input": False, "active_exploit": False,
        "vulnerable_function_reached": False, "matched_symbol": "", "confidence": "low",
        "mitigation": "", "usage_summary": "", "raw": "",
    }
    try:
        response = _llm_chat(prompt)
        r = {**_EMPTY, "raw": response}
        for line in response.split("\n"):
            key, _, val = line.strip().partition(":")
            key, val = key.strip().upper(), val.strip()
            if key == "APIS_CALLED":
                r["apis_called"] = [a.strip() for a in val.split(",") if a.strip() and a.strip().upper() != "NONE"]
            elif key == "VULNERABLE_API_USED":
                r["vulnerable_api_used"] = val.upper().startswith("YES")
            elif key == "USER_INPUT_IN_ARGS":
                r["user_input_in_args"] = val.upper().startswith("YES")
            elif key == "INPUT_SOURCE":
                r["input_source"] = val
            elif key == "EXPLOIT_WITHOUT_USER_INPUT":
                r["exploit_without_user_input"] = val.upper().startswith("YES")
            elif key == "MITIGATION":
                r["mitigation"] = "" if val.upper() in ("NONE", "N/A", "") else val
            elif key == "ACTIVE_EXPLOIT":
                r["active_exploit"] = val.upper().startswith("YES")
            elif key == "VULNERABLE_FUNCTION_REACHED":
                r["vulnerable_function_reached"] = val.upper().startswith("YES")
            elif key == "MATCHED_SYMBOL":
                r["matched_symbol"] = "" if val.upper() in ("NONE", "") else val
            elif key == "CONFIDENCE":
                low = val.lower()
                r["confidence"] = "high" if "high" in low else ("medium" if "med" in low else "low")
            elif key == "USAGE_SUMMARY":
                r["usage_summary"] = val
        return r
    except Exception as e:
        logging.error(f"Combined reachability analysis failed: {type(e).__name__}: {e}")
        return {**_EMPTY, "usage_summary": "Reachability analysis unavailable — the AI provider could not be reached (see server logs).", "raw": str(e)}


def _confirm_cve_reachability(snippet: str, library: str, vulns: List[Dict], file_type: str = "code") -> Dict:
    """
    Stage 2 — CVE-AWARE confirmation: is the SPECIFIC vulnerable code path reached?

    Unlike _analyse_code_usage (deliberately CVE-blind, answers "is the library used
    riskily"), this stage is GIVEN the actual CVE details + the vulnerable symbols and
    asks the precise question: does THIS file invoke the vulnerable function/API
    (directly or via a wrapper), and does untrusted input reach it?

    Returns:
      vulnerable_function_reached: True/False
      matched_symbol:  the specific vulnerable symbol observed, or ""
      how_reached:     one-line description
      input_reaches:   True/False
      confidence:      "high" | "medium" | "low"
      reasoning:       one sentence
      raw:             raw model text
    """
    _EMPTY = {
        "vulnerable_function_reached": False,
        "matched_symbol": "",
        "how_reached": "",
        "input_reaches": False,
        "confidence": "low",
        "reasoning": "",
        "raw": "",
    }
    if not vulns:
        return _EMPTY

    # Build a compact, real-field CVE context block.
    cve_lines = []
    all_syms = set()
    for v in vulns[:6]:  # cap to keep the prompt bounded
        ids = ", ".join(v.get("cve_ids") or []) or v.get("osv_id", "") or "unknown"
        syms = [s for s in (v.get("vulnerability_usage_analysis") or []) if s and s.lower() != library.lower()]
        all_syms.update(syms)
        summary = (v.get("summary") or "").strip()
        details = (v.get("details") or "").strip().replace("\n", " ")[:400]
        sym_str = ", ".join(syms[:12]) if syms else "(no specific function named in advisory)"
        cve_lines.append(
            f"- {ids} [{v.get('severity','?')}]: {summary}\n"
            f"    vulnerable symbols: {sym_str}\n"
            f"    detail: {details}"
        )
    cve_block = "\n".join(cve_lines)
    file_kind = "infrastructure file" if file_type == "infra" else "source file"

    prompt = f"""You are a senior application security engineer confirming vulnerability reachability.

The {file_kind} below uses the library `{library}`, which has these known vulnerabilities:
{cve_block}

Decide — based ONLY on what the code actually does — whether the SPECIFIC vulnerable
code path above is reached in this file. The vulnerable function may be called directly,
or indirectly through a wrapper/helper defined in this file. If the advisory names no
specific function, judge whether the library is used in the manner the advisory describes.
Merely importing or installing the library is NOT "reached".

**File content:**
{snippet}

**Respond with EXACTLY this format — one value per line, no extra text:**
VULNERABLE_FUNCTION_REACHED: YES or NO  (YES = the specific vulnerable API/path above is actually invoked here)
MATCHED_SYMBOL: the exact vulnerable function/API call observed, or NONE
HOW_REACHED: one line — direct call / via wrapper / library run as process / not called
INPUT_REACHES_IT: YES or NO  (YES = untrusted/external input flows into that call)
CONFIDENCE: HIGH or MEDIUM or LOW
REASONING: one sentence justifying the verdict
"""
    try:
        response = _llm_chat(prompt)
        result = {**_EMPTY, "raw": response}
        for raw_line in response.split("\n"):
            key, _, val = raw_line.strip().partition(":")
            key = key.strip().upper()
            val = val.strip()
            if key == "VULNERABLE_FUNCTION_REACHED":
                result["vulnerable_function_reached"] = val.upper().startswith("YES")
            elif key == "MATCHED_SYMBOL":
                result["matched_symbol"] = "" if val.upper() in ("NONE", "") else val
            elif key == "HOW_REACHED":
                result["how_reached"] = val
            elif key == "INPUT_REACHES_IT":
                result["input_reaches"] = val.upper().startswith("YES")
            elif key == "CONFIDENCE":
                low = val.lower()
                result["confidence"] = "high" if "high" in low else ("medium" if "med" in low else "low")
            elif key == "REASONING":
                result["reasoning"] = val
        return result
    except Exception as e:
        logging.error(f"CVE reachability stage failed: {type(e).__name__}: {e}")
        return {**_EMPTY, "reasoning": "Reachability analysis unavailable — the AI provider could not be reached.", "raw": str(e)}


def confirm_with_llm_reachability(snippet: str, library: str, vuln_desc: str, symbols: List[str], _model: str = None):
    """
    Backward-compat wrapper for test scripts.
    Returns (full_response, vulnerable_api_used, user_input_reaches_vuln, exploit_without_user_input, active_exploit).
    """
    result = _analyse_code_usage(snippet, library, symbols)
    return (
        result.get("raw", ""),
        result["vulnerable_api_used"],
        result["user_input_in_args"],
        result["exploit_without_user_input"],
        result["active_exploit"],
    )


# Keep backward-compat alias so any external code still calling the old name works
confirm_with_ollama_reachability = confirm_with_llm_reachability


# --- IMPORTANT CHANGE HERE: MODIFIED TO ENSURE FULL CLONE/UPDATE ---
def clone_repo_if_needed_reachability(file_location: str, github_token: str, org_name: str, github_repo_name: str) -> Path:
    """
    Clones a GitHub repository using the explicitly provided GitHub repository name.
    If the repository directory already exists and is a valid Git repo, it performs a git pull
    to ensure it's up-to-date and contains all necessary files for scanning.
    If it's not a valid repo or pull fails, it attempts to remove and re-clone.
    """
    repo_name = github_repo_name
    repo_path = API_CLONED_REPOS_PARENT / repo_name

    # --- FIX START: Corrected URL construction ---
    clone_url = f"https://{github_token}@github.com/{org_name}/{repo_name}.git" if github_token else f"https://github.com/{org_name}/{repo_name}.git"
    # --- FIX END ---

    if not validate_git_url(clone_url):
        raise ValueError(f"Invalid Git URL format: {clone_url}")

    clone_env = os.environ.copy()
    clone_env['GIT_CURL_IP_RESOLVE'] = 'ipv4'
    clone_env['GIT_CURL_VERBOSE'] = '1' # Keep verbose for now for debugging
    clone_env['GIT_TRACE'] = '1'        # Keep trace for now for debugging

    # Ensure the parent directory for cloning exists (API_CLONED_REPOS_PARENT)
    API_CLONED_REPOS_PARENT.mkdir(parents=True, exist_ok=True)

    if repo_path.exists() and (repo_path / ".git").is_dir():
        logging.info(f"✓ Repository '{repo_name}' already exists and is a Git repo at {repo_path}. Performing git pull to ensure it's up-to-date.")
        try:
            subprocess.run(["git", "pull", "--ff-only"], # --ff-only avoids merge commits on fast-forwardable branches
                             check=True, timeout=300, capture_output=True,
                             cwd=repo_path, # Execute pull inside the repo directory
                             env=clone_env
                           )
            logging.info(f"Successfully pulled '{repo_name}'.")
        except subprocess.CalledProcessError as e:
            error_output = e.stderr.decode(sys.getfilesystemencoding(), errors='ignore')
            stdout_output = e.stdout.decode(sys.getfilesystemencoding(), errors='ignore')
            logging.error(f"Failed to pull '{repo_name}': {e.cmd} returned {e.returncode}.\nStderr: {error_output}\nStdout: {stdout_output}")
            # If pull fails, maybe it's a corrupted clone or not meant to be updated this way, try re-cloning
            logging.warning(f"Pull failed for {repo_name}. Attempting to remove and re-clone.")
            try:
                shutil.rmtree(repo_path)
                logging.info(f"Removed existing incomplete clone of '{repo_name}'.")
            except Exception as rm_e:
                logging.error(f"Error removing existing repo at {repo_path}: {rm_e}")
                raise RuntimeError(f"Failed to clean up existing repository for re-clone: {rm_e}")

            # Fall through to cloning logic below (will now clone)
        except subprocess.TimeoutExpired as e:
            stderr_output = e.stderr.decode(sys.getfilesystemencoding(), errors='ignore') if e.stderr else "No stderr output"
            logging.error(f"Git pull of '{repo_name}' timed out after 300 seconds. Stderr: {stderr_output}")
            raise RuntimeError(f"Git pull of '{repo_name}' timed out after 300 seconds.")

    # If repo_path doesn't exist, or was removed due to failed pull, clone it
    if not repo_path.exists():
        logging.info(f"Cloning '{repo_name}' to {repo_path}...")
        logging.info(f"DEBUG: clone_repo_if_needed_reachability attempting to clone with URL: {clone_url.replace(github_token, '***TOKEN_REDACTED***')}")
        try:
            subprocess.run(["git", "clone", "--quiet", clone_url, str(repo_name)],
                             check=True, timeout=300, capture_output=True,
                             cwd=API_CLONED_REPOS_PARENT, # Clone into the SCA_CLONED_REPOS folder
                             env=clone_env
                           )
            logging.info(f"Successfully cloned '{repo_name}'.")
        except subprocess.CalledProcessError as e:
            error_output = e.stderr.decode(sys.getfilesystemencoding(), errors='ignore')
            stdout_output = e.stdout.decode(sys.getfilesystemencoding(), errors='ignore')
            logging.error(f"Failed to clone '{repo_name}' from {clone_url}: {e.cmd} returned {e.returncode}.\nStderr: {error_output}\nStdout: {stdout_output}")
            raise RuntimeError(f"Failed to clone '{repo_name}': {error_output.strip()}")
        except subprocess.TimeoutExpired as e:
            stderr_output = e.stderr.decode(sys.getfilesystemencoding(), errors='ignore') if e.stderr else "No stderr output"
            logging.error(f"Git clone of '{repo_name}' timed out after 300 seconds. Stderr: {stderr_output}")
            raise RuntimeError(f"Git clone of '{repo_name}' timed out after 300 seconds.")
    
    return repo_path

# --- IMPORTANT CHANGE HERE: Updated to use 'file_location_in_cloned_repo' ---
def scan_for_reachability(
    github_token: str,
    org_name: str,
    library_entry_data: Dict,
    github_repo_name: str,
    local_repo_path: Union[str, Path, None] = None,
    ollama_model: str = None,  # ignored — kept for call-site backward compat
    ai_refine: bool = True,
) -> Dict:
    """
    Performs the reachability scan for a single library entry.

    ai_refine=True  → AI scan: the LLM judges exploitability (active exploit, mitigations,
                      user-input flow) on top of the static signals.
    ai_refine=False → Normal scan: deterministic reachability only (tree-sitter call graph
                      + regex), NO LLM calls, no key required. Verdict caps at "reachable".

    Returns a dictionary containing the scan results (is_used, llm_confirms_vuln, evidence, scan_error).
    """
    output_results = {
        "is_used": False,
        "llm_confirms_vuln": False,
        "vulnerable_function_reached": False,
        "evidence": [],
        "scan_error": None,
        "reachability_analysis": None,
    }

    try:
        if local_repo_path is not None:
            repo_path = Path(local_repo_path)
            if not repo_path.is_dir():
                output_results["scan_error"] = f"Local repo path does not exist or is not a directory: {local_repo_path}"
                return output_results
        else:
            repo_path = clone_repo_if_needed_reachability(
                file_location=library_entry_data.get("file_location", ""),
                github_token=github_token,
                org_name=org_name,
                github_repo_name=github_repo_name
            )
        library = library_entry_data["library"]

        all_vuln_symbols = set()
        for vuln in library_entry_data.get("vulnerabilities", []):
            for tok in vuln.get("vulnerability_usage_analysis", []):
                if tok:
                    all_vuln_symbols.add(tok)
        symbols_for_patterns = list(all_vuln_symbols)

        patterns = build_patterns_reachability(symbols_for_patterns, library)

        # --- IMPORTANT: Use the file_location_in_cloned_repo provided by server.py ---
        # This is the specific file within the *cloned* repository that was the source of the vulnerability detection.
        local_target_file_path = Path(library_entry_data['file_location_in_cloned_repo'])

        # We will still scan all code files in the cloned repository to find ALL usages,
        # not just the one where the dependency was declared.
        # Use cached file list per repo so we don't re-walk the same repo for every library.
        all_files_in_cloned_repo = _get_repo_files_cached(repo_path)

        # Scope to the dependency's OWN language. An npm package must not be "found" in a .py
        # file (Python's `request`/`requests` ≠ the npm `request` package) — that produced
        # cross-ecosystem false matches and showed unrelated code as evidence.
        eco_exts = _ecosystem_code_exts(library_entry_data.get("ecosystem", ""))
        if eco_exts:
            all_files_in_cloned_repo = [f for f in all_files_in_cloned_repo
                                        if Path(f).suffix.lower() in eco_exts]

        # For evidence display: when using local_repo_path (REPOSITORIES/), paths are under repo_path; else under SCA_CLONED_REPOS
        evidence_root = repo_path if local_repo_path else API_CLONED_REPOS_PARENT

        confirmed_usages_for_entry = []

        logging.info(f"Scanning {repo_path.name} for '{library}' usage ({len(all_files_in_cloned_repo)} files)...")
        if not all_files_in_cloned_repo:
            logging.info(f"No code files found in {repo_path.name}. Skipping detailed scan for {library}.")

        all_vulns = library_entry_data.get("vulnerabilities", [])
        # Collect all unique API symbols from CVE usage-analysis hints — used as context clues for the LLM.
        # We do NOT cross-match CVEs; this is just so the LLM knows which APIs are security-sensitive.
        all_symbols = list({
            tok for v in all_vulns
            for tok in (v.get("vulnerability_usage_analysis") or []) if tok
        })
        logging.info(f"  {library}: {len(all_vulns)} known CVE(s) (reference only) | {len(all_symbols)} API symbol hints")

        exploitable_found = False  # early-exit flag: once one hit is confirmed exploitable, stop

        # First pass: grep only — find files where the library is mentioned (import/require/bare-word).
        # LLM is called only for those files, not for every file in the repo.
        # We cap at _MAX_LLM_FILES_PER_LIBRARY files per library to keep full scan fast.
        files_with_hits = 0
        llm_calls_so_far = 0
        # Pass 1 — grep the WHOLE repo (cheap) and collect every file referencing the
        # library, scored by relevance so the most likely-vulnerable files (those with
        # the CVE symbols, then config files) are analysed first. The per-library LLM
        # cap must never skip the important file just because of file-walk order.
        scored_hits = []
        for fpath in all_files_in_cloned_repo:
            _hits = grep_library_usage_reachability(fpath, library, patterns, symbols=symbols_for_patterns)
            if _hits:
                files_with_hits += 1
                output_results["is_used"] = True
                scored_hits.append((_file_relevance(fpath, _hits, all_symbols), fpath, _hits))
        scored_hits.sort(key=lambda x: -x[0])

        # Pass 2 — analyse highest-relevance files first. Signal-aware cap: files that
        # actually contain a CVE symbol (score ≥ 100) are NEVER capped out (up to a hard
        # ceiling); only lower-signal files respect the base cap. So the file that holds
        # the real vulnerable usage is always analysed.
        _HARD_MAX = max(_MAX_LLM_FILES_PER_LIBRARY, 12)
        for _score, fpath, hits in scored_hits:
            if exploitable_found:
                logging.info(f"  [early-exit] Exploitable usage already confirmed — skipping remaining files.")
                break
            if llm_calls_so_far >= _HARD_MAX:
                logging.info(f"  [cap] Hard ceiling ({_HARD_MAX}) reached — skipping remaining files.")
                break
            if _score < 100 and llm_calls_so_far >= _MAX_LLM_FILES_PER_LIBRARY:
                # low-signal file beyond the base cap — skip (symbol-bearing files above
                # already analysed; remaining are all lower-signal since sorted).
                logging.info(f"  [cap] Base cap ({_MAX_LLM_FILES_PER_LIBRARY}) reached for low-signal files.")
                break

            if hits:
                for hit in hits:
                    if exploitable_found:
                        break
                    # Honor the same two-tier cap as the outer loop: high-signal files (a CVE
                    # symbol present, score >= 100) are analysed up to the hard ceiling; only
                    # low-signal files respect the base cap. (Previously this always broke at the
                    # base cap, silently capping even the symbol-bearing files.)
                    if llm_calls_so_far >= _HARD_MAX:
                        break
                    if _score < 100 and llm_calls_so_far >= _MAX_LLM_FILES_PER_LIBRARY:
                        break

                    # ONE combined LLM call per hit (CVE-aware): "is the library used?" AND
                    # "is the SPECIFIC vulnerable function reached?" — file sent only once.
                    # Falls back to the CVE-blind stage if stage 2 is disabled or no CVE data.
                    file_type = hit.get("file_type", "code")

                    # Cross-file slice: trace callers across files so the LLM can see
                    # whether untrusted input from ANOTHER file reaches the sink here.
                    analysis_snippet = hit['context_snippet']
                    crossfile_meta = None
                    cslice = None
                    if _CROSSFILE_ENABLED and file_type == "code" and all_symbols:
                        try:
                            cslice = build_caller_slice(repo_path, hit['file'], all_symbols)
                            if cslice and cslice.caller_count > 0:
                                analysis_snippet = (
                                    hit['context_snippet']
                                    + "\n\n# ===== CROSS-FILE CALLERS (other files that call into this code) =====\n"
                                    + cslice.slice_text
                                )
                                crossfile_meta = {
                                    "sink_function": cslice.sink_function,
                                    "sink_in_parameter": cslice.sink_in_parameter,
                                    "caller_count": cslice.caller_count,
                                    "files_involved": cslice.files_involved,
                                }
                                logging.info(f"  [crossfile] {cslice.sink_function}() ← {cslice.caller_count} caller(s) across {len(cslice.files_involved)} file(s)")
                        except Exception as e:
                            logging.debug(f"  [crossfile] slice skipped: {e}")

                    if ai_refine:
                        logging.info(f"  [LLM] Analysing {'infra' if file_type=='infra' else 'code'} usage of '{library}' in {hit.get('file','?')}...")
                        if _CVE_STAGE_ENABLED and all_vulns:
                            usage = _analyse_reachability(analysis_snippet, library, all_vulns, all_symbols, file_type=file_type)
                        else:
                            usage = _analyse_code_usage(analysis_snippet, library, all_symbols, file_type=file_type)
                        usage.setdefault("analysis_mode", "ai")
                        logging.info(
                            f"  [LLM] active_exploit={usage['active_exploit']} | "
                            f"vuln_fn_reached={usage.get('vulnerable_function_reached')} | "
                            f"apis={usage['apis_called']} | user_input={usage['user_input_in_args']}"
                        )
                    else:
                        # Normal (deterministic) mode — no LLM. Static reachability from the
                        # tree-sitter caller slice (or regex fallback).
                        usage = _deterministic_usage(analysis_snippet, library, all_symbols, file_type, cslice)
                        logging.info(
                            f"  [static] vuln_api_used={usage['vulnerable_api_used']} | "
                            f"vuln_fn_reached={usage['vulnerable_function_reached']} | "
                            f"matched={usage['matched_symbol']} | conf={usage['confidence']}"
                        )

                    try:
                        rel = Path(hit['file']).resolve().relative_to(Path(evidence_root).resolve())
                        file_display = f"{repo_path.name}/{rel}" if local_repo_path else str(rel)
                    except ValueError:
                        file_display = str(Path(hit['file']))

                    evidence_item = {
                        "file": file_display,
                        "line": hit['line'],
                        "context_snippet": hit['context_snippet'],
                        "pattern_matched": hit.get('pattern_matched', ''),
                        "file_type": hit.get("file_type", "code"),
                        "apis_called": usage.get("apis_called", []),
                        "usage_summary": usage.get("usage_summary", ""),
                        "user_input_in_args": usage.get("user_input_in_args", False),
                        "input_source": usage.get("input_source", "N/A"),
                        "vulnerable_api_used": usage.get("vulnerable_api_used", False),
                        "exploit_without_user_input": usage.get("exploit_without_user_input", False),
                        "active_exploit": usage.get("active_exploit", False),
                        "mitigation": usage.get("mitigation", ""),
                        "cve_function_reached": usage.get("vulnerable_function_reached", False),
                        "cve_matched_symbol": usage.get("matched_symbol", ""),
                        "cve_reach_confidence": usage.get("confidence", ""),
                        "crossfile": crossfile_meta,
                    }
                    llm_calls_so_far += 1
                    confirmed_usages_for_entry.append(evidence_item)

                    # Early-exit: first confirmed exploitable hit → library is HIGH PRIORITY. Stop.
                    if usage["active_exploit"]:
                        exploitable_found = True
                        logging.info(f"  [early-exit] Active exploit confirmed in {file_display} — stopping scan for '{library}'.")

        output_results["evidence"] = confirmed_usages_for_entry
        if all_files_in_cloned_repo:
            logging.info(f"  {library}: grepped {len(all_files_in_cloned_repo)} files → {files_with_hits} with usage → {len(confirmed_usages_for_entry)} LLM call(s)")
        any_vuln_api_used    = any(u.get("vulnerable_api_used", False)        for u in confirmed_usages_for_entry)
        any_no_input_exploit = any(u.get("exploit_without_user_input", False) for u in confirmed_usages_for_entry)
        any_cve_fn_reached   = any(u.get("cve_function_reached", False)       for u in confirmed_usages_for_entry)
        # Consistency gates: "user input reaches the vuln" and "active exploit" both REQUIRE the
        # vulnerable API to actually be used IN THE SAME usage. Without this, per-usage LLM noise
        # produced contradictory panels like "User input reaches vuln: Yes / Vulnerable API used:
        # No" (input reaches general library calls, but the VULNERABLE function isn't even called)
        # and "Active exploit: Yes / Vulnerable API used: No".
        any_user_input       = any(u.get("user_input_in_args", False) and u.get("vulnerable_api_used", False)
                                   for u in confirmed_usages_for_entry)
        any_active_exploit   = any(u.get("active_exploit", False) and u.get("vulnerable_api_used", False)
                                   for u in confirmed_usages_for_entry)

        output_results["llm_confirms_vuln"] = any_active_exploit
        output_results["vulnerable_function_reached"] = any_cve_fn_reached
        output_results["scan_error"] = None
        cap_note = None
        if files_with_hits > len(confirmed_usages_for_entry) and confirmed_usages_for_entry:
            cap_note = f"Only first {len(confirmed_usages_for_entry)} of {files_with_hits} usages analysed (cap for speed; set MAX_LLM_FILES_PER_LIBRARY to analyse more)."
        output_results["reachability_analysis"] = _build_reachability_analysis(
            declared=True,
            imported=output_results["is_used"],
            vulnerable_api_used=any_vuln_api_used,
            user_input_reaches_vuln=any_user_input,
            exploit_without_user_input=any_no_input_exploit,
            evidence=confirmed_usages_for_entry,
            library=library,
            cap_note=cap_note,
            vulnerable_function_reached=any_cve_fn_reached,
            active_exploit=any_active_exploit,
            analysis_mode=("ai" if ai_refine else "deterministic"),
        )

    except Exception as e:
        error_message = f"Error during reachability scan for {library_entry_data.get('library', 'unknown')}: {type(e).__name__}: {e}"
        logging.error(error_message, exc_info=True)
        output_results["is_used"] = False
        output_results["llm_confirms_vuln"] = False
        output_results["evidence"] = []
        output_results["scan_error"] = error_message
        output_results["reachability_analysis"] = _build_reachability_analysis(
            declared=True,
            imported=False,
            vulnerable_api_used=False,
            user_input_reaches_vuln=False,
            exploit_without_user_input=False,
            evidence=[],
            library=library_entry_data.get("library", ""),
            scan_error=error_message,
        )

    return output_results


def _build_reachability_analysis(
    declared: bool,
    imported: bool,
    vulnerable_api_used: bool,
    evidence: List[Dict],
    library: str,
    scan_error: str = None,
    user_input_reaches_vuln: bool = False,
    exploit_without_user_input: bool = False,
    cap_note: str = None,
    vulnerable_function_reached: bool = False,
    active_exploit: bool = False,
    analysis_mode: str = "ai",
) -> Dict:
    """
    Builds the reachability_analysis block: declared, imported, vulnerable_api_used,
    vulnerable_function_reached (CVE-aware), user_input_reaches_vuln,
    exploit_without_user_input, and notes.

    analysis_mode: "ai" (LLM judged exploitability) or "deterministic" (static reachability
    only — exploitability not assessed; verdict caps at "reachable").
    """
    notes_parts = []
    if analysis_mode == "deterministic" and imported and not scan_error:
        notes_parts.append(
            "Normal (deterministic) scan — reachability from static call-graph analysis; "
            "exploitability not assessed. Run an AI scan to confirm active exploits."
        )
    if cap_note:
        notes_parts.append(cap_note)
    if scan_error:
        notes_parts.append(f"Scan error: {scan_error}")
    elif not imported:
        notes_parts.append("Library not imported or used in code (declared only).")
    else:
        for usage in evidence[:5]:
            file_rel  = usage.get("file", "")
            line      = usage.get("line", "")
            summary   = usage.get("usage_summary", "")
            apis      = usage.get("apis_called", [])
            active    = usage.get("active_exploit", False)

            if file_rel or line:
                loc_str = f"In {file_rel}:{line}"
                if summary:
                    notes_parts.append(f"{loc_str} — {summary}")
                elif apis:
                    notes_parts.append(f"{loc_str} — calls: {', '.join(apis)}")
                else:
                    notes_parts.append(f"{loc_str} — usage found.")

            if active:
                notes_parts.append("⚠ Active exploit path confirmed at this location.")

        # CVE-aware verdict (stage 2) takes precedence in the notes when available.
        if vulnerable_function_reached:
            notes_parts.insert(0, f"{library} — CVE-specific vulnerable function confirmed REACHED in code.")

        # Prepend overall library-level verdict. "Active exploit" requires a SINGLE-file
        # confirmation (active_exploit) — NOT vuln-API-in-file-X + user-input-in-file-Y,
        # which over-claims by combining unrelated files.
        if active_exploit:
            notes_parts.insert(0, f"{library} — active exploit confirmed: the vulnerable API is reached with a triggering condition in the same code path.")
        elif vulnerable_api_used:
            notes_parts.insert(0, f"{library} — API is used, but no single-path active exploit was confirmed (vulnerable API and untrusted input were not shown to meet in one place).")
        elif imported and not notes_parts:
            notes_parts.append(f"{library} imported and used in code; LLM analysis complete.")

    return {
        "declared": declared,
        "imported": imported,
        "vulnerable_api_used": vulnerable_api_used,
        "vulnerable_function_reached": vulnerable_function_reached,
        "user_input_reaches_vuln": user_input_reaches_vuln,
        "exploit_without_user_input": exploit_without_user_input,
        "active_exploit": active_exploit,
        "analysis_mode": analysis_mode,
        "notes": " ".join(notes_parts) if notes_parts else (
            "Declared in manifest; no reachability scan run or no usage found."
        ),
    }


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    print("This script is intended to be imported and used by server.py.")
    print("To test, run server.py and use the /api/scan-reachability endpoint.")
    print(f"Cloned repositories will be stored in: {API_CLONED_REPOS_PARENT.resolve()}")