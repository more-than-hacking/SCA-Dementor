"""Cross-file call-graph slicing (tree-sitter, fully open-source, multi-language).

Reachability's per-file LLM analysis can't see taint that crosses file boundaries:
the vulnerable call lives in handler.java, but the untrusted input enters in
controller.java. This module bridges that gap WITHOUT a heavyweight taint engine:

  1. tree-sitter (precise, deterministic) locates the function containing the
     vulnerable "sink" call, then walks the call graph BACKWARD to its callers
     across the whole repo.
  2. It returns a small, bounded CODE SLICE — the sink function plus its N-hop
     callers — which the LLM then reasons over to decide if untrusted input
     actually reaches the sink.

AST builds the structure; the LLM judges the taint. Languages are pluggable via
LANG_SPECS — Python, Java, Go, JavaScript/TypeScript out of the box. MIT-licensed
deps only (tree-sitter + tree-sitter-<lang>); any missing grammar is simply skipped.
"""
from __future__ import annotations

import importlib
import logging
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

log = logging.getLogger(__name__)

try:
    from tree_sitter import Language, Parser, Query, QueryCursor
    _TS_CORE = True
except Exception as e:  # pragma: no cover
    _TS_CORE = False
    log.info("tree-sitter core unavailable (%s) — cross-file slicing disabled", e)


@dataclass
class LangSpec:
    name: str
    exts: set
    module: str
    def_query: str          # captures @func on each function/method definition node
    call_query: str         # captures @callee on each call's callee identifier/expression
    func_types: set         # node types that count as a function/method definition
    language: object = None
    parser: object = None
    _def_q: object = None
    _call_q: object = None

    def ready(self) -> bool:
        return self.language is not None


# Language registry. Add an entry (grammar + queries) to support a new language.
_SPEC_DEFS = [
    LangSpec("python", {".py", ".pyi"}, "tree_sitter_python",
             "(function_definition) @func",
             "(call function: (_) @callee)",
             {"function_definition"}),
    LangSpec("java", {".java"}, "tree_sitter_java",
             "[(method_declaration) (constructor_declaration)] @func",
             "[(method_invocation name: (identifier) @callee) "
             " (object_creation_expression type: (type_identifier) @callee)]",
             {"method_declaration", "constructor_declaration"}),
    LangSpec("go", {".go"}, "tree_sitter_go",
             "[(function_declaration) (method_declaration)] @func",
             "(call_expression function: (_) @callee)",
             {"function_declaration", "method_declaration"}),
    LangSpec("javascript", {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}, "tree_sitter_javascript",
             "[(function_declaration) (method_definition) (function_expression)] @func",
             "(call_expression function: (_) @callee)",
             {"function_declaration", "method_definition", "function_expression", "arrow_function"}),
]

LANG_SPECS: Dict[str, LangSpec] = {}   # ext -> LangSpec (only successfully-loaded ones)

if _TS_CORE:
    for _spec in _SPEC_DEFS:
        try:
            _mod = importlib.import_module(_spec.module)
            _spec.language = Language(_mod.language())
            _spec.parser = Parser(_spec.language)
            _spec._def_q = Query(_spec.language, _spec.def_query)
            _spec._call_q = Query(_spec.language, _spec.call_query)
            for _e in _spec.exts:
                LANG_SPECS[_e] = _spec
        except Exception as e:  # pragma: no cover - missing grammar
            log.info("call-graph: grammar for %s unavailable (%s)", _spec.name, e)

TREE_SITTER_AVAILABLE = bool(LANG_SPECS)
SUPPORTED_LANGUAGES = sorted({s.name for s in LANG_SPECS.values()})

_MAX_INDEX_FILES = 8000  # safety cap for very large repos

# Repo index cache — building the call graph walks the whole repo, so do it once
# per repo and reuse across libraries. Lock-guarded for the parallel scan workers.
_INDEX_CACHE: Dict[str, "_RepoIndex"] = {}
_INDEX_LOCK = threading.Lock()

_SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "site-packages",
              "dist", "build", "target", "vendor", ".gradle", "out",
              # test code is not production-reachable — exclude so it doesn't flood sinks
              "test", "tests", "testing", "__tests__", "spec", "specs"}


def _is_test_file(path: Path) -> bool:
    """Test files by name convention (covers test code outside a tests/ dir)."""
    n = path.name
    stem = path.stem
    return (
        n.endswith(("Test.java", "Tests.java", "IT.java", "_test.go", "_test.py"))
        or stem.startswith(("Test", "test_"))
        or ".test." in n or ".spec." in n
    )


@dataclass
class FuncDef:
    name: str
    file: str
    start_line: int
    end_line: int
    source: str
    params: List[str] = field(default_factory=list)


@dataclass
class CallerSlice:
    sink_function: str
    sink_in_parameter: bool
    files_involved: List[str]
    slice_text: str
    caller_count: int


def _spec_for(path: Path) -> Optional[LangSpec]:
    return LANG_SPECS.get(path.suffix.lower())


# Ubiquitous methods (java.lang.Object + a few) that are NEVER the real vulnerable
# sink when matched by bare name — e.g. a CVE symbol "ClassUtils.getClass" must not
# match Object.getClass() inside every equals(). Matching these produces only FPs.
# Ubiquitous method/builtin names — matching one by BARE name (e.g. Object.keys(), require())
# is a false positive. A qualified `Class.method` form still matches (see _sink_matchers), so a
# real qualified sink is kept; only the noisy bare match is suppressed.
_GENERIC_METHODS = {
    # Java/Object basics
    "getclass", "equals", "hashcode", "tostring", "clone", "wait", "notify", "notifyall",
    "finalize", "compareto", "iterator", "size", "length", "isempty", "get", "set",
    "name", "value", "of", "valueof",
    # collections / JS-ubiquitous
    "keys", "values", "items", "entries", "add", "remove", "put", "push", "pop", "shift",
    "map", "filter", "foreach", "reduce", "find", "has", "contains", "indexof", "slice",
    "split", "join", "concat", "copy", "clear", "toarray", "tolist", "next", "hasnext",
    # I/O / lifecycle / misc verbs
    "read", "write", "open", "close", "start", "stop", "run", "call", "apply", "accept",
    "init", "build", "print", "println", "log", "format", "then", "catch", "empty",
    # language/module builtins — never a library's vulnerable API
    "require", "import", "export", "exports", "module", "define", "include", "use", "using", "from",
}
_PACKAGE_ROOTS = {"org", "com", "io", "net", "edu", "gov", "co"}


def _matchable_sink_names(symbols) -> set:
    """Trailing identifiers safe to match a call against.

    Drops (a) ubiquitous Object methods that only yield false positives by bare name,
    and (b) package paths like 'org.apache.commons' that are not callable functions.
    A qualified CVE symbol whose trailing token is generic (e.g. ClassUtils.getClass)
    is intentionally NOT matched — we'd rather under-report than flag every equals()."""
    names = set()
    for s in (symbols or []):
        s = (s or "").replace("::", ".").strip()
        if not s:
            continue
        parts = s.split(".")
        if len(parts) >= 2 and parts[0].lower() in _PACKAGE_ROOTS and s == s.lower():
            continue  # package path, not a function
        last = parts[-1].strip()
        if len(last) <= 1 or last.lower() in _GENERIC_METHODS:
            continue
        names.add(last)
    return names


def _sink_matchers(symbols):
    """Build (bare, qualified) matcher sets from CVE symbols.

    - bare: trailing method names safe to match alone (non-generic).
    - qualified: lower-cased 'Class.method' forms — these DO match even when the
      method is generic, so `ClassUtils.getClass` is matched as a qualified call
      while a bare Object.getClass() inside equals() is not. Best of both: recall
      for real qualified sinks, no false positives from ubiquitous bare methods."""
    bare, qual = set(), set()
    for s in (symbols or []):
        s = (s or "").replace("::", ".").strip()
        if not s:
            continue
        parts = s.split(".")
        if len(parts) >= 2 and parts[0].lower() in _PACKAGE_ROOTS and s == s.lower():
            continue  # package path
        last = parts[-1].strip()
        if len(last) <= 1:
            continue
        if len(parts) >= 2 and parts[-2]:
            qual.add((parts[-2] + "." + last).lower())
        if last.lower() not in _GENERIC_METHODS:
            bare.add(last)
    return bare, qual


def _alias_bare_names(src: bytes, symbols) -> set:
    """Identifiers bound via a SYMBOL alias to a vulnerable sink name, so the bare aliased call
    matches. e.g. `from yaml import load as L` or `import {decode as d} from 'jwt'` → {L}/{d}
    when load/decode are sink names. (Module aliases like `import jwt as _jwt` already match via
    the trailing call name: `_jwt.decode` → `decode`.)"""
    targets = _matchable_sink_names(symbols)
    if not targets:
        return set()
    text = src.decode("utf-8", "ignore")
    out = set()
    # Python:  from <mod> import a, b as B, load as L
    for m in re.finditer(r"(?m)^\s*from\s+[\w.]+\s+import\s+([^\n#]+)", text):
        for part in m.group(1).split(","):
            if " as " in part:
                orig, _, alias = part.partition(" as ")
                if orig.strip().strip("()") in targets:
                    out.add(alias.strip().strip("()"))
    # JS/TS:  import { decode as d, verify as v } from 'mod'
    for m in re.finditer(r"import\s*\{([^}]*)\}\s*from", text):
        for part in m.group(1).split(","):
            if " as " in part:
                orig, _, alias = part.partition(" as ")
                if orig.strip() in targets:
                    out.add(alias.strip())
    return {a for a in out if a.isidentifier()}


def _last_identifier(node, src: bytes) -> str:
    """Trailing name of a call target: 'load' from yaml.load / pkg.Load / a.b.load."""
    text = src[node.start_byte:node.end_byte].decode("utf-8", "ignore")
    return text.replace("::", ".").split(".")[-1].strip()


def _is_sink_call(node, src: bytes, bare: set, qual: set) -> bool:
    """Does this call match a vulnerable sink — by bare name, or by qualified
    Class.method (which rescues generic methods like ClassUtils.getClass)?"""
    name = _last_identifier(node, src)
    if name in bare:
        return True
    if not qual:
        return False
    text = src[node.start_byte:node.end_byte].decode("utf-8", "ignore").replace("::", ".")
    if "." in text:
        parts = text.split(".")
        if (parts[-2] + "." + parts[-1]).lower() in qual:
            return True
    else:
        # Java: receiver lives in the parent method_invocation's `object` field.
        p = node.parent
        obj = p.child_by_field_name("object") if p is not None else None
        if obj is not None:
            recv = src[obj.start_byte:obj.end_byte].decode("utf-8", "ignore").replace("::", ".").split(".")[-1]
            if recv and (recv + "." + name).lower() in qual:
                return True
    return False


def _enclosing_function(node, func_types: set):
    cur = node.parent
    while cur is not None:
        if cur.type in func_types:
            return cur
        cur = cur.parent
    return None


def _func_name(func_node, src: bytes) -> str:
    name_node = func_node.child_by_field_name("name")
    return src[name_node.start_byte:name_node.end_byte].decode("utf-8", "ignore") if name_node else "<anon>"


def _func_params(func_node, src: bytes) -> List[str]:
    """Best-effort parameter names — identifier leaves inside the parameters node.
    Over-collects slightly for typed languages (may include type names); fine for the
    substring-based 'is the sink arg a parameter?' heuristic."""
    params_node = func_node.child_by_field_name("parameters")
    out = []
    if not params_node:
        return out
    stack = list(params_node.named_children)
    while stack:
        n = stack.pop()
        if n.type in ("identifier", "field_identifier"):
            out.append(src[n.start_byte:n.end_byte].decode("utf-8", "ignore"))
        else:
            stack.extend(n.named_children)
    return out


def _call_args_text(callee_node, src: bytes) -> str:
    """Arguments text of the call enclosing a captured callee node (best effort)."""
    cur = callee_node.parent
    while cur is not None:
        args = cur.child_by_field_name("arguments")
        if args is not None:
            return src[args.start_byte:args.end_byte].decode("utf-8", "ignore")
        if cur.type in ("call", "call_expression", "method_invocation", "object_creation_expression"):
            break
        cur = cur.parent
    return ""


class _RepoIndex:
    """Repo-wide, multi-language index of function defs and caller→callee edges (by name)."""

    def __init__(self):
        self.defs: Dict[str, List[FuncDef]] = {}
        self.callers_of: Dict[str, List[str]] = {}
        self.edges: List[tuple] = []          # (caller_file, caller_name, callee_name)
        self.lang_counts: Dict[str, int] = {}

    def add_file(self, path: Path):
        spec = _spec_for(path)
        if spec is None or not spec.ready():
            return
        try:
            data = path.read_bytes()
        except Exception:
            return
        root = spec.parser.parse(data).root_node
        self.lang_counts[spec.name] = self.lang_counts.get(spec.name, 0) + 1

        for fnode in QueryCursor(spec._def_q).captures(root).get("func", []):
            name = _func_name(fnode, data)
            self.defs.setdefault(name, []).append(FuncDef(
                name=name, file=str(path),
                start_line=fnode.start_point[0] + 1, end_line=fnode.end_point[0] + 1,
                source=data[fnode.start_byte:fnode.end_byte].decode("utf-8", "ignore"),
                params=_func_params(fnode, data),
            ))

        for cnode in QueryCursor(spec._call_q).captures(root).get("callee", []):
            callee = _last_identifier(cnode, data)
            enc = _enclosing_function(cnode, spec.func_types)
            caller = _func_name(enc, data) if enc else "<module>"
            self.callers_of.setdefault(callee, []).append(caller)
            self.edges.append((str(path), caller, callee))


def _iter_source_files(repo_root: Path) -> List[Path]:
    exts = set(LANG_SPECS.keys())
    files = []
    for p in repo_root.rglob("*"):
        if (p.is_file() and p.suffix.lower() in exts
                and not (set(p.parts) & _SKIP_DIRS) and not _is_test_file(p)):
            files.append(p)
            if len(files) >= _MAX_INDEX_FILES:
                break
    return files


def _get_index(repo_root: Path) -> "_RepoIndex":
    key = str(repo_root.resolve())
    with _INDEX_LOCK:
        idx = _INDEX_CACHE.get(key)
        if idx is None:
            idx = _RepoIndex()
            for f in _iter_source_files(repo_root):
                idx.add_file(f)
            _INDEX_CACHE[key] = idx
        return idx


def build_caller_slice(
    repo_root: str | Path,
    target_file: str | Path,
    sink_symbols: List[str],
    max_hops: int = 2,
    max_callers: int = 6,
    max_chars: int = 6000,
) -> Optional[CallerSlice]:
    """Cross-file code slice tracing callers that may carry untrusted input into a
    vulnerable sink call found in `target_file`. Returns None if the language is
    unsupported, the file can't be parsed, or no sink call is found."""
    if not TREE_SITTER_AVAILABLE:
        return None
    repo_root = Path(repo_root)
    target_file = Path(target_file)
    spec = _spec_for(target_file)
    if spec is None or not spec.ready():
        return None
    try:
        tgt_src = target_file.read_bytes()
    except Exception:
        return None

    root = spec.parser.parse(tgt_src).root_node
    _bare, _qual = _sink_matchers(sink_symbols)
    _bare = _bare | _alias_bare_names(tgt_src, sink_symbols)   # match symbol-aliased calls
    if not _bare and not _qual:
        return None

    sink_callees = [c for c in QueryCursor(spec._call_q).captures(root).get("callee", [])
                    if _is_sink_call(c, tgt_src, _bare, _qual)]
    sink_funcs = [(_enclosing_function(c, spec.func_types), c) for c in sink_callees]
    sink_funcs = [(f, c) for (f, c) in sink_funcs if f is not None]
    if not sink_funcs:
        return None

    sink_func, sink_callee = sink_funcs[0]
    sink_func_name = _func_name(sink_func, tgt_src)
    sink_params = set(_func_params(sink_func, tgt_src))
    args_text = _call_args_text(sink_callee, tgt_src)
    sink_in_parameter = any(p and p in args_text for p in sink_params)

    index = _get_index(repo_root)

    collected: Dict[str, FuncDef] = {}
    files_involved = {str(target_file)}
    frontier = [sink_func_name]
    seen = {sink_func_name}
    hops = 0
    while frontier and hops < max_hops and len(collected) < max_callers:
        nxt = []
        for callee in frontier:
            for caller_name in index.callers_of.get(callee, []):
                if caller_name in seen or caller_name in ("<module>", "<anon>"):
                    continue
                seen.add(caller_name)
                for fd in index.defs.get(caller_name, []):
                    if fd.file == str(target_file) and fd.name == sink_func_name:
                        continue
                    collected[f"{fd.file}::{fd.name}"] = fd
                    files_involved.add(fd.file)
                    nxt.append(caller_name)
                    if len(collected) >= max_callers:
                        break
        frontier = nxt
        hops += 1

    parts = [f"# === SINK (vulnerable call here) — {target_file.name}::{sink_func_name}() ===\n"
             + tgt_src[sink_func.start_byte:sink_func.end_byte].decode("utf-8", "ignore")]
    for fd in collected.values():
        parts.append(f"\n# === CALLER — {Path(fd.file).name}::{fd.name}() (line {fd.start_line}) ===\n{fd.source}")

    slice_text = "\n".join(parts)
    if len(slice_text) > max_chars:
        slice_text = slice_text[:max_chars] + f"\n... [slice truncated at {max_chars} chars]"

    return CallerSlice(
        sink_function=sink_func_name,
        sink_in_parameter=sink_in_parameter,
        files_involved=sorted(files_involved),
        slice_text=slice_text,
        caller_count=len(collected),
    )


def build_reachability_paths(
    repo_root: str | Path,
    target_file: str | Path,
    sink_symbols: List[str],
    max_paths: int = 5,
    max_depth: int = 7,
) -> Optional[dict]:
    """
    The ACTUAL reachability flow for one finding: ordered path(s) from the caller
    entry point down to the vulnerable sink call — not the whole repo graph.

    Returns {sink_function, sink_file, sink_symbol, paths} where each path is an
    ordered list of {function, file, line} from the top-most caller → sink. Returns
    None if the language is unsupported or the sink isn't called in target_file.
    """
    if not TREE_SITTER_AVAILABLE:
        return None
    repo_root, target_file = Path(repo_root), Path(target_file)
    spec = _spec_for(target_file)
    if spec is None or not spec.ready():
        return None
    try:
        tgt_src = target_file.read_bytes()
    except Exception:
        return None

    root = spec.parser.parse(tgt_src).root_node
    _bare, _qual = _sink_matchers(sink_symbols)
    _bare = _bare | _alias_bare_names(tgt_src, sink_symbols)   # match symbol-aliased calls
    if not _bare and not _qual:
        return None

    sink_callee = next((c for c in QueryCursor(spec._call_q).captures(root).get("callee", [])
                        if _is_sink_call(c, tgt_src, _bare, _qual)), None)
    if sink_callee is None:
        return None
    sink_func = _enclosing_function(sink_callee, spec.func_types)
    if sink_func is None:
        return None
    sink_name = _func_name(sink_func, tgt_src)
    sink_symbol = _last_identifier(sink_callee, tgt_src)
    sink_node = (str(target_file), sink_name)

    index = _get_index(repo_root)
    # Make sure the target file's defs/edges are present even if it was filtered (e.g. a test).
    if not any(fd.file == str(target_file) for fds in index.defs.values() for fd in fds):
        index.add_file(target_file)

    # Node-level reverse adjacency: callee_node ← caller_nodes.
    node_fd: Dict[tuple, FuncDef] = {(fd.file, fd.name): fd for fds in index.defs.values() for fd in fds}
    rev: Dict[tuple, set] = {}
    for (cfile, cname, callee) in index.edges:
        caller = (cfile, cname)
        if caller not in node_fd:
            continue
        for fd in index.defs.get(callee, []):
            rev.setdefault((fd.file, fd.name), set()).add(caller)

    # Walk backward from the sink, prepending callers, until roots / depth / path cap.
    complete = []
    frontier = [[sink_node]]
    while frontier and len(complete) < max_paths:
        path = frontier.pop()
        head = path[0]
        callers = [c for c in rev.get(head, ()) if c not in path]
        if not callers or len(path) >= max_depth:
            complete.append(path)
        else:
            for c in callers[:3]:
                frontier.append([c] + path)

    def node_info(n):
        fd = node_fd.get(n)
        return {"function": n[1], "file": Path(n[0]).name,
                "line": fd.start_line if fd else 0,
                "is_sink": n == sink_node}

    paths = [[node_info(n) for n in p] for p in complete]
    return {
        "sink_function": sink_name,
        "sink_file": Path(target_file).name,
        "sink_symbol": sink_symbol,
        "paths": paths,
    }


def gather_flow_candidates(
    repo_root: str | Path,
    target_file: str | Path,
    sink_symbols: List[str],
    max_funcs: int = 14,
    max_src_chars: int = 1100,
) -> Optional[dict]:
    """
    Gather the REAL source of the sink function and its candidate callers (name-based
    closure) — the raw material for AI to trace the *exact* path. tree-sitter provides
    the bounded candidate set (recall); the LLM then resolves which calls truly happen
    (precision), grounded only in this provided code.

    Returns {sink_function, sink_file, sink_symbol, candidates:[{function,file,line,source}]}.
    """
    if not TREE_SITTER_AVAILABLE:
        return None
    repo_root, target_file = Path(repo_root), Path(target_file)
    spec = _spec_for(target_file)
    if spec is None or not spec.ready():
        return None
    try:
        tgt_src = target_file.read_bytes()
    except Exception:
        return None

    root = spec.parser.parse(tgt_src).root_node
    _bare, _qual = _sink_matchers(sink_symbols)
    if not _bare and not _qual:
        return None
    sink_callee = next((c for c in QueryCursor(spec._call_q).captures(root).get("callee", [])
                        if _is_sink_call(c, tgt_src, _bare, _qual)), None)
    if sink_callee is None:
        return None
    sink_func = _enclosing_function(sink_callee, spec.func_types)
    if sink_func is None:
        return None
    sink_name = _func_name(sink_func, tgt_src)
    sink_symbol = _last_identifier(sink_callee, tgt_src)
    sink_call_line = sink_callee.start_point[0] + 1   # line of the actual vulnerable call
    sink_node = (str(target_file), sink_name)

    index = _get_index(repo_root)
    if not any(fd.file == str(target_file) for fds in index.defs.values() for fd in fds):
        index.add_file(target_file)
    node_fd: Dict[tuple, FuncDef] = {(fd.file, fd.name): fd for fds in index.defs.values() for fd in fds}
    # Ensure the sink function's FuncDef is available even if tgt was unindexed.
    if sink_node not in node_fd:
        node_fd[sink_node] = FuncDef(sink_name, str(target_file),
                                     sink_func.start_point[0] + 1, sink_func.end_point[0] + 1,
                                     tgt_src[sink_func.start_byte:sink_func.end_byte].decode("utf-8", "ignore"))

    rev: Dict[tuple, set] = {}
    for (cfile, cname, callee) in index.edges:
        caller = (cfile, cname)
        if caller not in node_fd:
            continue
        for fd in index.defs.get(callee, []):
            rev.setdefault((fd.file, fd.name), set()).add(caller)

    # BFS backward from sink to collect a bounded candidate pool (the superset the LLM prunes).
    chosen, frontier, seen = [sink_node], list(rev.get(sink_node, ())), set([sink_node])
    while frontier and len(chosen) < max_funcs:
        n = frontier.pop(0)
        if n in seen:
            continue
        seen.add(n)
        chosen.append(n)
        frontier.extend(rev.get(n, ()))

    def clip(src):
        return src if len(src) <= max_src_chars else src[:max_src_chars] + "\n…(truncated)"

    candidates = []
    for n in chosen:
        fd = node_fd.get(n)
        if fd:
            candidates.append({"function": fd.name, "file": Path(fd.file).name,
                               "line": fd.start_line, "source": clip(fd.source)})
    return {"sink_function": sink_name, "sink_file": Path(target_file).name,
            "sink_symbol": sink_symbol, "sink_line": sink_call_line, "candidates": candidates}


def export_graph(repo_root: str | Path, focus_symbols: Optional[List[str]] = None,
                 max_nodes: int = 400, paths_only: bool = True) -> dict:
    """Export the repo call graph as {nodes, edges, stats} for visualization.
    Multi-language. Sinks (functions calling a focus_symbol) are highlighted.

    paths_only (default True): show ONLY the vulnerability paths — sink functions and
    the chain of callers that reach them — instead of every function in the repo. This
    is what keeps the picture readable; a full repo graph is an unreadable hairball.
    Set paths_only=False to see the whole graph (bounded by max_nodes)."""
    if not TREE_SITTER_AVAILABLE:
        return {"available": False, "nodes": [], "edges": [], "stats": {}}

    idx = _get_index(Path(repo_root))
    sink_names = _matchable_sink_names(focus_symbols)

    nodes: Dict[tuple, dict] = {}
    for name, fds in idx.defs.items():
        for fd in fds:
            nodes[(fd.file, fd.name)] = {
                "id": f"{Path(fd.file).name}::{fd.name}",
                "label": fd.name, "file": Path(fd.file).name, "kind": "normal",
            }

    raw_edges = set()
    incoming: Dict[tuple, list] = {}
    for (cfile, cname, callee) in idx.edges:
        caller_key = (cfile, cname)
        if caller_key not in nodes:
            continue
        if callee in sink_names:
            nodes[caller_key]["kind"] = "sink"
        for fd in idx.defs.get(callee, []):
            tgt = (fd.file, fd.name)
            if tgt in nodes and tgt != caller_key:
                raw_edges.add((caller_key, tgt))
                incoming.setdefault(tgt, []).append(caller_key)

    keep = set(nodes.keys())
    pruned = False
    sink_keys = [k for k, v in nodes.items() if v["kind"] == "sink"]
    # Vulnerability-paths view (default): keep ONLY sinks + their transitive callers.
    if paths_only and sink_keys:
        keep = set()
        frontier = list(sink_keys)
        while frontier and len(keep) < max_nodes:
            n = frontier.pop()
            if n in keep:
                continue
            keep.add(n)
            frontier.extend(incoming.get(n, []))
        for k in keep:
            if nodes[k]["kind"] != "sink":
                nodes[k]["kind"] = "caller"
        pruned = (len(keep) < len(nodes))
    elif len(nodes) > max_nodes:
        # Full-graph view but too big to draw — truncate.
        keep = set(list(nodes.keys())[:max_nodes])
        pruned = True

    out_nodes = [nodes[k] for k in keep]
    out_edges = [{"from": nodes[a]["id"], "to": nodes[b]["id"]}
                 for (a, b) in raw_edges if a in keep and b in keep]

    return {
        "available": True,
        "nodes": out_nodes,
        "edges": out_edges,
        "stats": {
            "functions": len(nodes), "shown": len(out_nodes), "edges": len(out_edges),
            "sinks": len(sink_keys), "pruned": pruned, "languages": idx.lang_counts,
        },
    }
