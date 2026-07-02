"""Exposure classification — is a service internet-facing (publicly visible) or internal?

For compliance triage: a vulnerable library in an INTERNET-FACING service is detectable
by external scanners and reachable by attackers (high priority); the same library in an
INTERNAL/backend service (worker, batch, consumer, internal microservice) is not externally
visible (lower priority).

Approach (AI-judged, both infra + code signals): cheaply gather exposure evidence from the
repo — Dockerfile EXPOSE, k8s Ingress/Service type, web controllers/routes, frontend
bundles, server config — then let the LLM classify the service. Cached per repo.
"""
from __future__ import annotations

import logging
import os
import re
import threading
from pathlib import Path

from dementor_sca.llm_client import chat as _llm_chat

log = logging.getLogger(__name__)

_CACHE: dict = {}
_LOCK = threading.Lock()

_SKIP = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", "target",
         "vendor", ".gradle", "out", "test", "tests"}
_MAX_FILES = 6000

# Web-endpoint signals per language.
_CONTROLLER_RE = re.compile(
    r"@RestController|@Controller\b|@RequestMapping|@(Get|Post|Put|Delete|Patch)Mapping"   # Spring
    r"|@app\.(route|get|post)|APIRouter\(|FastAPI\(|flask\.Flask|Blueprint\("              # Python
    r"|app\.(get|post|put|delete|use)\(|express\(\)|router\.(get|post)|createServer"      # Node
    r"|http\.HandleFunc|gin\.|mux\.NewRouter|echo\.New\("                                  # Go
)
_FRONTEND_DEPS = ("react", "react-dom", "@angular/core", "vue", "next", "svelte", "webpack", "vite")


def _iter_files(repo_root: Path):
    n = 0
    for p in repo_root.rglob("*"):
        if not p.is_file() or (set(p.parts) & _SKIP):
            continue
        yield p
        n += 1
        if n >= _MAX_FILES:
            break


def gather_exposure_evidence(repo_root: Path) -> dict:
    """Cheap, bounded scan for internet-facing vs internal signals."""
    ev = {"expose_ports": [], "k8s_public": [], "controllers": 0, "controller_files": [],
          "frontend": [], "server_config": [], "entrypoints": []}
    for p in _iter_files(repo_root):
        name, ext = p.name.lower(), p.suffix.lower()
        try:
            # Read only the file types we care about (and keep it light).
            if name.startswith("dockerfile"):
                txt = p.read_text("utf-8", "ignore")
                ev["expose_ports"] += re.findall(r"(?im)^\s*EXPOSE\s+([0-9 ]+)", txt)
                ev["entrypoints"] += re.findall(r"(?im)^\s*(?:ENTRYPOINT|CMD)\s+(.+)$", txt)[:2]
            elif ext in (".yaml", ".yml"):
                txt = p.read_text("utf-8", "ignore")
                if re.search(r"kind:\s*Ingress", txt) or re.search(r"type:\s*(LoadBalancer|NodePort)", txt):
                    ev["k8s_public"].append(p.name)
            elif name == "package.json":
                txt = p.read_text("utf-8", "ignore")
                hits = [d for d in _FRONTEND_DEPS if f'"{d}"' in txt]
                if hits:
                    ev["frontend"].append(f"{p.parent.name}/package.json: {', '.join(hits[:4])}")
            elif ext in (".java", ".py", ".js", ".ts", ".go", ".kt"):
                txt = p.read_text("utf-8", "ignore")
                if _CONTROLLER_RE.search(txt):
                    ev["controllers"] += 1
                    if len(ev["controller_files"]) < 6:
                        ev["controller_files"].append(p.name)
            elif name.startswith("application") and ext in (".properties", ".yml", ".yaml"):
                txt = p.read_text("utf-8", "ignore")
                for m in re.findall(r"(?im)^\s*(server\.port|server\.servlet\.context-path|spring\.mvc[^\n=]*)\s*[=:].*$", txt):
                    pass
                if re.search(r"(?im)server\.port|server\.servlet|spring\.mvc|spring-boot-starter-web", txt):
                    ev["server_config"].append(p.name)
        except Exception:
            continue
    # de-dup / trim
    ev["expose_ports"] = sorted(set(x.strip() for x in ev["expose_ports"]))[:5]
    ev["k8s_public"] = sorted(set(ev["k8s_public"]))[:5]
    ev["server_config"] = sorted(set(ev["server_config"]))[:5]
    ev["frontend"] = ev["frontend"][:5]
    return ev


def _digest(ev: dict) -> str:
    parts = []
    parts.append(f"Dockerfile EXPOSE ports: {ev['expose_ports'] or 'none'}")
    parts.append(f"k8s public exposure (Ingress / LoadBalancer / NodePort): {ev['k8s_public'] or 'none'}")
    parts.append(f"web controllers/routes found: {ev['controllers']} ({', '.join(ev['controller_files']) or 'none'})")
    parts.append(f"frontend (browser-shipped) bundles: {ev['frontend'] or 'none'}")
    parts.append(f"server/web config: {ev['server_config'] or 'none'}")
    if ev["entrypoints"]:
        parts.append(f"container entrypoint(s): {ev['entrypoints']}")
    return "\n".join(parts)


def classify_exposure(repo_root, repo_name: str = "") -> dict:
    """Return {exposure, confidence, reason, evidence} for a repo, cached.
    exposure ∈ {"internet-facing", "internal", "unknown"}."""
    repo_root = Path(repo_root)
    key = str(repo_root.resolve())
    with _LOCK:
        if key in _CACHE:
            return _CACHE[key]

    if not repo_root.is_dir():
        return {"exposure": "unknown", "confidence": "low", "reason": "repo not available locally", "evidence": {}}

    ev = gather_exposure_evidence(repo_root)
    digest = _digest(ev)

    # Fast deterministic shortcut: clear public infra signal needs no LLM.
    strong_public = bool(ev["expose_ports"] or ev["k8s_public"] or ev["frontend"])
    prompt = f"""You are an application-security engineer classifying a service's external exposure.

Decide whether the service "{repo_name or repo_root.name}" is INTERNET-FACING (reachable from
the public internet — public HTTP endpoints, an exposed/published port, a k8s Ingress or
LoadBalancer, or a browser-shipped frontend) or INTERNAL (backend-only: worker, batch job,
queue/topic consumer, internal microservice, library, or script with no public exposure).

Exposure evidence gathered from the repo:
{digest}

Notes:
- A frontend bundle shipped to browsers is ALWAYS internet-facing (its library versions are public).
- A webhook RECEIVER (accepts inbound HTTP from third parties) is internet-facing.
- Pure consumers/producers of internal queues, cron/batch jobs, and shared libraries are internal.
- EXPOSE in a Dockerfile or an Ingress/LoadBalancer strongly indicates internet-facing.

Respond EXACTLY:
EXPOSURE: internet-facing | internal | unknown
CONFIDENCE: high | medium | low
REASON: one sentence
"""
    # client_side = ships a browser frontend → its JS library versions are PUBLICLY visible
    # in the served bundle (an external scanner fingerprints them without code access).
    client_side = bool(ev["frontend"])
    res = {"exposure": "unknown", "confidence": "low", "reason": "", "client_side": client_side, "evidence": ev}
    try:
        resp = _llm_chat(prompt)
        for line in resp.splitlines():
            k, _, v = line.partition(":")
            k, v = k.strip().upper(), v.strip()
            if k == "EXPOSURE":
                low = v.lower()
                res["exposure"] = ("internet-facing" if "internet" in low or "facing" in low or "public" in low
                                   else "internal" if "internal" in low else "unknown")
            elif k == "CONFIDENCE":
                res["confidence"] = v.lower().split()[0] if v else "low"
            elif k == "REASON":
                res["reason"] = v
    except Exception as e:
        logging.warning("exposure classify failed: %s", e)
        # Fall back to the deterministic infra signal.
        res["exposure"] = "internet-facing" if strong_public else "unknown"
        res["reason"] = f"(heuristic fallback) {digest.splitlines()[0]}"

    with _LOCK:
        _CACHE[key] = res
    return res
