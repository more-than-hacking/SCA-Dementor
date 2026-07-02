"""Regression test: scan logs must never leak secrets.

Git clone URLs embed the PAT (https://<token>@github.com/...) and subprocess errors echo the
full command — so a clone failure leaked the token into the scan log/UI. _log() now redacts.

Run standalone:  python tests/test_log_redaction.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dementor_sca.scan_runner import _redact

SECRETS = ["ghp_AAAAAAAAAAAAAAAAAAAAAA", "gho_BBBBBBBBBBBBBBBBBBBBBB",
           "ghs_CCCCCCCCCCCCCCCCCCCCCC", "github_pat_11ABCDE0abcdefghij1234567"]


def _no_secret(s):
    return not any(tok in s for tok in SECRETS)


def test_url_embedded_token_redacted():
    msg = "Command '['git','clone','--depth','1','https://ghp_AAAAAAAAAAAAAAAAAAAAAA@github.com/acme/x.git','/p']' returned non-zero exit status 128."
    out = _redact(msg)
    assert _no_secret(out), out
    assert "https://***@github.com" in out


def test_all_github_token_forms_redacted():
    for tok in SECRETS:
        out = _redact(f"failed with {tok} embedded")
        assert _no_secret(out), out


def test_key_value_secrets_redacted():
    for s in ("Authorization: token ghs_CCCCCCCCCCCCCCCCCCCCCC", "api_key=ghp_AAAAAAAAAAAAAAAAAAAAAA"):
        assert _no_secret(_redact(s)), s


def test_plain_text_unchanged():
    msg = "Damn-vulnerable-sca: 25 vulnerable libraries found"
    assert _redact(msg) == msg


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        try:
            fn(); print(f"  ok  {fn.__name__}"); passed += 1
        except AssertionError as e:
            print(f"FAIL  {fn.__name__}: {e}")
    print(f"\n{passed}/{len(fns)} passed")
    sys.exit(0 if passed == len(fns) else 1)
