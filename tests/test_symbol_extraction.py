"""Tests for OSV vulnerable-symbol extraction (dementor_sca.pipeline_zero_fp).

Real code symbols must survive; prose words, vendor names, domains, filenames and
Latin abbreviations must be filtered (they previously produced false sinks that
polluted both reachability verdicts and the call-graph visualizer).

Run standalone:  python tests/test_symbol_extraction.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dementor_sca.pipeline_zero_fp import extract_vulnerable_symbols_from_osv


def test_keeps_real_symbols():
    v = {"summary": "RCE in deserialization",
         "details": "The `ObjectInputStream.readObject` method and `load_pem_public_key` are vulnerable."}
    syms = extract_vulnerable_symbols_from_osv(v)
    assert "ObjectInputStream.readObject" in syms
    assert "load_pem_public_key" in syms


def test_drops_prose_and_vendor_noise():
    v = {"summary": "Vulnerability in Apache Commons",
         "details": "This affects the application. The main entry point in Apache is vulnerable. "
                    "A remote attacker may use this. See version 1.2."}
    syms = extract_vulnerable_symbols_from_osv(v)
    for bad in ("main", "Apache", "application", "remote", "attacker", "version", "vulnerable"):
        assert bad not in syms, f"noise leaked: {bad}"


def test_drops_domains_files_abbreviations():
    v = {"details": "Visit bar.example.com (i.e. the host). Affected file rsakey.py and ElGamal.py. e.g. foo."}
    syms = extract_vulnerable_symbols_from_osv(v)
    for bad in ("example.com", "bar.example.com", "rsakey.py", "ElGamal.py", "i.e", "e.g"):
        assert bad not in syms, f"non-code token leaked: {bad}"


def test_prefers_qualified_over_bare():
    v = {"details": "The `ClassUtils.getClass` method is affected; getClass is the sink."}
    syms = extract_vulnerable_symbols_from_osv(v)
    assert "ClassUtils.getClass" in syms
    assert "getClass" not in syms          # bare suffix dropped in favour of qualified


def test_structured_symbols_rank_high():
    v = {"summary": "x", "details": "y",
         "database_specific": {"affected_functions": ["pkg.danger", "explicitSink"]}}
    syms = extract_vulnerable_symbols_from_osv(v)
    assert "pkg.danger" in syms and "explicitSink" in syms


def test_empty_when_no_symbols():
    v = {"summary": "A vulnerability exists.", "details": "Please update to the latest version."}
    # Only generic prose → nothing meaningful.
    assert extract_vulnerable_symbols_from_osv(v) == []


def test_reversed_noun_form_extracts_named_functions():
    # Advisory prose names the function BEFORE the noun ("X method/loader/functions") — common
    # in PyYAML/others. Must extract the code-shaped names.
    v = {"summary": "Improper Input Validation in PyYAML",
         "details": "susceptible to code execution through the full_load method or with the "
                    "FullLoader loader; the load_all functions are also affected."}
    syms = extract_vulnerable_symbols_from_osv(v)
    assert "full_load" in syms
    assert "FullLoader" in syms
    assert "load_all" in syms


def test_reversed_noun_form_rejects_english_words():
    # Plain-lowercase English words before those nouns must NOT be mistaken for symbols.
    v = {"details": "The affected function and a helper method in the vulnerable class allow attacks."}
    syms = extract_vulnerable_symbols_from_osv(v)
    for bad in ("affected", "helper", "vulnerable"):
        assert bad not in syms, f"English word leaked as symbol: {bad}"


def test_ignores_embedded_poc_code_block():
    # Advisories often paste a full PoC/unit test. Its local variables/imports (e.g.
    # numberText.length, System.out.println, factory.createParser) are NOT the library's
    # vulnerable API — matching them caused false reachability (any Java .length() matched).
    v = {"summary": "DoS in async parser",
         "details": "The `resetInt` validation is skipped in the async path.\n\n"
                    "```java\nString numberText = p.getText();\n"
                    "assertEquals(5000, numberText.length());\n"
                    "factory.createParser(payload);\nSystem.out.println(x);\n```\n"
                    "Use of `getBigIntegerValue` can then exhaust CPU."}
    syms = extract_vulnerable_symbols_from_osv(v)
    assert "resetInt" in syms                     # real symbol from prose kept
    assert "getBigIntegerValue" in syms
    for junk in ("numberText.length", "System.out.println", "factory.createParser", "length"):
        assert junk not in syms, f"PoC-code token leaked: {junk}"


def test_capped():
    details = " ".join(f"`mod.func{i}`" for i in range(40))
    syms = extract_vulnerable_symbols_from_osv({"details": details})
    assert len(syms) <= 12


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t(); print(f"  PASS  {t.__name__}")
        except AssertionError as e:
            failed += 1; print(f"  FAIL  {t.__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
