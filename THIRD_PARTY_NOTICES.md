# Third-Party Notices

Dementor — The SCA Hunter is released under the MIT License (see `LICENSE`). It depends on the
open-source components below. All are compatible with Dementor's MIT license and are used as
**unmodified** dependencies (installed via `pip`, not vendored or altered). No dependency is under
a strong-copyleft (GPL/AGPL) license, so none affects Dementor's own license.

## Runtime dependencies

| Component | License | Notes |
|---|---|---|
| requests | Apache-2.0 | permissive |
| PyYAML | MIT | permissive |
| python-dotenv | BSD-3-Clause | permissive |
| packaging | Apache-2.0 OR BSD-2-Clause | permissive |
| Flask | BSD-3-Clause | permissive |
| Werkzeug | BSD-3-Clause | permissive |
| Jinja2 | BSD-3-Clause | permissive |
| MarkupSafe | BSD-3-Clause | permissive |
| click | BSD-3-Clause | permissive |
| blinker | MIT | permissive |
| gunicorn | MIT | permissive |
| cryptography | Apache-2.0 OR BSD-3-Clause | permissive |
| PyJWT | MIT | permissive |
| PyNaCl | Apache-2.0 | permissive |
| urllib3 | MIT | permissive |
| idna | BSD-3-Clause | permissive |
| tree-sitter | MIT | permissive |
| tree-sitter-python / -java / -go / -javascript | MIT | permissive |
| **PyGithub** | **LGPL-3.0** | weak copyleft — used as an unmodified imported library; may be replaced/upgraded via pip |
| **tqdm** | **MPL-2.0 AND MIT** | file-level copyleft — unmodified; MPL obligations apply only to modified MPL files (none) |
| **certifi** | **MPL-2.0** | CA-certificate bundle — unmodified |

Using PyGithub (LGPL) and tqdm/certifi (MPL-2.0) as unmodified dependencies is permitted in an
MIT-licensed application. If you fork and **modify** any of these components, review that
component's license for the obligations that then apply (LGPL: publish the modified library and
allow relinking; MPL: publish modifications to the affected files).

## Vulnerability & threat-intelligence data

Dementor queries these public data sources over their APIs (data, not code). It does **not** use
the NVD/NIST API — OSV is used as the CVE source because it is package- and version-range aware
(more precise than NVD's CPE matching for library dependencies) and aggregates GitHub Security
Advisories, ecosystem databases (PyPI/npm/Go/RustSec) and CVE/NVD data.

- **OSV** (Open Source Vulnerabilities) — https://osv.dev — CVE/advisory data.
  License: **CC-BY-4.0** (OSV database and the GitHub Advisory Database it aggregates). Attribution
  is required; this notice provides it. Individual advisories may carry their own upstream licenses.
- **EPSS** (Exploit Prediction Scoring System) — FIRST.org — https://www.first.org/epss —
  free to use; attribution requested. Accessed keyless via `api.first.org`.
- **CISA KEV** (Known Exploited Vulnerabilities Catalog) — U.S. CISA — **public domain**
  (U.S. Government work); no restrictions.

Attribution: "This product uses the OSV database (https://osv.dev), the EPSS data from FIRST.org,
and the CISA Known Exploited Vulnerabilities Catalog."

## AI providers (optional, bring-your-own-key)

The optional AI scan calls a provider you configure (Google Gemini, OpenAI, or Anthropic) using
**your** API key, under that provider's terms. No provider SDK is bundled — calls are plain HTTPS.

---

To regenerate the dependency list and licenses:

```bash
pip install pip-licenses && pip-licenses --format=markdown
```
