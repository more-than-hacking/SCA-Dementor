# Configuration

| File | Purpose | Committed? |
|------|---------|------------|
| `parser_config.yaml` | Language → parser module + file patterns for dependency discovery | Yes |
| `Languages.yaml` | Dependency file names kept when pruning clones (Repo_Dependency_Fetcher) | Yes |
| `zero_fp.yaml` | Zero-FP pipeline options (ollama_confirm_gate, report_path, etc.) | Yes |
| `org_config.yaml` | GitHub token and org name (**secrets**) | **No** (gitignored) |

## Setting up `org_config.yaml`

Create `org_config.yaml` with:

```yaml
GITHUB_TOKEN: your_github_token_here
org_name: your_github_org_name
```

Or set environment variables `GITHUB_TOKEN` and `ORG_NAME` (and leave `org_config.yaml` out of the repo).
