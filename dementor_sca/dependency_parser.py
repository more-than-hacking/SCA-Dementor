import os
import json
import yaml
import importlib
import glob
from pathlib import Path

from dementor_sca import REPO_ROOT

# --- Configurable Paths ---
_REPOS_DIR = REPO_ROOT / "REPOSITORIES"
REPO_ROOT_STR = os.environ.get("DEPENDENCY_SCAN_ROOT", str(_REPOS_DIR))
if not REPO_ROOT_STR.endswith(os.sep):
    REPO_ROOT_STR = REPO_ROOT_STR + os.sep
CONFIG_PATH = REPO_ROOT / "config" / "parser_config.yaml"
SKIPPED_LOG_PATH = REPO_ROOT / "skipped_libraries.log"


def load_config():
    with open(CONFIG_PATH, "r") as f:
        return yaml.safe_load(f)


def discover_files(root, config_by_lang):
    all_files = []
    for lang, config in config_by_lang.items():
        for pattern in config.get("patterns", []):
            search_pattern = os.path.join(root, "**", pattern)
            matched = glob.glob(search_pattern, recursive=True)
            matched_files = [f for f in matched if os.path.isfile(f)]
            all_files.extend(matched_files)
    return all_files


def main():
    config = load_config()
    all_results = []
    all_skipped = []

    for lang, lang_conf in config.items():
        parser_name = lang_conf.get("parser")
        patterns = lang_conf.get("patterns", [])

        try:
            parser_module = importlib.import_module(f"dementor_sca.parsers.{parser_name}")
        except ImportError:
            print(f"⚠️  Skipping '{lang}' - parser '{parser_name}' not found")
            continue

        if not hasattr(parser_module, "parse"):
            print(f"⚠️  Skipping '{lang}' - no 'parse()' function found in parser")
            continue

        print(f"\n🔍 Discovering files for '{lang}' using patterns: {patterns}")
        dep_files = discover_files(REPO_ROOT_STR, {lang: lang_conf})
        print(f"📄 Found {len(dep_files)} files for '{lang}'")

        for file_path in dep_files:
            try:
                results, skipped = parser_module.parse(file_path)
                all_results.extend(results)
                all_skipped.extend(skipped)
            except Exception as e:
                print(f"❌ Error parsing {file_path}: {e}")

    out_path = REPO_ROOT / "dependency_results.json"
    with open(out_path, "w") as f:
        json.dump(all_results, f, indent=2)

    if all_skipped:
        with open(SKIPPED_LOG_PATH, "w") as log_file:
            for entry in all_skipped:
                log_file.write(entry + "\n")
        print(f"⚠️ {len(all_skipped)} dependencies skipped. See {SKIPPED_LOG_PATH} for details.")

    print(f"\n✅ Dependency scan complete. Results saved to {out_path}")


if __name__ == "__main__":
    main()
