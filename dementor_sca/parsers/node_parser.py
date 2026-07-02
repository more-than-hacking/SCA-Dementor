import json
import os

def parse_package_json(file_path):
    dependencies = []
    skipped = []

    try:
        with open(file_path, 'r') as f:
            data = json.load(f)

        for section in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]:
            deps = data.get(section, {})
            for name, version in deps.items():
                version = version.strip()
                # Clean versions like ^1.2.3, ~1.2.3, >=1.0.0 etc.
                cleaned_version = version.lstrip("^~>=< ")
                if not cleaned_version or cleaned_version.startswith("git") or cleaned_version.startswith("file"):
                    skipped.append(f"{name} with unsupported version '{version}' in {file_path}")
                    continue

                dependencies.append({
                    "ecosystem": "npm",
                    "file": os.path.abspath(file_path),
                    "library": name,
                    "version_constraint": version,
                    "version": cleaned_version,
                    "resolved": cleaned_version,
                })

    except Exception as e:
        skipped.append(f"Error parsing {file_path}: {str(e)}")

    return dependencies, skipped

def parse(file_path):
    if os.path.basename(file_path) == "package.json":
        return parse_package_json(file_path)
    return [], []
