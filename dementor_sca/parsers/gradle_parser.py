import os
import re

def parse(file_path):
    if not os.path.exists(file_path):
        return [], [f"{file_path} not found"]

    dependencies = []
    skipped = []

    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
    except Exception as e:
        return [], [f"Failed to read {file_path}: {str(e)}"]

    # Gradle dependency declaration regex
    # Matches: implementation 'group:artifact:version'
    dep_pattern = re.compile(r'^\s*(implementation|api|compile|testImplementation|runtimeOnly|annotationProcessor)\s+[\'"]([^\'"]+):([^\'"]+):([^\'"]+)[\'"]')

    for lineno, line in enumerate(lines, start=1):
        match = dep_pattern.search(line)
        if not match:
            continue

        group_id = match.group(2).strip()
        artifact_id = match.group(3).strip()
        version = match.group(4).strip()

        # Skip placeholders or unresolved versions
        if not version or any(c in version for c in ['$', '{', '}', '(', ')']):
            skipped.append(f"Unresolved version '{version}' for {group_id}:{artifact_id} at line {lineno} in {file_path}")
            continue

        dependencies.append({
            "ecosystem": "maven",
            "file": os.path.abspath(file_path),
            "library": f"{group_id}:{artifact_id}",
            "version": version,
            "raw_version": version,
            "resolved": version
        })

    return dependencies, skipped
