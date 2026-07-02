import os
import re

def clean_python_version(version_constraint):
    if not version_constraint:
        return None
    # Remove any leading operators like ==, >=, <=, ~=, !=, etc.
    cleaned = re.sub(r'^[><=~!]+', '', version_constraint).strip()
    # Extract the first version number from cleaned string
    versions = re.findall(r'[\d]+(?:\.[\d]+)*', cleaned)
    if versions:
        return versions[0]
    return None

def parse_requirements_txt(file_path):
    dependencies = []
    skipped = []

    with open(file_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            dep_spec = line.split(';')[0].strip()

            if dep_spec.startswith('-e ') or dep_spec.startswith('--'):
                continue

            match = re.match(r'^([a-zA-Z0-9_\-\.]+)(.*)$', dep_spec)
            if not match:
                skipped.append(f"Line {line_num} invalid in {file_path}: {line}")
                continue

            pkg = match.group(1)
            ver_constraint = match.group(2).strip() or None

            cleaned_version = clean_python_version(ver_constraint)
            if ver_constraint and cleaned_version is None:
                skipped.append(f"Line {line_num} unrecognized version '{ver_constraint}' for {pkg} in {file_path}")
                continue

            dependencies.append({
                "ecosystem": "pypi",
                "file": os.path.abspath(file_path),
                "library": pkg,
                "version_constraint": ver_constraint,
                "version": cleaned_version,
                "resolved": cleaned_version
            })

    return dependencies, skipped

def parse(file_path):
    if not file_path.endswith('requirements.txt'):
        return [], []
    return parse_requirements_txt(file_path)
