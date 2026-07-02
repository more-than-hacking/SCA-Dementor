import os
import re

def parse_go_mod(file_path):
    dependencies = []
    skipped = []

    if not os.path.exists(file_path) or not os.path.isfile(file_path):
        return [], [f"{file_path} not found or is not a file"]

    with open(file_path, "r") as f:
        lines = f.readlines()

    in_require_block = False

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()

        # Skip empty lines or comments
        if not stripped or stripped.startswith("//"):
            continue

        # Handle require block
        if stripped.startswith("require ("):
            in_require_block = True
            continue
        if in_require_block and stripped == ")":
            in_require_block = False
            continue

        # --- Handle replace directives ---
        if stripped.startswith("replace "):
            replace_stmt = stripped[len("replace "):]

            # Case 1: replace old_module old_version => new_module new_version
            match_full_replace = re.match(r'^([^\s]+)\s+([^\s]+)\s+=>\s+([^\s]+)\s+([^\s]+)$', replace_stmt)

            # Case 2: replace old_module => new_module version
            match_simple_replace = re.match(r'^([^\s]+)\s+=>\s+([^\s]+)\s+([^\s]+)$', replace_stmt)

            # Case 3: replace old_module => new_module (no version)
            match_minimal_replace = re.match(r'^([^\s]+)\s+=>\s+([^\s]+)$', replace_stmt)

            if match_full_replace:
                old_module, old_ver, new_module, new_ver = match_full_replace.groups()
                if not re.search(r'\d', new_ver):
                    skipped.append(f"Line {line_num} skipped (no digit in version) in {file_path}: '{line.strip()}'")
                    continue
                dependencies.append({
                    "ecosystem": "go",
                    "file": os.path.abspath(file_path),
                    "library": new_module,
                    "version_constraint": new_ver,
                    "version": new_ver,
                    "resolved": new_ver,
                    "replaces": f"{old_module} {old_ver}"
                })

            elif match_simple_replace:
                old_module, new_module, new_ver = match_simple_replace.groups()
                if not re.search(r'\d', new_ver):
                    skipped.append(f"Line {line_num} skipped (no digit in version) in {file_path}: '{line.strip()}'")
                    continue
                dependencies.append({
                    "ecosystem": "go",
                    "file": os.path.abspath(file_path),
                    "library": new_module,
                    "version_constraint": new_ver,
                    "version": new_ver,
                    "resolved": new_ver,
                    "replaces": old_module
                })

            elif match_minimal_replace:
                old_module, new_module = match_minimal_replace.groups()
                skipped.append(f"Line {line_num} skipped (no version in replace) in {file_path}: '{line.strip()}'")
                continue

            else:
                skipped.append(f"Line {line_num} invalid replace format in {file_path}: '{line.strip()}'")
                continue

            continue  # Skip remaining logic for replace lines

        # --- Handle single-line require ---
        if stripped.startswith("require "):
            stripped = stripped[len("require "):]
            in_require_block = False  # It's a one-liner now

        # --- Parse require lines (either from require (...) or single-line) ---
        if in_require_block or stripped:
            parts = stripped.split()
            if len(parts) < 2:
                skipped.append(f"Line {line_num} invalid in {file_path}: '{line.strip()}'")
                continue

            name = parts[0]
            version = parts[1].strip("()[]")

            if not re.search(r'\d', version):
                skipped.append(f"Line {line_num} skipped (no digit in version) in {file_path}: '{line.strip()}'")
                continue

            dependencies.append({
                "ecosystem": "go",
                "file": os.path.abspath(file_path),
                "library": name,
                "version_constraint": version,
                "version": version,
                "resolved": version
            })

    return dependencies, skipped


def parse(file_path):
    if not file_path.endswith("go.mod"):
        return [], []
    return parse_go_mod(file_path)
