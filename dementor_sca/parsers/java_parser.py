import os
import xml.etree.ElementTree as ET
import re

NAMESPACE = {"m": "http://maven.apache.org/POM/4.0.0"}

def load_pom(path):
    if not os.path.exists(path) or not os.path.isfile(path):
        return None
    try:
        tree = ET.parse(path)
        return tree.getroot()
    except ET.ParseError:
        return None

def extract_properties(root):
    props = {}
    props_el = root.find("m:properties", NAMESPACE)
    if props_el is not None:
        for prop in props_el:
            key = prop.tag.split("}")[-1]
            if prop.text:
                props[key] = prop.text.strip()

    project_ver = root.find("m:version", NAMESPACE)
    if project_ver is not None:
        props["project.version"] = project_ver.text.strip()

    parent_ver = root.find("m:parent/m:version", NAMESPACE)
    if parent_ver is not None and "project.version" not in props:
        props["project.version"] = parent_ver.text.strip()

    return props

def extract_dep_mgmt(root):
    versions = {}
    for dep in root.findall(".//m:dependencyManagement/m:dependencies/m:dependency", NAMESPACE):
        gid = dep.find("m:groupId", NAMESPACE)
        aid = dep.find("m:artifactId", NAMESPACE)
        ver = dep.find("m:version", NAMESPACE)
        if gid is not None and aid is not None and ver is not None:
            key = f"{gid.text.strip()}:{aid.text.strip()}"
            versions[key] = ver.text.strip()
    return versions

def resolve_parent_path(current_path, root):
    rel_el = root.find("m:parent/m:relativePath", NAMESPACE)
    rel_path = rel_el.text.strip() if rel_el is not None and rel_el.text else "../pom.xml"
    parent_path = os.path.abspath(os.path.join(os.path.dirname(current_path), rel_path))
    return parent_path

def parse(file_path):
    if not os.path.exists(file_path):
        return [], [f"{file_path} not found"]
    if not os.path.isfile(file_path):
        return [], [f"{file_path} is not a file"]

    root = load_pom(file_path)
    if root is None:
        return [], [f"XML parse error: {file_path}"]

    # Load parent POM if it exists
    parent_path = resolve_parent_path(file_path, root)
    parent_root = load_pom(parent_path)

    properties = {}
    dep_mgmt_versions = {}

    if parent_root is not None:
        properties.update(extract_properties(parent_root))
        dep_mgmt_versions.update(extract_dep_mgmt(parent_root))

    properties.update(extract_properties(root))  # override with current POM
    dep_mgmt_versions.update(extract_dep_mgmt(root))  # override with current POM

    results = []
    skipped = []

    for dep in root.findall(".//m:dependencies/m:dependency", NAMESPACE):
        gid_el = dep.find("m:groupId", NAMESPACE)
        aid_el = dep.find("m:artifactId", NAMESPACE)
        ver_el = dep.find("m:version", NAMESPACE)

        if gid_el is None or aid_el is None:
            skipped.append(f"Dependency missing groupId or artifactId in {file_path}")
            continue

        gid = gid_el.text.strip()
        aid = aid_el.text.strip()
        raw_version = ver_el.text.strip() if ver_el is not None else ""

        key = f"{gid}:{aid}"
        resolved_version = raw_version

        # Interpolated property resolution
        if raw_version.startswith("${") and raw_version.endswith("}"):
            prop_key = raw_version[2:-1]
            resolved_version = properties.get(prop_key, raw_version)

        # Fallback to dependencyManagement
        if not resolved_version and key in dep_mgmt_versions:
            resolved_version = dep_mgmt_versions[key]

        if not resolved_version:
            skipped.append(f"{key} with missing version in {file_path}")
            continue

        # Normalize version ranges like [4.21.0,5.0.0)
        range_match = re.match(r'[\[\(]\s*([^\],\)]+)', resolved_version)
        if range_match:
            original = resolved_version
            resolved_version = range_match.group(1).strip()
            # Optionally log:
            # print(f"ℹ️  Normalized version range {original} → {resolved_version} for {key}")

        # Clean version from (note) or [note] suffixes
        resolved_version = re.sub(r'[\(\[].*?[\)\]]', '', resolved_version).strip()

        if not resolved_version or resolved_version.startswith("${"):
            skipped.append(f"{key} with unresolved version '{raw_version}' in {file_path}")
            continue

        results.append({
            "library": key,
            "version": resolved_version,
            "raw_version": raw_version,
            "ecosystem": "maven",
            "file": file_path,
        })

    return results, skipped
