import hashlib
import json
from pathlib import Path


KINDS = (
    "Models", "Datasets", "Adapters", "Agents", "Agent cards",
    "Tools", "MCP servers", "Prompts & policies", "Runtime", "Other",
)


def read_json(path):
    def unique_keys(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"Duplicate JSON key: {key}")
            result[key] = value
        return result

    with Path(path).open(encoding="utf-8-sig") as source:
        return json.load(source, object_pairs_hook=unique_keys)


def category(component):
    properties = {item["name"]: item.get("value", "") for item in component.get("properties", [])}
    kind = properties.get("demo:kind", "")
    if "adapter" in kind or "lora" in kind:
        return "Adapters"
    if kind == "ai-agent":
        return "Agents"
    if kind == "a2a-agent-card":
        return "Agent cards"
    if kind == "agent-tool":
        return "Tools"
    if kind == "mcp-server":
        return "MCP servers"
    if kind in ("prompt", "policy", "guardrail"):
        return "Prompts & policies"
    return {
        "machine-learning-model": "Models", "data": "Datasets",
        "container": "Runtime", "operating-system": "Runtime", "platform": "Runtime",
    }.get(component.get("type"), "Other")


def inventory(bom):
    if not isinstance(bom, dict) or bom.get("bomFormat") != "CycloneDX":
        raise ValueError("Expected a CycloneDX JSON AIBOM.")
    result = {}

    def visit(items, nested_key):
        if not isinstance(items, list):
            raise ValueError(f"{nested_key} must be an array.")
        for item in items:
            if not isinstance(item, dict):
                raise ValueError("Each inventory entry must be an object.")
            ref = item.get("bom-ref")
            if not isinstance(ref, str) or not ref.strip():
                raise ValueError("Every component and service needs a nonempty bom-ref.")
            if ref in result:
                raise ValueError(f"Duplicate bom-ref: {ref}")
            result[ref] = item
            visit(item.get(nested_key, []), nested_key)

    visit(bom.get("components", []), "components")
    visit(bom.get("services", []), "services")
    root = bom.get("metadata", {}).get("component")
    if root:
        visit([root], "components")
    return result


def definition(component):
    result = dict(component)
    result.pop("components", None)
    result.pop("services", None)
    for field in ("hashes", "properties"):
        if field in result:
            result[field] = sorted(result[field], key=lambda item: json.dumps(item, sort_keys=True))
    return result


def digest_file(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def sha256(component):
    matches = [item.get("content", "").lower() for item in component.get("hashes", [])
               if item.get("alg") == "SHA-256"]
    if len(matches) > 1:
        raise ValueError("Multiple SHA-256 declarations on one artifact.")
    if not matches:
        return None
    value = matches[0]
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError("Invalid SHA-256 digest.")
    return value


def dependency_map(bom, refs):
    result = {}
    for entry in bom.get("dependencies", []):
        ref = entry.get("ref")
        targets = entry.get("dependsOn", [])
        if ref not in refs or ref in result or not isinstance(targets, list):
            raise ValueError("Invalid or duplicate dependency source.")
        if any(not isinstance(target, str) or target not in refs for target in targets):
            raise ValueError(f"Unresolved dependency from {ref}.")
        if len(targets) != len(set(targets)):
            raise ValueError(f"Duplicate dependency target for {ref}.")
        result[ref] = set(targets)
    return {ref: result.get(ref, set()) for ref in refs}


def load_manifest(path):
    manifest = read_json(path)
    if not isinstance(manifest, dict) or manifest.get("manifestVersion") != 1:
        raise ValueError("Expected manifestVersion 1.")
    entries = inventory(manifest["baseline"])
    if not entries:
        raise ValueError("The reference inventory is empty.")
    dependency_map(manifest["baseline"], entries)
    for component in entries.values():
        sha256(component)
    paths = manifest.get("artifactPaths", {})
    if not isinstance(paths, dict) or any(ref not in entries or not isinstance(value, str)
                                          for ref, value in paths.items()):
        raise ValueError("artifactPaths must map known bom-refs to relative paths.")
    return manifest


def evidence_warnings(manifest, ref, record):
    policy = manifest.get("evidenceExpectations", {})
    requirements = dict(policy.get("defaults", {}))
    requirements.update(policy.get("artifacts", {}).get(ref, {}))
    properties = record.get("properties", []) if record else []
    if not isinstance(properties, list):
        properties = []
    warnings = []
    for claim, requirement in sorted(requirements.items()):
        if not requirement.get("required", False):
            continue
        declarations = [item.get("value") for item in properties
                        if isinstance(item, dict) and item.get("name") == f"demo:evidence:{claim}"]
        declared = declarations[0] if len(declarations) == 1 else (
            "NOT_RECORDED" if not declarations else "AMBIGUOUS")
        expected = requirement.get("requiredAssessment", "VERIFIED")
        if not isinstance(declared, str) or declared != expected:
            warnings.append(f"{claim}: declared {declared}; requires {expected}.")
        elif expected == "VERIFIED":
            warnings.append(f"{claim}: declares VERIFIED; supporting evidence has not been verified.")
    return warnings


def verify_dummy(manifest, bom):
    expected = inventory(manifest["baseline"])
    actual = inventory(bom)
    rows = []
    for ref in sorted(expected.keys() | actual.keys()):
        reference = expected.get(ref)
        candidate = actual.get(ref)
        item = candidate or reference
        expected_hash = sha256(reference) if reference else None
        try:
            submitted_hash = sha256(candidate) if candidate else None
            if reference is None:
                status = "UNEXPECTED"
            elif candidate is None:
                status = "MISSING"
            elif expected_hash is None or submitted_hash is None:
                status = "NO HASH"
            else:
                status = "MATCH" if expected_hash == submitted_hash else "MISMATCH"
        except (ValueError, TypeError, AttributeError):
            submitted_hash = "Invalid hash"
            status = "MISMATCH"
        rows.append({"ref": ref, "name": item.get("name", ref), "status": status,
                     "expectedHash": expected_hash, "submittedHash": submitted_hash,
                     "evidenceWarnings": evidence_warnings(manifest, ref, candidate)})
    return rows


def verify(manifest, bom, artifact_root=None):
    expected = inventory(manifest["baseline"])
    actual = inventory(bom)
    expected_edges = dependency_map(manifest["baseline"], expected)
    actual_edges = dependency_map(bom, actual)
    root = Path(artifact_root).resolve() if artifact_root else None
    rows = []
    for ref in sorted(expected.keys() | actual.keys()):
        reference = expected.get(ref)
        candidate = actual.get(ref)
        item = candidate or reference
        issues = []
        declaration = "Not checked"
        byte_status = "Not checked"
        expected_digest = sha256(reference) if reference else None
        actual_digest = None
        if reference is None:
            issues.append("Unexpected artifact")
        elif candidate is None:
            issues.append("Missing artifact")
        else:
            declared_digest = sha256(candidate)
            if definition(reference) != definition(candidate):
                issues.append("Definition changed")
            if expected_edges[ref] != actual_edges[ref]:
                issues.append("Relationships changed")
            if expected_digest:
                declaration = "Match" if declared_digest == expected_digest else "Mismatch"
                if declared_digest != expected_digest:
                    issues.append("Declared digest missing or changed")
            else:
                declaration = "No reference digest"
            relative = manifest.get("artifactPaths", {}).get(ref)
            if root is not None and relative and expected_digest:
                path = (root / relative).resolve()
                if Path(relative).is_absolute() or not path.is_relative_to(root):
                    byte_status = "Blocked path"
                    issues.append("Artifact path escapes selected root")
                else:
                    try:
                        actual_digest = digest_file(path)
                        byte_status = "Match" if actual_digest == expected_digest else "Mismatch"
                        if actual_digest != expected_digest:
                            issues.append("Artifact bytes changed")
                    except OSError as error:
                        byte_status = "Unavailable"
                        issues.append(f"Artifact unreadable: {error.strerror or str(error)}")
            elif expected_digest:
                byte_status = "Not supplied" if root is None else "No reference path"
        status = "FAIL" if issues else ("BYTES MATCH" if byte_status == "Match" else "DECLARATION ONLY")
        rows.append({
            "ref": ref, "name": item.get("name", ref), "kind": category(item),
            "status": status, "declaration": declaration, "bytes": byte_status,
            "signature": "Not verified", "issues": issues,
            "expectedSha256": expected_digest, "actualSha256": actual_digest,
            "expected": reference, "submitted": candidate,
            "expectedDependencies": sorted(expected_edges.get(ref, set())),
            "submittedDependencies": sorted(actual_edges.get(ref, set())),
        })
    return rows