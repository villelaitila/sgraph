# Multi-SBOM Generator Design

## Problem

The current `sbom_cyclonedx_generator.py` produces a single CycloneDX SBOM for the entire model, iterating level-1 children and assuming one top-level element. For large organizational models (root -> Org -> Group -> Repo), we need per-repository SBOMs with inter-repo dependency tracking.

## Model Topology

```
root (level 0, unnamed)
  -> TalenomSoftware (level 1)
      -> GroupName (level 2)
          -> repositoryName (level 3)
      -> External (virtual container for 3rd party dependencies)
```

## Design

### Approach: Minimal extension to existing generator

Add a `--level` CLI parameter. When specified, generate one SBOM per element at that level. Default behavior (no `--level` or `--level 1`) remains unchanged.

### Data Flow (--level 3)

```
model.xml
    | load
SGraph (full model)
    | generalizer.generalize_model(level=target_level)
SGraph (flattened, dependencies coalesced to repo level)
    | collect elements at target level (excluding External)
[repo_A, repo_B, repo_C, ...]
    | per element:
    |   - External children -> 3rd party components (existing logic)
    |   - Dependencies to other level-N elements -> internal deps (BOM-Link)
    |   - UUID v5(element path) -> deterministic serialNumber
[SBOM_A, SBOM_B, SBOM_C, ...]
    | serialize
output.json (JSON array of all SBOMs)
```

### Spec Version Upgrade

CycloneDX 1.6 -> 1.7. Version 1.7 (Oct 2025) is the latest. The BOM-Link mechanism (for cross-SBOM references) has been available since 1.5 and is well-documented in 1.7.

### Identifiers

**serialNumber per repo:** UUID v5 with a fixed namespace and the element's path as the name.

```python
SGRAPH_SBOM_NS = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # or custom

def deterministic_serial(element_path: str) -> str:
    return f"urn:uuid:{uuid.uuid5(SGRAPH_SBOM_NS, element_path)}"
```

Same path always produces the same UUID, no state file needed.

**bom-ref per repo:** Slugified element name, e.g., `online3-invoicepayment`.

**BOM-Link URN** (for cross-SBOM dependency references):
```
urn:cdx:<serialNumber>/<version>#<bom-ref>
```

### Per-Repo SBOM Structure

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.7",
  "version": 1,
  "serialNumber": "urn:uuid:<uuid5-from-repo-path>",
  "metadata": {
    "timestamp": "...",
    "tools": [{"vendor": "Softagram", "name": "Softagram Analyzer", "version": "3.0"}],
    "component": {
      "type": "application",
      "name": "online3_invoicepayment",
      "bom-ref": "online3-invoicepayment"
    }
  },
  "components": [
    {"...3rd party components for this repo..."}
  ],
  "dependencies": [
    {
      "ref": "online3-invoicepayment",
      "dependsOn": [
        "urn:cdx:<uuid5-repo-B>/1#online3-sales",
        "pkg:nuget/Newtonsoft.Json@13.0.1"
      ]
    }
  ]
}
```

Both 3rd-party (purl) and internal (BOM-Link URN) dependencies appear in the same `dependsOn` list.

### External Element Handling

Each repo-SBOM includes only External elements that the repo actually depends on (via the generalized model's outgoing associations), not the entire global External tree.

### Flattening Internal Dependencies

Uses the existing `generalizer.py` to coalesce granular dependencies (e.g., csproj -> csproj) up to the target level. After generalization, outgoing associations between level-N elements represent repo-to-repo dependencies.

### Output Format

- `--level` specified: JSON array of SBOM objects
- No `--level` (default): Single SBOM object (backward compatible)

### CLI

```bash
# Existing behavior (unchanged)
python sbom_cyclonedx_generator.py model.xml sbom.json

# New: multi-SBOM at level 3
python sbom_cyclonedx_generator.py model.xml sbom.json --level 3
```

### DependencyTrack Note

DependencyTrack does not yet support cross-project BOM-Link stitching (open feature request #3375). However, per-project SBOM + internal dependency graph within each SBOM works today. The BOM-Link URNs are future-proof.

### Files to Change

| File | Change |
|------|--------|
| `sbom_cyclonedx_generator.py` | `--level` param, `generate_multi_from_sgraph()`, BOM-Link logic, spec 1.6->1.7 |
| `sbom_cyclonedx_generator_test.py` | New tests for multi-SBOM, inter-repo deps |
| `modelfile_for_sbom_tests.xml` | Extended model with 3+ levels and cross-repo deps |
