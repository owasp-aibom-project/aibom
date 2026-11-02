# Integrity Checker

Lightweight CustomTkinter desktop application. Python 3.11+ with Tk, CustomTkinter, Pillow, and NetworkX are required. No web framework, database, or network access is needed at runtime.

From the repository root on Windows:

1. Create a virtual environment:

```powershell
python -m venv ws-10-integrity\.venv
```

2. Install the dependencies:

```powershell
.\ws-10-integrity\.venv\Scripts\python.exe -m pip install -r ws-10-integrity\src\integrity-checker\requirements.txt
```

3. Run the application:

```powershell
.\ws-10-integrity\.venv\Scripts\python.exe ws-10-integrity\src\integrity-checker\app.py
```

4. Run the tests (optional):

```powershell
.\ws-10-integrity\.venv\Scripts\python.exe -m unittest discover -s ws-10-integrity\tests\integrity-checker -v
```

## Artifact browser

The Artifacts tab groups the reference inventory into type cards. Select a card for its searchable artifact list, then select an artifact for its complete reference record, file path, dependencies, and reverse dependencies. Empty types remain visible. The `demo:kind` convention distinguishes agents, adapters, tools, MCP servers, policies, and Agent Cards; other entries use their CycloneDX component type.

## Verification

The Verify AIBOM tab compares **dummy hash declarations** and separately flags insufficient evidence declarations. It does not read artifact files, verify signatures, or validate dependency relationships.

Choose Open AIBOM to select a CycloneDX JSON file; comparison runs automatically. The compact list shows artifact names and results. Select a row to reveal its manifest and submitted hashes. The footer labels the dummy-hash mode.

- Samples > Matching sample: fourteen matching dummy hashes across two independent flows.
- Samples > Modified sample: thirteen matching hashes and one deliberately changed support-model hash. The flow view additionally marks three support dependents AT RISK; the independent translation flow remains green.
- Reference > Save example: export the matching reference AIBOM for upload or manual editing.

Results are MATCH, MISMATCH, MISSING, UNEXPECTED, or NO HASH. Missing hashes never count as matches. Invalid submitted SHA-256 values are reported as mismatches for the affected artifact.

The values are fabricated 64-character hexadecimal strings, such as repeated `1` or `2` characters, not hashes calculated from real artifacts. No artifact folder or additional verification settings are required.

## Flows

The Flows page automatically builds a directed graph from the current AIBOM's `dependencies`. Arrows run from dependency to consumer. These are declared relationships, not observed runtime execution or evidence that a transformation occurred. The reference is shown as a gray NOT CHECKED preview until an AIBOM or sample is loaded.

- Green: the artifact's dummy hash matches the manifest and it has no known unmatched upstream dependency.
- Yellow-orange (AT RISK): its own hash matches, but it depends directly or indirectly on an unmatched artifact.
- Red: mismatching/missing hash, missing artifact, unexpected artifact, or unresolved reference.

Open AIBOM and the Samples menu work directly on this page. Results stay synchronized with Verify AIBOM. Click a node for its reference, status, and full hashes. Use the mouse wheel or +/- to zoom, drag to pan, and Fit to frame the graph. Branches, cycles, self-references, and disconnected artifacts are supported. Missing reference artifacts remain visible, potentially disconnected when their relationships are absent from the uploaded AIBOM.

The demo contains two disconnected flows, laid out in separate horizontal bands. The translation flow has its own base model, dataset, LoRA adapter, and agent. The base model and dataset feed adapter training; the agent uses the base model with the adapter as its fine-tuned configuration, not a separate merged weight file. None of these four artifacts depends on the support flow.

Warnings propagate transitively through declared dependencies, including cycles. Direct hash failures remain red and take precedence over inherited warnings. Node details preserve the original hash result and list the unmatched upstream references responsible for the warning. This flags dependency risk, not proof that downstream bytes changed or that an artifact is compromised. Loading a corrected AIBOM recalculates warnings. Relationship authenticity and changes are not verified. If dependency declarations are malformed, the page shows an error instead of an outdated graph.

## Static reference format

`manifest.json` contains `manifestVersion: 1`, release metadata, and a CycloneDX `baseline`. Each artifact has a unique `bom-ref` and a dummy SHA-256 entry in `hashes`. Inventory order does not matter; comparisons use `bom-ref`, not array positions. Nested components/services and the metadata root component are included when present.

Use Reference > Open manifest to select a different static reference. The existing local example files and `artifactPaths` remain available as reference metadata but are not used by the simplified verifier. No database is required.

## Evidence expectations and declarations

The standalone `aibom-dummy.cdx.json` and `aibom-unmatched.cdx.json` files each include six custom `demo:evidence:*` properties on every artifact:

| Property suffix | Declared demo values | Meaning |
| --- | --- | --- |
| `publisher_identity` | `SELF_ASSERTED` | Publisher identity is not independently corroborated. |
| `artifact_integrity` | `NOT_CHECKED` | Actual artifact bytes have not been verified. A dummy hash MATCH does not change this declaration. |
| `provider_artifact_signature` | `ABSENT` | No provider artifact signature is supplied. |
| `lineage` | `SELF_ASSERTED`, `PARTIAL`, `UNKNOWN` | History is declared, incompletely described, or unknown; not cryptographically established. |
| `training_data_provenance` | `SELF_ASSERTED`, `UNKNOWN`, `NOT_APPLICABLE` | Dataset origins are declared or unknown. NOT_APPLICABLE concerns the artifact itself (for example an agent definition), not its model dependencies. |
| `independent_attestation` | `NONE` | No independent attestation is supplied. |

These are demonstration conventions, not standard CycloneDX status fields or computed verification results. They deliberately mix availability, coverage, and support labels inherited from the legacy example; they are not a ranked trust scale. No VERIFIED claims or fictitious evidence links are added.

The manifest's top-level `evidenceExpectations` describes policy version `demo-evidence-1`. Its defaults request verified publisher identity, real byte integrity, and an authorized artifact signature; independent attestation is optional. Per-artifact requirements add training lineage and dataset provenance where specified. Defaults apply to every artifact being compared; artifact-specific entries add or override the corresponding claim requirement. A required claim needs actual supporting evidence, not merely a matching status string.

`expectedInputs` lists approved input bom-refs, whose exact approved hashes are found in the baseline. A future provenance verifier must check both the output digest and these input digests against an authenticated manifest. Training input requirements describe expected provenance; they are not inferred from or substituted for the display dependency graph. Authorized identities, concrete verification rules, and supporting evidence still need configuration before real enforcement is possible.

An amber warning symbol appears beside artifacts in the browser, verification results, and flow nodes when required evidence declarations are missing, ambiguous, or do not match the required assessment. Hover over the symbol for its meaning and select the artifact for the per-claim details. Optional requirements do not trigger warnings. A declared VERIFIED value also warns when VERIFIED is required, because the application cannot verify supporting evidence. Other statuses are compared exactly, not ranked on a trust scale. No warning means no identified declaration gap under the configured requirements, not independently verified evidence.

Evidence warnings do not change hash results or graph colors and do not propagate to dependent artifacts. The browser uses declarations from the loaded AIBOM, or the reference baseline when no AIBOM is selected; its JSON artifact record remains the reference record. No evidence is retrieved, no signatures are verified, and expected training inputs are not assessed. All fourteen artifacts in the supplied files currently warn under the default requirements. Load the standalone files with Open AIBOM; the built-in Samples and Save example still use the unchanged manifest baseline and therefore warn about missing declarations. The matching file still has fourteen matching hashes; the unmatched file still differs only in the support-model hash.

## Trust boundary

This is a **simulation, not a security control**. The manifest is unsigned, matching declarations do not prove byte integrity, and signature or metadata changes are not checked. No files or URLs referenced by an uploaded AIBOM are opened. Do not use the demo as an untrusted multi-tenant service or load hostile oversized JSON documents.
