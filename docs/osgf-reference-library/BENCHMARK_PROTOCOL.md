# Cross-version benchmark and dataset admission

New contract: `osgf.reference-benchmark/0.1.0`. Historical graph-first protocols and datasets remain untouched. This contract's D means directional coverage, not the older study's blended D; the condition definitions are embedded in every result.

| Condition | Meaning |
|---|---|
| A | Frozen original aggregate set Jaccard |
| B | Existing graph-first set Jaccard |
| C | Existing operational-only set Jaccard, only with compatible artifacts |
| D | Directional base-evidence set reference coverage |
| E | Existing top-5 operational slot refinement over B; missing slots retain rank |

E is a ranking policy. Its ROC/classification use the unchanged B score and must not be advertised as a distinct blended classifier. All conditions use the exact same directed pair list, annotated truth and gallery. Unknown truth is not inferred from family, filename or score: such regions can be searched but are excluded from supervised metrics and must be counted in the extraction report.

Dataset cases explicitly declare ID, split, source family, near-duplicate group, binary SHA-256, query artifact or reference ID, optional operational artifact, group, compiler, optimization and annotation source. Pairs explicitly declare query, reference, boolean truth, hard-negative status and annotation source. Complete within-split query galleries are required. Binary, source-family and declared near-duplicate groups cannot cross splits. Identical binaries cannot form pairs or be reused across query/reference roles. Near-duplicate group truth is curator supplied; the runner does not discover unknown code sharing.

Preregistration hashes the dataset, complete library, query/operational artifacts, engines and evaluation dependencies. Scoring fails if any pinned bytes change. Output directories must be new. No-seed query cases may contain a validated empty seed-search index; their scores remain null and they remain in retrieval denominators. Eligible indexes must be expanded into individual seeds. Seed eligibility and classifier availability are separate.

ROC AUC and raw pAUC over FPR [0,0.05], MRR, Recall@1/3/5, tie bounds, margins, candidate recall, hard-negative rows, collisions, per-group metrics and macro group AUC are reported. Pair-level metrics are micro-aggregated. Thresholds maximize balanced accuracy on discovery only, with the largest threshold chosen on ties. If both comparable discovery classes are unavailable, classification is unavailable. Never tune on heldout results. Correlated variants are not independent statistical samples.

## Current controlled pilot

`run_reference_controlled.py` authors a benign public-symbol lookup program with subject/equivalent routines, a same-API different-symbol hard negative, and a no-seed arithmetic probe. GCC O0/O2 binaries are compiled but never executed; Ghidra analyzes them statically. Every automatic seed is searched; source-contract annotations are applied downstream for metrics. The design and source hash are written before extraction. Final artifact preregistration occurs before scoring.

This is one development lineage, intentionally discovery-only. It cannot supply independent validation, heldout or malware-generalization conclusions. `--query-msvc` compares GCC references against the installed MSVC query compiler using the existing compiler inventory. `--query-helper` moves the subject observation into a separately detected callee; source-contract region mapping is applied after automatic detection. These optional variants were actually executed. Do not split variants across partitions to make the tables look complete. The runner accepts future independently curated datasets with all three partitions. Broad independent file/network/cryptographic families remain additional scientific work.

```powershell
python scripts/run_reference_controlled.py --output .build-cache/new-reference-pilot --engine rust_engine/target/debug/rust_engine.exe --operational-engine rust_engine/operational/target/debug/osgf_operational.exe --compiler C:/MinGW/bin/gcc.exe --ghidra 'C:/Users/aless/Desktop/_/Projects/ghidra_12.0.4_PUBLIC' --ghidra-python 'C:/Users/aless/AppData/Roaming/ghidra/ghidra_12.0.4_PUBLIC/venv/Scripts/python.exe' --java-home 'C:/Program Files/Eclipse Adoptium/jdk-25.0.2.10-hotspot'
python scripts/reference_benchmark.py preregister --dataset path/to/dataset.json --library path/to/library --engine rust_engine/target/debug/rust_engine.exe --output path/to/new-registration.json
python scripts/reference_benchmark.py run --dataset path/to/dataset.json --library path/to/library --engine rust_engine/target/debug/rust_engine.exe --registration path/to/new-registration.json --output path/to/new-evaluation
```

Use `--operational-engine` consistently at preregistration and evaluation when supplied. Absolute paths are pinned in the registration: relocating a study requires a new explicitly recorded registration, not editing old metadata.

## Authorized malware admission protocol (not executed)

1. Obtain explicit institutional authorization and document repository/source, license, acquisition date, SHA-256 and chain of custody. Do not download arbitrary samples automatically.
2. Use a suitable isolated static research environment. Never run samples or disable endpoint protection. Preserve any quarantine and do not bypass the blocked historical graph-first experiment.
3. Record executable format/architecture, tool versions, raw graphs, all seed triggers, extraction limits and source-bound canonical/fingerprint artifacts. Keep samples under the authorized storage policy; the library need only store derived artifacts.
4. Have independent analyst evidence identify region functionality, uncertainty and annotation source before inspecting similarity scores. Malware-family attribution alone is neither function equivalence nor proof of maliciousness. Distinguish documented malicious, associated, generic, benign and unknown regions.
5. Curate hard negatives sharing APIs, literals, topology, broad families and common library code. Maintain separate source/lineage/near-duplicate groups and disjoint query/reference binary roles. Audit unknown shared libraries explicitly.
6. Preregister discovery/validation/heldout groups, labels, gallery, candidate policies and engine hashes. Fix thresholds on discovery only. Preserve all failed extractions and unknown/no-seed cases in accounting.
7. Report availability, seed coverage, per-family retrieval and hard-negative errors alongside pooled metrics; use independent group replication before generalization claims.

No authorized malware corpus is currently populated by this task. This absence blocks malware scientific acceptance, not engineering tests.
