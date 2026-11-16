# Semantic research benchmark v0.1

Date: 2026-11-09. New internally authored prospective pilot; not an external blinded benchmark. Method and primary condition/threshold policy were registered in method.json before source files were authored. No source family crosses a split. No old labels/splits/goldens changed.

The primary score is the fixed equal mean of the existing exact/multilevel mean and the new algebra-effect score. The discovery threshold maximizes TPR subject to FPR <= 0.05 (ties: lower FPR, then higher threshold). This is not a guarantee on heldout FPR. The other seven fixed conditions and balanced-accuracy threshold policy are diagnostic comparisons, not post-hoc model selection.

| Family | Split | Oracle inputs | Source proof |
|---|---|---:|---|
| unsigned_distance | discovery | 1051 | Ordering selects max-min, in [0,2^32-1]. |
| gray_encoding | discovery | 1051 | Each output bit is input bit i xor bit i+1; bit32 is zero. |
| median_three | validation | 1051 | Three compare-exchanges sort; nested inequalities select middle order statistic including ties. |
| byte_reversal | validation | 1051 | Disjoint byte masks map byte i to position 3-i; iterative assembly gives same permutation. |
| morton_interleave | heldout | 1051 | Successive disjoint masks spread low16 bits into even positions; y occupies odd positions. Higher input bits are ignored. |
| unsigned_average | heldout | 1051 | x+y=2*(x&y)+(x^y); quotient/remainder decomposition also yields floor((x+y)/2) without 32-bit overflow. |

Each family has subject, subject_equivalent and foil. The foil flips bit0 of the original result, with a recorded negative witness. Domain: all 32-bit unsigned x/y/z, no OS input. Independent Python formula checks support the algebraic source proofs; compiled targets are never executed. Exact source/build hashes, compiler versions and full compile commands are in manifest.json. GCC O0/O2 and MSVC O0 yield 18 builds / 54 routine cases.

All same-split, cross-build pairs are evaluated: 135 per split, 405 total, with 30 positives and 105 negatives per split. Same-family confusion is separately reported so cross-family negatives cannot hide difficult errors. Cases are correlated by source and compiler; there are only two families per split. No significance/population-generalization claim is justified.

Runtime projects, repeated comparisons and fingerprints are under ignored runtime/. The versioned result is results.json. Reproduction requires the recorded compiler/Ghidra toolchain and executable bytes. Never overwrite method, manifest or result history; a modified method requires a new study. Actual execution outcome belongs to docs/semantic-flow/FINAL_REPORT.md.

```powershell
python scripts/run_semantic_benchmark.py register-method --study datasets/osgf_semantic_benchmark_v0_1 --engine rust_engine/operational/target/debug/osgf_operational.exe
python scripts/create_semantic_benchmark.py --study datasets/osgf_semantic_benchmark_v0_1
python scripts/build_value_flow_corpus.py --study-dir datasets/osgf_semantic_benchmark_v0_1
python scripts/run_semantic_benchmark.py run --study datasets/osgf_semantic_benchmark_v0_1 --engine rust_engine/operational/target/debug/osgf_operational.exe --ghidra 'C:\Users\aless\Desktop\_\Projects\ghidra_12.0.4_PUBLIC' --python 'C:\Users\aless\AppData\Roaming\ghidra\ghidra_12.0.4_PUBLIC\venv\Scripts\python.exe' --java-home 'C:\Program Files\Eclipse Adoptium\jdk-25.0.2.10-hotspot'
```

These paths are now registered; the commands intentionally refuse overwriting existing method/source/evaluation directories. Use a separate study directory and document a new registration when repeating a build/evaluation. The exact scored implementation hashes must match.

## Completed result — 2026-11-10

405/405 repeated comparisons passed determinism. Primary combined heldout: 6 TP, 24 FN, 0 FP, 105 TN; identical classification to multilevel. Effects/algebra: 8 TP, 2 FP. Families: 12 TP, 6 FP. No condition recovered the 12 heldout positive pairs between different equivalent implementations. The desired near-maximal recall was not achieved; no promotion or heldout tuning. Full results and limitations: docs/semantic-flow/FINAL_REPORT.md.
