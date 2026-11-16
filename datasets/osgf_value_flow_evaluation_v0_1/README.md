# Optional High SSA value-flow study

Read [REPORT.md](REPORT.md) and [implementation rules](../../docs/step10c/IMPLEMENTATION.md). This is an additive study, not a modification of a previous freeze.

- `method_protocol.json`: normalization/evaluator and executable hashes fixed before new source authoring.
- `protocol.json`: original baseline evaluation configuration, extraction domain and pinned study driver.
- `manifest.json`: exact source/compiled bytes, compiler commands, source-derived labels and independent Python arithmetic checks.
- `results.json`: real-Ghidra A/B/C/D baseline results for the nine new builds.
- `value_protocol.json` / `value_results.json`: exact versus normalized versus fixed mean comparison.
- `development_protocol.json` / `development_results.json`: previously observed corpus, development-only.
- `runtime/`: local compiled targets, projects, full provenance, repeated artifacts and logs, intentionally not versioned.

Compilation, never target execution:

```powershell
python scripts/build_value_flow_corpus.py --study-dir datasets/osgf_value_flow_evaluation_v0_1
```

The full real-Ghidra command and all regression commands are in `docs/step10c/FINAL_REPORT.md`. Evaluators require new output directories and reject existing results, changed implementation/executable bytes or wrong input hashes. On another host, different compilers/OS/libraries can change PE or Rust executable bytes. Register a separate experiment rather than replacing these historical hashes. Current checked-in sources/metadata use explicit LF rules; compiled-source hashes refer to exact bytes.

To rerun extraction using the same local registered target binaries, copy the protocol, method_protocol and manifest into a new study directory, preserving their exact bytes, and choose a fresh --work directory under that study. Do not copy old result/value_protocol files. Manifest paths still refer to the verified original target binaries. For a different build/environment, create a separately documented manifest/protocol and retain these results.

Three new source families, one per discovery/validation/heldout split, do not establish population-wide generalization. Same-family variants are correlated; 81 pairs are not 81 independent families. No LLM, source-level parameter inference or memory-alias equivalence is implemented.
