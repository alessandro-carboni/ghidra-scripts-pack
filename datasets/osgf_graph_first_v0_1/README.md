# Observable-seeded graph-first study v0.1

Prospective, internally authored, family-separated study. The six source families are registered in manifest.json; algorithm and A–E policies in protocol.json plus the preserved pre-evaluation technical amendment chain. Runtime binaries/projects/comparisons are deliberately ignored.

**Current status: BLOCKED before complete evaluation.** Eleven of eighteen builds are recorded. Bitdefender quarantined the twelfth before hashing; no heldout result or performance claim is available. The runner requires all eighteen builds and fails on a partial matrix. No target executable has been run.

PowerShell commands from repository root:

```powershell
python scripts/run_graph_first_study.py register --study datasets/osgf_graph_first_v0_1 --engine rust_engine/target/debug/rust_engine.exe --operational-engine rust_engine/operational/target/debug/osgf_operational.exe
python scripts/create_graph_first_study.py --study datasets/osgf_graph_first_v0_1
python scripts/build_value_flow_corpus.py --study-dir datasets/osgf_graph_first_v0_1
```

Registration/source creation were performed and intentionally refuse replacement. Build command records successful compilation bytes and refuses unregistered preexisting executable outputs. Resolve the quarantined build before resuming; preserve the failed attempt's log.

The complete evaluation command below is **prepared, not executed**:

```powershell
python scripts/run_graph_first_study.py run --study datasets/osgf_graph_first_v0_1 --engine rust_engine/target/debug/rust_engine.exe --operational-engine rust_engine/operational/target/debug/osgf_operational.exe --ghidra 'C:\Users\aless\Desktop\_\Projects\ghidra_12.0.4_PUBLIC' --python 'C:\Users\aless\AppData\Roaming\ghidra\ghidra_12.0.4_PUBLIC\venv\Scripts\python.exe' --java-home 'C:\Program Files\Eclipse Adoptium\jdk-25.0.2.10-hotspot'
```

Full limitations and actual findings: ../../docs/graph-first/SCIENTIFIC_COMPARISON.md. Results are not malware probabilities or equivalence proofs. All historical baselines and labels remain unchanged.
