# Deterministic case studies

Condition B; sorted by score then pair ID, no favorable-case selection. All 436 A/B entries remain in FAILURE_CATALOG.json. Stored independent behavioral witnesses are not claimed as freshly executed binary tests.

## highest false matches: pair:1111ce3850555321293ef20a

Split discovery_train; label non_equivalent; routines ['sum_array', 'count_matches']; score 1.0. Builds: numeric-gcc-O0 / numeric-gcc-O0.

Independent ground truth: `{"case": 1, "evidence": "Different pure reductions/search predicates on the identical input; recorded outputs witness non-equivalence.", "input_bytes": [13, 30, 47, 64, 81, 98, 115], "label": "non_equivalent", "left_result": 448, "method": "behavior_counterexample", "right_result": 0}`.

| View | Set | Multiset | Intersection / union multiplicity |
|---|---:|---:|---:|
| rooted_topology | 1.0 | 1.0 | 3 / 3 |
| typed_evidence | None | None | 0 / 0 |
| interaction_motif | None | None | 0 / 0 |

Source-bearing evidence:
- `graph:6ff68b280145bdaab2fc192b`: `datasets/osgf_pairs_v0_1/graphs/graph_6ff68b280145bdaab2fc192b.json` SHA-256 `0b7708a92ac26ea8c6b24b87d213c1c928c127b947095b4ae96f5bb97b1e97af`; source `samples/controlled/source/numeric.c`, routine `sum_array`; local node kinds `{'FUNCTION': 1}`.
- `graph:e4935848a6d0deab8dd9c53d`: `datasets/osgf_pairs_v0_1/graphs/graph_e4935848a6d0deab8dd9c53d.json` SHA-256 `ccc5c3e362df359f226f95a8f6ce0341609839be6852067905c6231acbacc578`; source `samples/controlled/source/numeric.c`, routine `count_matches`; local node kinds `{'FUNCTION': 1}`.

Confirmed representation-indistinguishable: every view has equal descriptor counts. Empty views supply no semantic evidence; matching generic roles/distances cannot distinguish the recorded behavior. Arithmetic failure is excluded by the independent oracle. Exact earliest extraction loss is supported by exporter/schema inspection; fresh binary reconstruction was not completed.

Warnings: `["query: indirect_calls observation unavailable; not interpreted as zero", "query: unresolved_indirect_calls observation unavailable; not interpreted as zero", "query: explicit_dynamic_dispatch observation unavailable; not interpreted as zero", "reference: indirect_calls observation unavailable; not interpreted as zero", "reference: unresolved_indirect_calls observation unavailable; not interpreted as zero", "reference: explicit_dynamic_dispatch observation unavailable; not interpreted as zero"]`.

Exact matched, left-only, right-only and count-difference descriptor arrays, complete source references and source-bearing SimilarityResult artifact hashes are retained in FAILURE_CATALOG.json under this pair ID.

## highest false matches: pair:11da606b1cea94fb33958b0b

Split discovery_train; label non_equivalent; routines ['find_max', 'count_matches']; score 1.0. Builds: numeric-gcc-O0 / numeric-gcc-O0.

Independent ground truth: `{"case": 1, "evidence": "Different pure reductions/search predicates on the identical input; recorded outputs witness non-equivalence.", "input_bytes": [13, 30, 47, 64, 81, 98, 115], "label": "non_equivalent", "left_result": 115, "method": "behavior_counterexample", "right_result": 0}`.

| View | Set | Multiset | Intersection / union multiplicity |
|---|---:|---:|---:|
| rooted_topology | 1.0 | 1.0 | 3 / 3 |
| typed_evidence | None | None | 0 / 0 |
| interaction_motif | None | None | 0 / 0 |

Source-bearing evidence:
- `graph:9f979d065fb55f6a7d87ac15`: `datasets/osgf_pairs_v0_1/graphs/graph_9f979d065fb55f6a7d87ac15.json` SHA-256 `39e78421adde61fe6733023235b4c61189ace5a49564a66a61cd4d7ccb6e14ba`; source `samples/controlled/source/numeric.c`, routine `find_max`; local node kinds `{'FUNCTION': 1}`.
- `graph:e4935848a6d0deab8dd9c53d`: `datasets/osgf_pairs_v0_1/graphs/graph_e4935848a6d0deab8dd9c53d.json` SHA-256 `ccc5c3e362df359f226f95a8f6ce0341609839be6852067905c6231acbacc578`; source `samples/controlled/source/numeric.c`, routine `count_matches`; local node kinds `{'FUNCTION': 1}`.

Confirmed representation-indistinguishable: every view has equal descriptor counts. Empty views supply no semantic evidence; matching generic roles/distances cannot distinguish the recorded behavior. Arithmetic failure is excluded by the independent oracle. Exact earliest extraction loss is supported by exporter/schema inspection; fresh binary reconstruction was not completed.

Warnings: `["query: indirect_calls observation unavailable; not interpreted as zero", "query: unresolved_indirect_calls observation unavailable; not interpreted as zero", "query: explicit_dynamic_dispatch observation unavailable; not interpreted as zero", "reference: indirect_calls observation unavailable; not interpreted as zero", "reference: unresolved_indirect_calls observation unavailable; not interpreted as zero", "reference: explicit_dynamic_dispatch observation unavailable; not interpreted as zero"]`.

Exact matched, left-only, right-only and count-difference descriptor arrays, complete source references and source-bearing SimilarityResult artifact hashes are retained in FAILURE_CATALOG.json under this pair ID.

## highest false matches: pair:1510de987f48e7682a0c2e5b

Split discovery_train; label non_equivalent; routines ['count_matches', 'sum_array']; score 1.0. Builds: numeric-gcc-O3 / numeric-gcc-O3.

Independent ground truth: `{"case": 1, "evidence": "Different pure reductions/search predicates on the identical input; recorded outputs witness non-equivalence.", "input_bytes": [13, 30, 47, 64, 81, 98, 115], "label": "non_equivalent", "left_result": 0, "method": "behavior_counterexample", "right_result": 448}`.

| View | Set | Multiset | Intersection / union multiplicity |
|---|---:|---:|---:|
| rooted_topology | 1.0 | 1.0 | 3 / 3 |
| typed_evidence | None | None | 0 / 0 |
| interaction_motif | None | None | 0 / 0 |

Source-bearing evidence:
- `graph:50ddc4bd6c3731e5e16271e7`: `datasets/osgf_pairs_v0_1/graphs/graph_50ddc4bd6c3731e5e16271e7.json` SHA-256 `eafaf08a2243de19f7fd944b3e6bfa2212482530f7d18551bf3095bd83c1d683`; source `samples/controlled/source/numeric.c`, routine `count_matches`; local node kinds `{'FUNCTION': 1}`.
- `graph:69473d48acf3964897468bc1`: `datasets/osgf_pairs_v0_1/graphs/graph_69473d48acf3964897468bc1.json` SHA-256 `da95d58566fa23ce69259b7c78266d163156d6561f0d8299fa3eb13deca2da20`; source `samples/controlled/source/numeric.c`, routine `sum_array`; local node kinds `{'FUNCTION': 1}`.

Confirmed representation-indistinguishable: every view has equal descriptor counts. Empty views supply no semantic evidence; matching generic roles/distances cannot distinguish the recorded behavior. Arithmetic failure is excluded by the independent oracle. Exact earliest extraction loss is supported by exporter/schema inspection; fresh binary reconstruction was not completed.

Warnings: `["query: indirect_calls observation unavailable; not interpreted as zero", "query: unresolved_indirect_calls observation unavailable; not interpreted as zero", "query: explicit_dynamic_dispatch observation unavailable; not interpreted as zero", "reference: indirect_calls observation unavailable; not interpreted as zero", "reference: unresolved_indirect_calls observation unavailable; not interpreted as zero", "reference: explicit_dynamic_dispatch observation unavailable; not interpreted as zero"]`.

Exact matched, left-only, right-only and count-difference descriptor arrays, complete source references and source-bearing SimilarityResult artifact hashes are retained in FAILURE_CATALOG.json under this pair ID.

## highest false matches: pair:25d0069a84bb89c4392ce742

Split held_out_test; label non_equivalent; routines ['search_string', 'count_letters']; score 1.0. Builds: text-msvc-O0 / text-msvc-O0.

Independent ground truth: `{"case": 1, "evidence": "Different pure reductions/search predicates on the identical input; recorded outputs witness non-equivalence.", "input_bytes": [13, 30, 47, 64, 81, 98, 115], "label": "non_equivalent", "left_result": 0, "method": "behavior_counterexample", "right_result": 1}`.

| View | Set | Multiset | Intersection / union multiplicity |
|---|---:|---:|---:|
| rooted_topology | 1.0 | 1.0 | 3 / 3 |
| typed_evidence | None | None | 0 / 0 |
| interaction_motif | None | None | 0 / 0 |

Source-bearing evidence:
- `graph:6af1521b07a0e6eef1d5b1c9`: `datasets/osgf_pairs_v0_1/graphs/graph_6af1521b07a0e6eef1d5b1c9.json` SHA-256 `223d8cd0ef6c8d2ec6039256cf29dec05b5c367e36e8ce11870a8d621b0d061b`; source `samples/controlled/source/text.c`, routine `search_string`; local node kinds `{'FUNCTION': 1}`.
- `graph:8a3b2f2040165f1694ff6dcb`: `datasets/osgf_pairs_v0_1/graphs/graph_8a3b2f2040165f1694ff6dcb.json` SHA-256 `f60732a93c4fbec32384eafbed86fada5b4cf367e18a33264f45f2807dbd19d7`; source `samples/controlled/source/text.c`, routine `count_letters`; local node kinds `{'FUNCTION': 1}`.

Confirmed representation-indistinguishable: every view has equal descriptor counts. Empty views supply no semantic evidence; matching generic roles/distances cannot distinguish the recorded behavior. Arithmetic failure is excluded by the independent oracle. Exact earliest extraction loss is supported by exporter/schema inspection; fresh binary reconstruction was not completed.

Warnings: `["query: indirect_calls observation unavailable; not interpreted as zero", "query: unresolved_indirect_calls observation unavailable; not interpreted as zero", "query: explicit_dynamic_dispatch observation unavailable; not interpreted as zero", "reference: indirect_calls observation unavailable; not interpreted as zero", "reference: unresolved_indirect_calls observation unavailable; not interpreted as zero", "reference: explicit_dynamic_dispatch observation unavailable; not interpreted as zero"]`.

Exact matched, left-only, right-only and count-difference descriptor arrays, complete source references and source-bearing SimilarityResult artifact hashes are retained in FAILURE_CATALOG.json under this pair ID.

## highest false matches: pair:2cc388e58e5248b47a12eb29

Split held_out_test; label non_equivalent; routines ['count_digits', 'count_letters']; score 1.0. Builds: text-gcc-O3 / text-gcc-O3.

Independent ground truth: `{"case": 1, "evidence": "Different pure reductions/search predicates on the identical input; recorded outputs witness non-equivalence.", "input_bytes": [13, 30, 47, 64, 81, 98, 115], "label": "non_equivalent", "left_result": 0, "method": "behavior_counterexample", "right_result": 1}`.

| View | Set | Multiset | Intersection / union multiplicity |
|---|---:|---:|---:|
| rooted_topology | 1.0 | 1.0 | 3 / 3 |
| typed_evidence | None | None | 0 / 0 |
| interaction_motif | None | None | 0 / 0 |

Source-bearing evidence:
- `graph:5b3f7f95c182e005704204bf`: `datasets/osgf_pairs_v0_1/graphs/graph_5b3f7f95c182e005704204bf.json` SHA-256 `16cc5e9dd45059674ae6412684ed83eaf8baeb6dcc1641d9ccff3103736826f4`; source `samples/controlled/source/text.c`, routine `count_digits`; local node kinds `{'FUNCTION': 1}`.
- `graph:76a3e581b253a744b5e4a495`: `datasets/osgf_pairs_v0_1/graphs/graph_76a3e581b253a744b5e4a495.json` SHA-256 `fc22002cace8b6142a31115404e6b1c0ce8dffa5f3414b43d5ee37c7ae575cb9`; source `samples/controlled/source/text.c`, routine `count_letters`; local node kinds `{'FUNCTION': 1}`.

Confirmed representation-indistinguishable: every view has equal descriptor counts. Empty views supply no semantic evidence; matching generic roles/distances cannot distinguish the recorded behavior. Arithmetic failure is excluded by the independent oracle. Exact earliest extraction loss is supported by exporter/schema inspection; fresh binary reconstruction was not completed.

Warnings: `["query: indirect_calls observation unavailable; not interpreted as zero", "query: unresolved_indirect_calls observation unavailable; not interpreted as zero", "query: explicit_dynamic_dispatch observation unavailable; not interpreted as zero", "reference: indirect_calls observation unavailable; not interpreted as zero", "reference: unresolved_indirect_calls observation unavailable; not interpreted as zero", "reference: explicit_dynamic_dispatch observation unavailable; not interpreted as zero"]`.

Exact matched, left-only, right-only and count-difference descriptor arrays, complete source references and source-bearing SimilarityResult artifact hashes are retained in FAILURE_CATALOG.json under this pair ID.

## lowest equivalent: pair:116f9b94ff3137f41fe0e872

Split discovery_train; label equivalent; routines ['copy_buffer', 'copy_buffer']; score 0.1111111111111111. Builds: memory-gcc-O2 / memory-msvc-O2.

Independent ground truth: `{"evidence": "Same controlled source artifact and routine body, distinct compiler configuration; build transcripts independently checked.", "label": "equivalent", "method": "same_controlled_source", "routine_body_sha256": "351b689b36d3f7f78364ac3b1e20d6b18ef15900c3e4bf503bfc420eaf1482e6", "source_hash": "efb4da1bba3c842cb77875670e4101ca21c7e775d6f578d8501af944455bac0d"}`.

| View | Set | Multiset | Intersection / union multiplicity |
|---|---:|---:|---:|
| rooted_topology | 0.5 | 0.3333333333333333 | 6 / 18 |
| typed_evidence | 0.0 | 0.0 | 0 / 5 |
| interaction_motif | 0.0 | 0.0 | 0 / 5 |

Source-bearing evidence:
- `graph:d7e7cd037d233de6cebaf4a0`: `datasets/osgf_pairs_v0_1/graphs/graph_d7e7cd037d233de6cebaf4a0.json` SHA-256 `e09c6625618e1301b953ebe5eba92906fa554191da141b85cf868ce984bd6d52`; source `samples/controlled/source/memory.c`, routine `copy_buffer`; local node kinds `{'FUNCTION': 2}`.
- `graph:f7ff29a34cb7913c325851da`: `datasets/osgf_pairs_v0_1/graphs/graph_f7ff29a34cb7913c325851da.json` SHA-256 `1ba52df55142469ae8f961596cdf7c3ea49205ec27462e5071f9accebca09150`; source `samples/controlled/source/memory.c`, routine `copy_buffer`; local node kinds `{'API': 5, 'FUNCTION': 5, 'VISIBILITY_INDICATOR': 2}`.

Observed feature/context mismatch despite independent equivalence label. Exact function roles/distances and helper-attached evidence differ. Runtime/helper sensitivity is supported by the descriptors, but compiler optimization causality is not established merely from graph absence. Inspect full count_differences in FAILURE_CATALOG.json; no label is changed.

Warnings: `["query: indirect_calls observation unavailable; not interpreted as zero", "query: unresolved_indirect_calls observation unavailable; not interpreted as zero", "query: explicit_dynamic_dispatch observation unavailable; not interpreted as zero", "reference: unresolved calls; targets remain unknown", "reference: unresolved indirect calls; may overlap unresolved-call records"]`.

Exact matched, left-only, right-only and count-difference descriptor arrays, complete source references and source-bearing SimilarityResult artifact hashes are retained in FAILURE_CATALOG.json under this pair ID.

## lowest equivalent: pair:39a5fca045a8fe658c916bf3

Split discovery_train; label equivalent; routines ['copy_buffer', 'copy_buffer']; score 0.1111111111111111. Builds: memory-gcc-O0 / memory-msvc-O2.

Independent ground truth: `{"evidence": "Same controlled source artifact and routine body, distinct compiler configuration; build transcripts independently checked.", "label": "equivalent", "method": "same_controlled_source", "routine_body_sha256": "351b689b36d3f7f78364ac3b1e20d6b18ef15900c3e4bf503bfc420eaf1482e6", "source_hash": "efb4da1bba3c842cb77875670e4101ca21c7e775d6f578d8501af944455bac0d"}`.

| View | Set | Multiset | Intersection / union multiplicity |
|---|---:|---:|---:|
| rooted_topology | 0.5 | 0.3333333333333333 | 6 / 18 |
| typed_evidence | 0.0 | 0.0 | 0 / 5 |
| interaction_motif | 0.0 | 0.0 | 0 / 5 |

Source-bearing evidence:
- `graph:378d5c42136eb4c6a7689c46`: `datasets/osgf_pairs_v0_1/graphs/graph_378d5c42136eb4c6a7689c46.json` SHA-256 `b5feef14fed744ebd637b89429a4df968396de56604952f30b8e2880137f7389`; source `samples/controlled/source/memory.c`, routine `copy_buffer`; local node kinds `{'FUNCTION': 2}`.
- `graph:f7ff29a34cb7913c325851da`: `datasets/osgf_pairs_v0_1/graphs/graph_f7ff29a34cb7913c325851da.json` SHA-256 `1ba52df55142469ae8f961596cdf7c3ea49205ec27462e5071f9accebca09150`; source `samples/controlled/source/memory.c`, routine `copy_buffer`; local node kinds `{'API': 5, 'FUNCTION': 5, 'VISIBILITY_INDICATOR': 2}`.

Observed feature/context mismatch despite independent equivalence label. Exact function roles/distances and helper-attached evidence differ. Runtime/helper sensitivity is supported by the descriptors, but compiler optimization causality is not established merely from graph absence. Inspect full count_differences in FAILURE_CATALOG.json; no label is changed.

Warnings: `["query: indirect_calls observation unavailable; not interpreted as zero", "query: unresolved_indirect_calls observation unavailable; not interpreted as zero", "query: explicit_dynamic_dispatch observation unavailable; not interpreted as zero", "reference: unresolved calls; targets remain unknown", "reference: unresolved indirect calls; may overlap unresolved-call records"]`.

Exact matched, left-only, right-only and count-difference descriptor arrays, complete source references and source-bearing SimilarityResult artifact hashes are retained in FAILURE_CATALOG.json under this pair ID.

## lowest equivalent: pair:4cbba235388402ac0156a330

Split discovery_train; label equivalent; routines ['copy_buffer', 'copy_buffer']; score 0.1111111111111111. Builds: memory-gcc-O3 / memory-msvc-O2.

Independent ground truth: `{"evidence": "Same controlled source artifact and routine body, distinct compiler configuration; build transcripts independently checked.", "label": "equivalent", "method": "same_controlled_source", "routine_body_sha256": "351b689b36d3f7f78364ac3b1e20d6b18ef15900c3e4bf503bfc420eaf1482e6", "source_hash": "efb4da1bba3c842cb77875670e4101ca21c7e775d6f578d8501af944455bac0d"}`.

| View | Set | Multiset | Intersection / union multiplicity |
|---|---:|---:|---:|
| rooted_topology | 0.5 | 0.3333333333333333 | 6 / 18 |
| typed_evidence | 0.0 | 0.0 | 0 / 5 |
| interaction_motif | 0.0 | 0.0 | 0 / 5 |

Source-bearing evidence:
- `graph:c2ce95fed5a318c82acd9ceb`: `datasets/osgf_pairs_v0_1/graphs/graph_c2ce95fed5a318c82acd9ceb.json` SHA-256 `e09c6625618e1301b953ebe5eba92906fa554191da141b85cf868ce984bd6d52`; source `samples/controlled/source/memory.c`, routine `copy_buffer`; local node kinds `{'FUNCTION': 2}`.
- `graph:f7ff29a34cb7913c325851da`: `datasets/osgf_pairs_v0_1/graphs/graph_f7ff29a34cb7913c325851da.json` SHA-256 `1ba52df55142469ae8f961596cdf7c3ea49205ec27462e5071f9accebca09150`; source `samples/controlled/source/memory.c`, routine `copy_buffer`; local node kinds `{'API': 5, 'FUNCTION': 5, 'VISIBILITY_INDICATOR': 2}`.

Observed feature/context mismatch despite independent equivalence label. Exact function roles/distances and helper-attached evidence differ. Runtime/helper sensitivity is supported by the descriptors, but compiler optimization causality is not established merely from graph absence. Inspect full count_differences in FAILURE_CATALOG.json; no label is changed.

Warnings: `["query: indirect_calls observation unavailable; not interpreted as zero", "query: unresolved_indirect_calls observation unavailable; not interpreted as zero", "query: explicit_dynamic_dispatch observation unavailable; not interpreted as zero", "reference: unresolved calls; targets remain unknown", "reference: unresolved indirect calls; may overlap unresolved-call records"]`.

Exact matched, left-only, right-only and count-difference descriptor arrays, complete source references and source-bearing SimilarityResult artifact hashes are retained in FAILURE_CATALOG.json under this pair ID.

## lowest equivalent: pair:5610e91a0cfb19bbbe47e459

Split discovery_train; label equivalent; routines ['copy_buffer', 'copy_buffer']; score 0.11764705882352942. Builds: memory-msvc-O0 / memory-gcc-O3.

Independent ground truth: `{"evidence": "Same controlled source artifact and routine body, distinct compiler configuration; build transcripts independently checked.", "label": "equivalent", "method": "same_controlled_source", "routine_body_sha256": "351b689b36d3f7f78364ac3b1e20d6b18ef15900c3e4bf503bfc420eaf1482e6", "source_hash": "efb4da1bba3c842cb77875670e4101ca21c7e775d6f578d8501af944455bac0d"}`.

| View | Set | Multiset | Intersection / union multiplicity |
|---|---:|---:|---:|
| rooted_topology | 0.5 | 0.35294117647058826 | 6 / 17 |
| typed_evidence | 0.0 | 0.0 | 0 / 5 |
| interaction_motif | 0.0 | 0.0 | 0 / 5 |

Source-bearing evidence:
- `graph:85c723d9a2dc49689deba0c5`: `datasets/osgf_pairs_v0_1/graphs/graph_85c723d9a2dc49689deba0c5.json` SHA-256 `1d7d356d2e7b32e2f6cbe78e955394bc324e630471b0ef0c92204e6d5f3ff03c`; source `samples/controlled/source/memory.c`, routine `copy_buffer`; local node kinds `{'API': 5, 'FUNCTION': 5, 'VISIBILITY_INDICATOR': 2}`.
- `graph:c2ce95fed5a318c82acd9ceb`: `datasets/osgf_pairs_v0_1/graphs/graph_c2ce95fed5a318c82acd9ceb.json` SHA-256 `e09c6625618e1301b953ebe5eba92906fa554191da141b85cf868ce984bd6d52`; source `samples/controlled/source/memory.c`, routine `copy_buffer`; local node kinds `{'FUNCTION': 2}`.

Observed feature/context mismatch despite independent equivalence label. Exact function roles/distances and helper-attached evidence differ. Runtime/helper sensitivity is supported by the descriptors, but compiler optimization causality is not established merely from graph absence. Inspect full count_differences in FAILURE_CATALOG.json; no label is changed.

Warnings: `["query: unresolved calls; targets remain unknown", "query: unresolved indirect calls; may overlap unresolved-call records", "reference: indirect_calls observation unavailable; not interpreted as zero", "reference: unresolved_indirect_calls observation unavailable; not interpreted as zero", "reference: explicit_dynamic_dispatch observation unavailable; not interpreted as zero"]`.

Exact matched, left-only, right-only and count-difference descriptor arrays, complete source references and source-bearing SimilarityResult artifact hashes are retained in FAILURE_CATALOG.json under this pair ID.

## lowest equivalent: pair:6dd1cdf57e3f1b10578f7809

Split discovery_train; label equivalent; routines ['copy_buffer', 'copy_buffer']; score 0.11764705882352942. Builds: memory-msvc-O0 / memory-gcc-O2.

Independent ground truth: `{"evidence": "Same controlled source artifact and routine body, distinct compiler configuration; build transcripts independently checked.", "label": "equivalent", "method": "same_controlled_source", "routine_body_sha256": "351b689b36d3f7f78364ac3b1e20d6b18ef15900c3e4bf503bfc420eaf1482e6", "source_hash": "efb4da1bba3c842cb77875670e4101ca21c7e775d6f578d8501af944455bac0d"}`.

| View | Set | Multiset | Intersection / union multiplicity |
|---|---:|---:|---:|
| rooted_topology | 0.5 | 0.35294117647058826 | 6 / 17 |
| typed_evidence | 0.0 | 0.0 | 0 / 5 |
| interaction_motif | 0.0 | 0.0 | 0 / 5 |

Source-bearing evidence:
- `graph:85c723d9a2dc49689deba0c5`: `datasets/osgf_pairs_v0_1/graphs/graph_85c723d9a2dc49689deba0c5.json` SHA-256 `1d7d356d2e7b32e2f6cbe78e955394bc324e630471b0ef0c92204e6d5f3ff03c`; source `samples/controlled/source/memory.c`, routine `copy_buffer`; local node kinds `{'API': 5, 'FUNCTION': 5, 'VISIBILITY_INDICATOR': 2}`.
- `graph:d7e7cd037d233de6cebaf4a0`: `datasets/osgf_pairs_v0_1/graphs/graph_d7e7cd037d233de6cebaf4a0.json` SHA-256 `e09c6625618e1301b953ebe5eba92906fa554191da141b85cf868ce984bd6d52`; source `samples/controlled/source/memory.c`, routine `copy_buffer`; local node kinds `{'FUNCTION': 2}`.

Observed feature/context mismatch despite independent equivalence label. Exact function roles/distances and helper-attached evidence differ. Runtime/helper sensitivity is supported by the descriptors, but compiler optimization causality is not established merely from graph absence. Inspect full count_differences in FAILURE_CATALOG.json; no label is changed.

Warnings: `["query: unresolved calls; targets remain unknown", "query: unresolved indirect calls; may overlap unresolved-call records", "reference: indirect_calls observation unavailable; not interpreted as zero", "reference: unresolved_indirect_calls observation unavailable; not interpreted as zero", "reference: explicit_dynamic_dispatch observation unavailable; not interpreted as zero"]`.

Exact matched, left-only, right-only and count-difference descriptor arrays, complete source references and source-bearing SimilarityResult artifact hashes are retained in FAILURE_CATALOG.json under this pair ID.

## strong true positive: pair:05d513202e5e89e0409ce047

Split discovery_train; label equivalent; routines ['xor_buffer', 'xor_buffer']; score 1.0. Builds: memory-gcc-O2 / memory-gcc-O3.

Independent ground truth: `{"evidence": "Same controlled source artifact and routine body, distinct compiler configuration; build transcripts independently checked.", "label": "equivalent", "method": "same_controlled_source", "routine_body_sha256": "62cd4fc304dcf7800aae41f937509264e5d168a31c4e78bf713adc31b54f9e23", "source_hash": "efb4da1bba3c842cb77875670e4101ca21c7e775d6f578d8501af944455bac0d"}`.

| View | Set | Multiset | Intersection / union multiplicity |
|---|---:|---:|---:|
| rooted_topology | 1.0 | 1.0 | 3 / 3 |
| typed_evidence | None | None | 0 / 0 |
| interaction_motif | None | None | 0 / 0 |

Source-bearing evidence:
- `graph:80c5e52d69eb6096e1c1364b`: `datasets/osgf_pairs_v0_1/graphs/graph_80c5e52d69eb6096e1c1364b.json` SHA-256 `1619e794772abc8927fca78c99a9b3d3f43b612fce5696b9180b610ed47ea902`; source `samples/controlled/source/memory.c`, routine `xor_buffer`; local node kinds `{'FUNCTION': 1}`.
- `graph:b73eb2288fb2b140585aba8d`: `datasets/osgf_pairs_v0_1/graphs/graph_b73eb2288fb2b140585aba8d.json` SHA-256 `1619e794772abc8927fca78c99a9b3d3f43b612fce5696b9180b610ed47ea902`; source `samples/controlled/source/memory.c`, routine `xor_buffer`; local node kinds `{'FUNCTION': 1}`.

Agreement on the observed descriptors supports this comparison, not exhaustive semantic equivalence. Ground truth remains independent. Missing observability and narrow corpus coverage prevent extrapolation to arbitrary binaries.

Warnings: `["query: indirect_calls observation unavailable; not interpreted as zero", "query: unresolved_indirect_calls observation unavailable; not interpreted as zero", "query: explicit_dynamic_dispatch observation unavailable; not interpreted as zero", "reference: indirect_calls observation unavailable; not interpreted as zero", "reference: unresolved_indirect_calls observation unavailable; not interpreted as zero", "reference: explicit_dynamic_dispatch observation unavailable; not interpreted as zero"]`.

Exact matched, left-only, right-only and count-difference descriptor arrays, complete source references and source-bearing SimilarityResult artifact hashes are retained in FAILURE_CATALOG.json under this pair ID.

## incomplete observability: pair:05d513202e5e89e0409ce047

Split discovery_train; label equivalent; routines ['xor_buffer', 'xor_buffer']; score 1.0. Builds: memory-gcc-O2 / memory-gcc-O3.

Independent ground truth: `{"evidence": "Same controlled source artifact and routine body, distinct compiler configuration; build transcripts independently checked.", "label": "equivalent", "method": "same_controlled_source", "routine_body_sha256": "62cd4fc304dcf7800aae41f937509264e5d168a31c4e78bf713adc31b54f9e23", "source_hash": "efb4da1bba3c842cb77875670e4101ca21c7e775d6f578d8501af944455bac0d"}`.

| View | Set | Multiset | Intersection / union multiplicity |
|---|---:|---:|---:|
| rooted_topology | 1.0 | 1.0 | 3 / 3 |
| typed_evidence | None | None | 0 / 0 |
| interaction_motif | None | None | 0 / 0 |

Source-bearing evidence:
- `graph:80c5e52d69eb6096e1c1364b`: `datasets/osgf_pairs_v0_1/graphs/graph_80c5e52d69eb6096e1c1364b.json` SHA-256 `1619e794772abc8927fca78c99a9b3d3f43b612fce5696b9180b610ed47ea902`; source `samples/controlled/source/memory.c`, routine `xor_buffer`; local node kinds `{'FUNCTION': 1}`.
- `graph:b73eb2288fb2b140585aba8d`: `datasets/osgf_pairs_v0_1/graphs/graph_b73eb2288fb2b140585aba8d.json` SHA-256 `1619e794772abc8927fca78c99a9b3d3f43b612fce5696b9180b610ed47ea902`; source `samples/controlled/source/memory.c`, routine `xor_buffer`; local node kinds `{'FUNCTION': 1}`.

Agreement on the observed descriptors supports this comparison, not exhaustive semantic equivalence. Ground truth remains independent. Missing observability and narrow corpus coverage prevent extrapolation to arbitrary binaries.

Warnings: `["query: indirect_calls observation unavailable; not interpreted as zero", "query: unresolved_indirect_calls observation unavailable; not interpreted as zero", "query: explicit_dynamic_dispatch observation unavailable; not interpreted as zero", "reference: indirect_calls observation unavailable; not interpreted as zero", "reference: unresolved_indirect_calls observation unavailable; not interpreted as zero", "reference: explicit_dynamic_dispatch observation unavailable; not interpreted as zero"]`.

Exact matched, left-only, right-only and count-difference descriptor arrays, complete source references and source-bearing SimilarityResult artifact hashes are retained in FAILURE_CATALOG.json under this pair ID.

## cross compiler: pair:116f9b94ff3137f41fe0e872

Split discovery_train; label equivalent; routines ['copy_buffer', 'copy_buffer']; score 0.1111111111111111. Builds: memory-gcc-O2 / memory-msvc-O2.

Independent ground truth: `{"evidence": "Same controlled source artifact and routine body, distinct compiler configuration; build transcripts independently checked.", "label": "equivalent", "method": "same_controlled_source", "routine_body_sha256": "351b689b36d3f7f78364ac3b1e20d6b18ef15900c3e4bf503bfc420eaf1482e6", "source_hash": "efb4da1bba3c842cb77875670e4101ca21c7e775d6f578d8501af944455bac0d"}`.

| View | Set | Multiset | Intersection / union multiplicity |
|---|---:|---:|---:|
| rooted_topology | 0.5 | 0.3333333333333333 | 6 / 18 |
| typed_evidence | 0.0 | 0.0 | 0 / 5 |
| interaction_motif | 0.0 | 0.0 | 0 / 5 |

Source-bearing evidence:
- `graph:d7e7cd037d233de6cebaf4a0`: `datasets/osgf_pairs_v0_1/graphs/graph_d7e7cd037d233de6cebaf4a0.json` SHA-256 `e09c6625618e1301b953ebe5eba92906fa554191da141b85cf868ce984bd6d52`; source `samples/controlled/source/memory.c`, routine `copy_buffer`; local node kinds `{'FUNCTION': 2}`.
- `graph:f7ff29a34cb7913c325851da`: `datasets/osgf_pairs_v0_1/graphs/graph_f7ff29a34cb7913c325851da.json` SHA-256 `1ba52df55142469ae8f961596cdf7c3ea49205ec27462e5071f9accebca09150`; source `samples/controlled/source/memory.c`, routine `copy_buffer`; local node kinds `{'API': 5, 'FUNCTION': 5, 'VISIBILITY_INDICATOR': 2}`.

Observed feature/context mismatch despite independent equivalence label. Exact function roles/distances and helper-attached evidence differ. Runtime/helper sensitivity is supported by the descriptors, but compiler optimization causality is not established merely from graph absence. Inspect full count_differences in FAILURE_CATALOG.json; no label is changed.

Warnings: `["query: indirect_calls observation unavailable; not interpreted as zero", "query: unresolved_indirect_calls observation unavailable; not interpreted as zero", "query: explicit_dynamic_dispatch observation unavailable; not interpreted as zero", "reference: unresolved calls; targets remain unknown", "reference: unresolved indirect calls; may overlap unresolved-call records"]`.

Exact matched, left-only, right-only and count-difference descriptor arrays, complete source references and source-bearing SimilarityResult artifact hashes are retained in FAILURE_CATALOG.json under this pair ID.

