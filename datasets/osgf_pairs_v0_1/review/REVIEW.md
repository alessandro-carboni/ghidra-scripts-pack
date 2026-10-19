# Step 8 — Manual ground-truth review

Status: pending human review. Automatic source proofs and runtime checks are supporting evidence, not human decisions.

For each pair inspect the named C routines, the contract and the witness/proof. Record accept, reject or ambiguous with reviewer, notes and reason in review_decisions.json. Do not accept merely because tests pass.

Contract: unsigned 32-bit result; 0 <= length <= 255; readable bytes followed by NUL. Pure reductions have no externally visible side effects. API negative functions use NUL-terminated input; baseline OS probes are host-state dependent.

## pair:05d513202e5e89e0409ce047

Coverage: optimization_variants. Proposed label: **equivalent**. Split: discovery_train.

- left: `xor_buffer` in `samples/controlled/source/memory.c`; gcc O2; graph `graph:80c5e52d69eb6096e1c1364b`.
- right: `xor_buffer` in `samples/controlled/source/memory.c`; gcc O3; graph `graph:b73eb2288fb2b140585aba8d`.

Evidence: Same controlled source artifact and routine body, distinct compiler configuration; build transcripts independently checked.

## pair:07cc392b51982eae31170a94

Coverage: harmless_strand. Proposed label: **equivalent**. Split: discovery_train.

- left: `xor_buffer__harmless_strand` in `samples/controlled/source/memory_variants.c`; gcc O0; graph `graph:15c76146b9e60ad12b0fd597`.
- right: `xor_buffer` in `samples/controlled/source/memory.c`; gcc O0; graph `graph:cc626d14f75b8e55bcebbde2`.

Evidence: Added pure unsigned-arithmetic helper reads no external state, writes no memory and its result is discarded.
Validation: 1,024 deterministic inputs covering every admitted length with four byte patterns. These are tests, not exhaustive enumeration of all byte strings; the source rationale is necessary.

## pair:08a67b5f71593b6810caf125

Coverage: cross_compiler_variants. Proposed label: **equivalent**. Split: validation.

- left: `read_file` in `samples/controlled/source/system_api.c`; msvc O0; graph `graph:1fffd8206ff02270366f0ef5`.
- right: `read_file` in `samples/controlled/source/system_api.c`; gcc O2; graph `graph:b5083d42018b58221e8b5f18`.

Evidence: Same controlled source artifact and routine body, distinct compiler configuration; build transcripts independently checked.

## pair:0df30c682fbf6df950146b14

Coverage: thunk. Proposed label: **equivalent**. Split: held_out_test.

- left: `interaction_socket_kind` in `samples/controlled/source/interaction_socket_kind.c`; msvc O0; graph `graph:add20e80b7f397b7e5a5a1bf`.
- right: `interaction_socket_kind__thunk` in `samples/controlled/source/interaction_socket_kind.c`; msvc O0; graph `graph:afbbbd0331774d830f5b1c03`.

Evidence: Fixed delegation invokes the original routine exactly once with identical arguments, return value, API effects and error handling; no additional OS operation.
Validation: 1,024 deterministic inputs covering every admitted length with four byte patterns. These are tests, not exhaustive enumeration of all byte strings; the source rationale is necessary.

## pair:1107ec8823f5fad30c4b336c

Coverage: hard_negatives. Proposed label: **non_equivalent**. Split: discovery_train.

- left: `weighted_buffer` in `samples/controlled/source/memory.c`; msvc O2; graph `graph:6f97cc580039993c6d95009d`.
- right: `copy_buffer` in `samples/controlled/source/memory.c`; msvc O2; graph `graph:f7ff29a34cb7913c325851da`.

Evidence: Different pure reductions/search predicates on the identical input; recorded outputs witness non-equivalence.
Input bytes: `[13, 30, 47, 64, 81, 98, 115]` (trailing NUL); results: left=2268, right=448.

## pair:150a989550f7c4251c21e5de

Coverage: transparent_wrapper. Proposed label: **equivalent**. Split: validation.

- left: `interaction_registry_summary__transparent_wrapper` in `samples/controlled/source/interaction_registry_summary.c`; msvc O0; graph `graph:515ac6b9562e4c96565cecab`.
- right: `interaction_registry_summary` in `samples/controlled/source/interaction_registry_summary.c`; msvc O0; graph `graph:e0b39088fd752beb6dbe465f`.

Evidence: Fixed delegation invokes the original routine exactly once with identical arguments, return value, API effects and error handling; no additional OS operation.
Validation: 1,024 deterministic inputs covering every admitted length with four byte patterns. These are tests, not exhaustive enumeration of all byte strings; the source rationale is necessary.

## pair:1e750c46cf950165a7b926c4

Coverage: linear_chain. Proposed label: **equivalent**. Split: validation.

- left: `interaction_registry_summary` in `samples/controlled/source/interaction_registry_summary.c`; msvc O2; graph `graph:2ecd38be52171c5f62c8c613`.
- right: `interaction_registry_summary__linear_chain` in `samples/controlled/source/interaction_registry_summary.c`; msvc O2; graph `graph:85fda6135a0812d4e38ef265`.

Evidence: Fixed delegation invokes the original routine exactly once with identical arguments, return value, API effects and error handling; no additional OS operation.
Validation: 1,024 deterministic inputs covering every admitted length with four byte patterns. These are tests, not exhaustive enumeration of all byte strings; the source rationale is necessary.

## pair:24e9f59cb1fc34954424c670

Coverage: dead_branch. Proposed label: **equivalent**. Split: discovery_train.

- left: `sum_array` in `samples/controlled/source/numeric.c`; gcc O0; graph `graph:6ff68b280145bdaab2fc192b`.
- right: `sum_array__dead_branch` in `samples/controlled/source/numeric_variants.c`; gcc O0; graph `graph:ae48e58a26e0e82dd3d93d57`.

Evidence: Branch n>255 is unreachable under the explicit 0<=n<=255 input contract; reachable execution delegates unchanged.
Validation: 1,024 deterministic inputs covering every admitted length with four byte patterns. These are tests, not exhaustive enumeration of all byte strings; the source rationale is necessary.

## pair:2bbcd0b314402aa2d3270877

Coverage: similar_api_different_structure. Proposed label: **non_equivalent**. Split: validation.

- left: `api_length_wrapped` in `samples/controlled/source/negative_api.c`; msvc O0; graph `graph:6e6140063c2c20b2ac93dccf`.
- right: `api_length` in `samples/controlled/source/negative_api.c`; msvc O0; graph `graph:8a2656f2e0b015b32fff4c59`.

Evidence: Both call lstrlenA; api_length_wrapped introduces a helper call and adds one to the result.
Input bytes: `[]` (trailing NUL); results: left=1, right=0.

## pair:4f62234f82e7de4579316522

Coverage: easy_negatives. Proposed label: **non_equivalent**. Split: validation.

- left: `api_length_plus_one` in `samples/controlled/source/negative_api.c`; msvc O0; graph `graph:41f60446d3b0a0e788a55306`.
- right: `api_compare` in `samples/controlled/source/negative_api.c`; msvc O0; graph `graph:bee6a52c200d8305d055d26d`.

Evidence: Length plus one versus string equality: different operation, API and string evidence.
Input bytes: `[]` (trailing NUL); results: left=1, right=0.

## pair:6034c2910327190dd52ca3b6

Coverage: similar_constants_different_behavior. Proposed label: **non_equivalent**. Split: validation.

- left: `api_compare_inverted` in `samples/controlled/source/negative_api.c`; msvc O0; graph `graph:24aa2b421f1c2e1a6dd65843`.
- right: `api_compare` in `samples/controlled/source/negative_api.c`; msvc O0; graph `graph:bee6a52c200d8305d055d26d`.

Evidence: Same AB literal and lstrcmpA call; opposite predicates.
Input bytes: `[]` (trailing NUL); results: left=1, right=0.

## pair:82f8042842e888a2fa036e1f

Coverage: function_splitting. Proposed label: **equivalent**. Split: discovery_train.

- left: `sum_array` in `samples/controlled/source/numeric.c`; gcc O0; graph `graph:6ff68b280145bdaab2fc192b`.
- right: `sum_array__function_splitting` in `samples/controlled/source/numeric_variants.c`; gcc O0; graph `graph:ffe5373515ca9c3ff7b75f25`.

Evidence: Partition bytes into two disjoint halves; combine associative sum/max/xor reductions with the original identity for empty input.
Validation: 1,024 deterministic inputs covering every admitted length with four byte patterns. These are tests, not exhaustive enumeration of all byte strings; the source rationale is necessary.

## pair:b7cad7998f41a4ac66177bb7

Coverage: benign_lookalike. Proposed label: **non_equivalent**. Split: validation.

- left: `api_length_plus_one` in `samples/controlled/source/negative_api.c`; msvc O0; graph `graph:41f60446d3b0a0e788a55306`.
- right: `api_length` in `samples/controlled/source/negative_api.c`; msvc O0; graph `graph:8a2656f2e0b015b32fff4c59`.

Evidence: Identical API call and arguments; one result is incremented.
Input bytes: `[]` (trailing NUL); results: left=1, right=0.

## pair:c9fdbde98c0b37f8be797d59

Coverage: similar_topology_different_evidence. Proposed label: **non_equivalent**. Split: validation.

- left: `api_length` in `samples/controlled/source/negative_api.c`; msvc O0; graph `graph:8a2656f2e0b015b32fff4c59`.
- right: `api_compare` in `samples/controlled/source/negative_api.c`; msvc O0; graph `graph:bee6a52c200d8305d055d26d`.

Evidence: Single API call topology; lstrlenA length versus lstrcmpA equality with literal AB.
Input bytes: `[13, 30, 47, 64, 81, 98, 115]` (trailing NUL); results: left=7, right=0.
