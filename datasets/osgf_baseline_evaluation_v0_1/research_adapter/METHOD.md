# Step 10.2 research design 0.1.0 — pending human comparability review

This implementation is a proposed experimental control, not an approval of the
study or its conclusions. It implements the preferred source-traceable adapter
from the supplied Step 10.2 instructions. No corpus pair scores, thresholds or
rankings have been calculated. The admission decision is still pending.

Both conditions consume the SAME extracted LocalSubgraphDocument; existing
canonical documents embed it. The upstream Ghidra extraction is already shared
preprocessing. This experiment cannot undo normalization performed upstream or
recover information absent from that snapshot. It must not be described as an
experiment on completely unprocessed machine code or on raw JSON byte similarity.

## Precisely disabled operations

| Fact or operation | A: no v0.1 semantic canonicalization | B: frozen v0.1 |
| --- | --- | --- |
| API value | Exact selected `name`, otherwise `normalized_name`, including whitespace/case/decorations | trim, ASCII lower-case, module/import/decoration normalization |
| Constant | Exact unsigned literal; source category and symbolic-name array in a tagged raw semantic object, null only if both absent | exact literal plus supported, source-confirmed memory-protection semantic mapping |
| Section | Same observed permission flags; tagged raw section name, including null when absent | same flags plus derived role; name excluded |
| Value-node identity | Preserve separate source API/constant/category occurrences | merge equal normalized API/constant/category facts |
| Edge context APIs | Exact raw values, sorted and exact-deduplicated | normalized values, sorted and deduplicated |
| Strings and categories | Exact text/category, already lossless in v0.1 | same |

Missing section name is NOT the literal string `unknown`. A validates the newly
interpreted raw section-name property as text when present; malformed values fail
explicitly. B's unchanged validity domain is broader here, which must be reported
as condition-specific unavailability rather than dropping the graph globally.
Constant literals are never replaced by their symbolic names. Unsupported aliases
remain visible in A, not inferred into a supported semantic class.

Shared preprocessing: typed/local validation, function role and caller/callee
distances, deterministic graph labeling and handles, source-array sorting,
ordering of known unordered property arrays, edge occurrence counts and site
checks, unknown unresolved targets, observability extraction and coverage.
Neither condition puts absolute addresses, original function names, similarity
labels or capability scores into semantic feature descriptors. Arbitrary raw
extensions remain provenance only; A does not mean every source property is a
feature. A/W and Nt/Zw API distinctions remain distinct in BOTH conditions.

## Reuse, integrity and fairness

`scripts/evaluation_adapter.py` creates a separate crate only inside ignored
`runtime/research_adapter/`. It verifies a pinned inventory of the 13 required
Rust modules and Cargo manifests/lock. Code text hashes explicitly use UTF-8 LF
for checkout portability; actual generated compilation bytes have a separate
`generated_sources.json` inventory. This is code identity, never a reinterpretation
of Step 8 compiled-source provenance. The frozen source files are read-only.

The generator checks that every surgical replacement applies exactly once.
Original Rust test modules are excluded from the generated crate because they
test the frozen contracts; the original 252 Rust tests are still run unchanged.
Research regressions invoke real research and frozen executables independently.
The exact feature-family and motif code is reused, including descriptor keys,
feature SHA construction, edge multiplicity vs structural motif multiplicity,
4096 default retention limits, 100000 maximum retention and one-million work
checks. The Jaccard/aggregate algorithm is reused unchanged; an independent Python
oracle also checks nontrivial synthetic comparisons.

Copied types are named ResearchGraph/ResearchFingerprint and use
`research-0.1.0`, never frozen canonical/fingerprint versions. ResearchGraph carries
A/B condition in its scientific identity. Revalidation rebuilds the graph from
its input and condition and checks complete equality; fingerprint/provenance
reconstruction remains mandatory. The bundle also embeds the exact UTF-8 input
text and SHA-256 and validates this binding. The frozen CLI rejects these research
graphs. A and B bundles cannot be mixed in a research comparison.

Research B is a parity witness, not a replacement for production condition B:
later corpus B must use the actual frozen CLI. B feature arrays, counts, feature
IDs, supports, source coverage, motif metadata and resolved origins match the
frozen executable exactly on the fixtures. Research wrapper versions/digests
necessarily differ and are never presented as byte-identical frozen artifacts.
No-op A/B parity is tested on inputs without section abstraction, symbolic
constant enrichment, API spelling normalization or merging; shared structural
roles and labeling remain explicit even in these no-op cases.

## Interpretation and residual confounds

This is a bundled semantic-normalization ablation, not isolated causal attribution
to a single API rule. Source labels/section names are lexical representations in A
and semantic abstractions in B; that representation change IS the intervention.
Do not align their feature hashes as though descriptors were identical. Later
cross-condition churn requires a documented mapping or must be unsupported.
Within-condition churn uses exact descriptors as preregistered.

Value merging can change support topology/IDs and descriptor ordering; therefore
lexicographic motif retention can retain different motifs at the SAME budget.
Both conditions report all truncation metadata; do not hide this by changing
budgets or filtering difficult cases. Paired scalar deltas require the same
comparable-view sets per the protocol. Equal-graph no-op parity is a necessary
implementation test, not empirical evidence of generalization or equivalence of
all A/B inputs. No full-corpus coverage or performance claim is made at this gate.

The scientific gate requested in the pasted protocol is: “STOP for human approval
at the A/B comparability gate”. Approval must cover this explicit definition and
its shared preprocessing before 10.3 materialization. Pending approval, 10.3–10.10
are NOT RUN and no final evaluation freeze or Step 11 is allowed.
