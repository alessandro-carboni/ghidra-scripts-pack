# Step 10B.1 — Ghidra P-code extraction research

## Verified environment and sources

Installed application.properties identifies Ghidra 12.0.4 PUBLIC, revision e40ed13014025f82488b1f8f7bca566894ac376b, Java minimum/compiler 21. The installed SoftwareModeling-src.zip and Decompiler-src.zip were inspected directly. ghidra_api_evidence.json records source paths, exact source SHA-256 and presence checks for the APIs below. Online documentation is supporting reference, not proof that its rolling version equals the installation.

Official references consulted on 2026-11-03:

- https://ghidra.re/ghidra_docs/languages/html/pcoderef.html
- https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Instruction.html
- https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html
- https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/HighFunction.html

## Raw versus High

Raw P-code lifts machine instructions into register-transfer operations. It retains instruction-local operation order and storage/size information. Architectural bookkeeping and compiler lowering remain visible. Register reuse alone is not a global def-use identity; inter-instruction dataflow requires control-flow-aware analysis. A histogram is insufficient for the eventual operational evidence model.

High P-code is a decompiler-transformed representation. It may eliminate, propagate, merge or introduce analysis operations. MULTIEQUAL/INDIRECT and reconstructed expressions are analysis artifacts, not claims that a corresponding machine instruction executed. High-level structure depends on analysis settings, prototypes, simplification, language/compiler specs and Ghidra version. It is not interchangeable with raw operations. Def-use links describe the recovered model; they do not solve arbitrary aliasing, indirect calls or behavioral equivalence.

| Choice | Precision / information | Cross-compiler robustness | Reproduction and provenance | Overhead / failure |
|---|---|---|---|---|
| A: Raw only | Close to instruction semantics; opcodes, ordered operands, widths, storage and instruction mapping; no ready global SSA | May expose compiler/register/flag noise; not empirically established here | Strong local origin mapping; pin language, context and override policy | Lower expected overhead; unsupported lifting, no instructions and cancellation explicit |
| B: High only | Recovered SSA/def-use, blocks and simplified expressions; assumptions must be retained | Potentially reduces noise but optimizer/prototype differences can introduce instability | Sequence location is an analysis association, not necessarily one-to-one machine provenance | Decompiler startup/cache plus per-function analysis; timeout/crash/no HighFunction possible |
| C: Hybrid | Complementary views if kept separate; enables cross-checking but not automatic equivalence | Must evaluate rather than assume better robustness | Two origin levels, two coverage states and pinned settings; never concatenate or substitute silently | Highest cost and validation complexity; raw success cannot hide high failure |

## Decision

Start incrementally with **A, Raw P-code extraction research**, keeping an explicit path to optional High P-code later. This is a first evidence acquisition decision, not a claim that raw-only features solve the audit failures. Raw operations already expose candidate arithmetic/predicate distinctions missing from the current graph. First inspect their availability, source association, operand widths and instruction sequence before designing Step 10B.2.

High P-code is justified when the project requires recovered inter-instruction SSA def-use and block-level dependencies without implementing an equivalent analysis engine. Its reliability remains conditional on decompiler recovery. If added, treat it as a separately identified layer. A failed High extraction may leave valid Raw evidence available, but must retain High failure status; it must not be reported as a successful High result or compared as though both samples had the same layer.

## API and extraction lifecycle verified against installed sources

Raw: enumerate instructions in the selected function body and call Instruction.getPcode(). Inspect PcodeOp.getInputs(), getOutput() and getSeqnum(); the no-argument operation source is the intended initial policy. The override-aware overload is a distinct choice and must be recorded rather than silently enabled. Preserve instruction address and operation index, operand order, storage space and byte width. Constants and register/unique storage must not be confused. Do not infer full dataflow from equal raw varnode locations.

High: create DecompInterface, configure options and simplification explicitly, openProgram(program), and check its result. Use decompileFunction(function, boundedTimeoutSeconds, monitor). Check cancellation, isTimedOut(), decompileCompleted(), error message and a non-null getHighFunction() before reading operations. HighFunction inherits getPcodeOps() through PcodeSyntaxTree; it is not a method invented for this project. Varnode.getDef()/getDescendants() provide recovered def-use traversal; missing definitions can represent inputs and must not become invented operations. Dispose the interface in finally. Do not interpret an empty or failed extraction as a valid empty semantic view.

## Future provenance and failure requirements

Bind binary SHA, selected function identity/body, Ghidra revision, language/compiler specification, analysis/override/decompiler options and extraction layer. Keep original instruction references and high sequence references separate. A transformed operation's location is not proof of an original one-to-one instruction; mark that limitation. Raw and High availability, timeout, cancellation, unsupported operation/language, invalid output and explicit budget exhaustion must be separately observable. No broad exception handler with silent fallback.

Deterministic ordering must follow recorded instruction/operation order for Raw and a declared traversal for High. Address-based provenance is not a portable semantic key. Do not claim byte stability across Ghidra versions; re-extract under a new extraction identity and compare via independent tests. Pin versions/settings and test repeated identical inputs before accepting determinism. Keep durations and host paths outside scientific identity.

Cost expectation: Raw lifting is generally cheaper than decompilation, but no time/memory measurements were run in this research phase. Future measurement must separate startup, analysis, serialization, cache effects and function size, with bounded time/operation limits. No numerical overhead or accuracy claim is made.

## Required next-phase experiments, not executed here

Compare defined arithmetic and different predicate routines, compiler-equivalent implementations, wrappers, changed constants, unsupported semantics and controlled limits. Verify exact machine-to-Raw provenance and High-derived associations separately; include decompiler timeout/cancellation and repeated-run determinism. Use existing approved binaries or an approved isolated environment, not automatic execution of the previously flagged micro.exe. Test extraction without executing analyzed sample code. Fresh Ghidra extraction, computational benchmarks, cross-compiler superiority and a production operational schema are NOT RUN / NOT IMPLEMENTED in 10B.1.

Stop at chapter 4. Step 10B.2 operational evidence model, Rust integration, new fingerprints/scoring and LLM are outside this delivery.
