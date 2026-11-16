# Step 10.0 validation record — 2026-10-21

Branch codex; starting HEAD c2fdcced4a19d583d72374a07bd0f5dfb1cda867; clean initial
working tree. The following checks are newly executed for Step 10.0, not copied
from the historical Step 8/9 acceptance reports. No empirical corpus scores.

Commands (PowerShell, repository root):

```powershell
python scripts/evaluation_preflight.py --write-audit
python scripts/evaluation_preflight.py --check
python -m pytest -q -s tests/test_evaluation_preflight.py
python scripts/step9_preflight.py --baseline datasets/osgf_transformations_v0_1/baseline.json
python scripts/transformation_harness.py report --run datasets/osgf_transformations_v0_1/runs/run-aba4cd955a9a4166b0e0d6c9 --engine rust_engine/target/debug/rust_engine.exe
python -m ruff check .
python -m ruff format --check .
python -m pytest -q tests
cargo fmt --manifest-path rust_engine/Cargo.toml -- --check
cargo test --locked --manifest-path rust_engine/Cargo.toml
cargo clippy --locked --manifest-path rust_engine/Cargo.toml --all-targets -- -D warnings
cargo build --locked --manifest-path rust_engine/Cargo.toml
python scripts/test_canonical_baseline.py --engine rust_engine/target/debug/rust_engine.exe
python scripts/test_fingerprint_baseline.py --engine rust_engine/target/debug/rust_engine.exe
python scripts/test_similarity_baseline.py --engine rust_engine/target/debug/rust_engine.exe
python scripts/dataset_review.py check
python scripts/validate_dataset_acceptance.py
python scripts/dataset_splits.py datasets/osgf_pairs_v0_1/manifest.json --config datasets/osgf_pairs_v0_1/split_config.json --check
python scripts/test_similarity_real_canonical.py --engine rust_engine/target/debug/rust_engine.exe --canonical-dir reports/canonical-notepad-step5
git diff --check
```

The existing scientific acceptance/smoke comparisons above are regression checks,
not Step 10 corpus evaluation. The Step 10 probes produce no similarity result.

Focused tests: 11 PASS. Initial test setup incorrectly treated the historical local
fixture as already canonical: 8 passed/3 failed. Corrected setup to invoke existing
canonicalize-local-subgraph into a temporary file; no engine/fixture change. All
three noncanonical-input probes then passed for fingerprint and comparison, with
no output created for rejected inputs.

Audit: PASS, byte-reproduced by --check. All 161 protected files match the Step 9
inventory, all 120 canonical graphs readable/hash-verified, all 35 local binaries
present/hash-verified; 218 pairs match the frozen counts/labels/splits. Preliminary
audit SHA-256: 2a9f746d9d8008bf0bc7c9d8f6b76cc13f5431dcbe0567583c0d35b921af683a.
Step 8 scientific digest: 095ca81b151cbcf9e58af28ad6bffebd60c2d153d4102ec019462fd7377569b2.

Detailed runtime logs remain ignored under .build-cache/step10-*.log and
step10-regressions-results.json. Final regression outcomes are appended below.

NOT RUN: hosted CI/Linux, new compiler/Ghidra extraction or fresh Step 9 replay
(not needed for a read-only audit; historical replay is not claimed as newly run).
Condition A adapter/parity and all Step 10 scoring/ranking/metrics are intentionally
NOT IMPLEMENTED/NOT RUN. Step 10.1 awaits review, Step 10.2 requires the approved
protocol and comparability gate. No commit/push or Step 11.

## Final executed outcomes

| Check | Outcome |
|---|---|
| Step 10 focused tests/probes | PASS, 11 tests, 1.60s |
| Full current Python suite | PASS, 335 tests + 175 subtests, 202.07s |
| Current Rust suite | PASS, 252 tests |
| Ruff lint / format | PASS; 65 files already formatted |
| cargo fmt / Clippy -D warnings / locked build | PASS |
| Canonical / fingerprint / similarity acceptance | PASS, 7 / 11 / 20 tests |
| Step 8 acceptance, manual review and leakage | PASS, 14 accepted review decisions verified |
| Step 9 preflight / protected inventory | PASS, 161 unchanged files |
| Step 9 read-only v2 run acceptance | PASS, 6144 oracle replay cases, 12 verified graphs, 30 verified provenance mappings |
| Preliminary audit rerun / byte hash | PASS, exact reproduction; 35 local sample binary hashes verified |

The full Python suite includes Step 9 structural-calls-v2 and historical-evidence
preservation regressions. No tests were replaced by synthetic integration claims.
The immutable audit contains all input-hash evidence; no frozen file is modified.

Additional regression: real Notepad smoke PASS, 25/25 graphs, 75 comparable views,
10 warning-bearing graphs, 25/25 byte-deterministic reruns. git diff --check PASS.
All 15 regression-driver commands returned exit code 0. Hosted CI was NOT RUN.

Final state: Step 10.0 technical audit complete, ready for review. Seven new Step 10
files, no tracked existing file changed. No Step 10.1, protocol freeze, A adapter,
empirical score matrix or metric result. Await explicit next-microstep instruction.

## 2026-10-22 — Step 10.1: protocollo preregistrato
Protocollo JSON/schema/hash creati prima di misurare punteggi; SHA256 35a4d37ba175e1316e4f2bd179179da5da28e2c534bfb7a1fa1005ddabb040eb. Primaria aggregate Multiset Jaccard; recall distinta da hit; gallerie solo giudicate, K>N unsupported, null espliciti, soglia solo discovery, nessuna negativa implicita. Query ammesse 61/22/31; K5 31/4/15. Deduplicazione per funzione fisica, conservando funzioni diverse nello stesso PE e provenance distinta a parita di contenuto. Definiti churn, stabilita, tempi, incertezza per componenti e gate A/B.
Test mirati: 16 PASS (rerun finale 13.36s). Suite Python: 351 PASS +175 subtest (258.75s); Rust252 PASS; Ruff67file, fmt, Clippy/build, acceptance canonical7/fingerprint11/similarity20, Step8/review14/leakage PASS. Inventario161file e digest Step8 invariati. Il protocollo e lo schema verificano anche i tipi e impediscono sovrascritture. Nessun risultato empirico Step10, commit/push o Step11. Prossimo: gate metodologico 10.2.
Comandi PowerShell eseguiti (cwd repository):
```powershell
python -m pytest -q tests/test_evaluation_protocol.py
python scripts/evaluation_protocol.py
python scripts/evaluation_preflight.py --check
& .build-cache/step10-1-regressions.ps1
```
Comandi completi del driver e risultati in datasets/osgf_baseline_evaluation_v0_1/VALIDATION.md; log .build-cache/step10-1-regressions.log e step10-1-focused.log. CI hosted/Linux e nuove estrazioni Ghidra NOT RUN. Il report 10.0 precedente resta storico.


## 2026-10-22 — Step 10.2: adapter e gate tecnico completati; approvazione metodologica pending
Branch codex, HEAD c2fdcced4a19d583d72374a07bd0f5dfb1cda867 invariato. Step 10.1 concluso; implementata la proposta A/B del 10.2. Nessun punteggio/ranking del corpus Step10, commit/push, freeze finale o Step11.
Creati scripts/evaluation_adapter.py, tests/test_evaluation_adapter.py e research_adapter/{main.rs,source_inventory.json,METHOD.md,gate_evidence.json} sotto datasets/osgf_baseline_evaluation_v0_1. La crate generata resta locale/ignorata. Il generatore verifica gli hash del codice di base e applica modifiche puntuali a una copia: Rust frozen intatto.
A conserva API grezze, annotazioni grezze delle costanti, nomi delle sezioni e identita separate dei nodi-valore. B mantiene la normalizzazione v0.1. Ruoli relativi, ordinamento strutturale, contatori, famiglie di feature, budget dei motivi e algoritmi Jaccard sono comuni. Il documento METHOD.md specifica l'intervento, i confondenti e i limiti: non si tratta di zero preprocessing o di un'ablation causale di una singola regola.
Formati ResearchGraph/ResearchFingerprint separati, versioni research-0.1.0; ricostruzione completa dalla sorgente e condizione obbligatoria. Bundle con input testuale e SHA256 esatto, provenance verificata, confronti cross-condition rifiutati. Nessun documento canonico falsificato o validazione aggirata.
Risultati eseguiti ora: 25 test mirati PASS (10.87s); suite Python376 PASS +175 subtest (239.52s); Rust252 PASS; acceptance canonical7/fingerprint11/similarity20 PASS. Parita B per feature/conteggi/coverage/provenance/limiti e confronti numerici non banali, no-op A/B, oracolo Jaccard indipendente, relocation/ordinamento/determinismo, collisioni API, nomi A/W e Nt/Zw distinti, stringhe/costanti esatte, viste vuote e monolaterali, troncamenti e manomissioni: PASS. Clippy crate ricerca PASS; fmt/Clippy/build frozen PASS; Ruff finale PASS su69file. Step8 acceptance/review14/leakage PASS. Inventario161file e golden invariati. Smoke Notepad frozen25/25 PASS,75viste,10grafi con warning,25/25 rerun byte-deterministici.
Storia errori preservata: primi test sintetici 3FAIL/14PASS per API selezionata errata e contatori fixture non aggiornati, poi corretti. Il driver completo ha exit1 per un controllo di formattazione iniziale: corretta la formattazione e rieseguiti Ruff lint/format con exit0. Tutti i test del driver hanno exit0; il log iniziale non e stato riscritto come verde. Nessuna modifica ai golden per ottenere PASS.
NOT RUN: CI hosted/Linux; scoring/materializzazione A/B completa del corpus; 10.3-10.10; nuova estrazione Ghidra/fresh replay Step9. Il preflight segnala launcher Ghidra non configurato in questa sessione: non serve per questo gate basato sulle sorgenti locali gia congelate. Le precedenti prove Step9 reali restano risultati storici, non nuove esecuzioni.
Comandi PowerShell completi, eseguiti dalla root della repository:
```powershell
python -m ruff check .
python -m ruff format --check .
python -m pytest -q tests
cargo fmt --manifest-path rust_engine/Cargo.toml -- --check
cargo test --locked --manifest-path rust_engine/Cargo.toml
cargo clippy --locked --manifest-path rust_engine/Cargo.toml --all-targets -- -D warnings
cargo build --locked --manifest-path rust_engine/Cargo.toml
python scripts/test_canonical_baseline.py --engine rust_engine/target/debug/rust_engine.exe
python scripts/test_fingerprint_baseline.py --engine rust_engine/target/debug/rust_engine.exe
python scripts/test_similarity_baseline.py --engine rust_engine/target/debug/rust_engine.exe
python scripts/dataset_review.py check
python scripts/validate_dataset_acceptance.py
python scripts/dataset_splits.py datasets/osgf_pairs_v0_1/manifest.json --config datasets/osgf_pairs_v0_1/split_config.json --check
python scripts/test_similarity_real_canonical.py --engine rust_engine/target/debug/rust_engine.exe --canonical-dir reports/canonical-notepad-step5
git diff --check
python scripts/evaluation_adapter.py --build
python -m pytest -q -s tests/test_evaluation_adapter.py
cargo clippy --offline --locked --manifest-path datasets/osgf_baseline_evaluation_v0_1/runtime/research_adapter/Cargo.toml --all-targets -- -D warnings
rustfmt --edition 2021 --config skip_children=true --check datasets/osgf_baseline_evaluation_v0_1/research_adapter/main.rs
python scripts/evaluation_protocol.py
python scripts/step9_preflight.py --baseline datasets/osgf_transformations_v0_1/baseline.json
python -m ruff check .
python -m ruff format --check .
```
Log: .build-cache/step10-2-regressions.log, step10-2-regressions-results.json, step10-2-focused-final.log, step10-2-frozen-inventory.log. Risultati visibili nella scheda PowerShell OSGF-Step10.2. Definizione da revisionare: datasets/osgf_baseline_evaluation_v0_1/research_adapter/METHOD.md. Evidenza e binding codice/metodo: research_adapter/gate_evidence.json.
Checkpoint per ripresa: 10.1 completato; 10.2 tecnico completato, decisione umana NON compilata. Il protocollo incollato richiede: "STOP for human approval at the A/B comparability gate". Attendere approvazione di questa definizione A/B; poi riprendere dal 10.3 fino al 10.10. Nessuna etichetta, split, anchor-only o semantica Step5-7 modificata.



## 2026-10-22 — Step 10.3 completato: catalogo A/B e provenance
Autorizzazione utente: "ok continua con step successivo", dopo la richiesta di approvazione della definizione A/B. Registrata in research_adapter/approval.json con binding SHA256 dell'evidenza del gate; le vecchie note pending del 10.2 rimangono snapshot storici. Branch codex, HEAD c2fdcced4a19d583d72374a07bd0f5dfb1cda867 invariato.
Implementati scripts/evaluation_catalog.py e tests/test_evaluation_catalog.py. Documentazione in datasets/osgf_baseline_evaluation_v0_1/CATALOG.md; aggiornato docs/baseline_evaluation_v0_1.md. Catalogo da versionare: graph_catalog.json; prova esecuzione: catalog_validation.json. Gli artefatti generati restano locali/ignorati in runtime/catalog-v0_1 e runtime/catalog-replay-v0_1.
Materializzati tutti i120grafi per entrambe le condizioni: A120/120 e B120/120, zero fallimenti/esclusioni. Nessun filtro per label, anchor-only o segnali scarsi; conservata ogni provenance distinta anche a parita di digest. A usa solo il formato di ricerca approvato; B usa il vero fingerprint-canonical frozen con sidecar originale. Identita/cache legate a sorgenti, sample/build/gruppo/split, hash del protocollo e approvazione, hash degli eseguibili e codice/configurazione del generatore.
Pubblicazione atomica da staging; nessuna sovrascrittura di output esistenti. Un fallimento non ammette artefatti e rende il catalogo INCOMPLETE con exit nonzero. --verify ricostruisce sempre tutti gli artefatti, controllando provenance e metadata oltre agli hash. Non esiste una verifica solo-hash che possa accettare una sidecar corrotta con hash aggiornato.
Prove reali: --verify PASS per240record; due materializzazioni indipendenti con481file identici byte per byte (480artefatti + catalogo). Dry-run finale identico al piano pubblicato. SHA256 catalogo: b2e795baeb57255f85faad396262228969134151d0d9f1d89bcb10d6e2e716bf. Nessun percorso personale assoluto o timestamp nel catalogo scientifico.
Test: suite Python completa392PASS +175subtest (229.85s); Rust252PASS. Mirati catalogo16PASS, ultimo rerun4.15s dopo avere aggiunto l'asserzione esplicita per canonico assente. Coperti input/hash/versione/percorso errati, condizione sconosciuta, provenance corrotta anche con hash coerente, file mancanti/extra, replay, identita stale, collisioni output, abort atomico, copertura completa e nessuna scrittura nel dry-run. Ruff71file/fmt/Clippy/build PASS. Acceptance canonical7/fingerprint11/similarity20 PASS; Step8 acceptance/review14/leakage PASS. Smoke Notepad25/25,75viste,10grafi con warning e25/25 rerun deterministici PASS. Tutti i15comandi del driver completo hanno exit0. Inventario161file protetti e golden invariati; digest Step8 095ca81b151cbcf9e58af28ad6bffebd60c2d153d4102ec019462fd7377569b2 invariato.
Comandi PowerShell eseguiti dalla root della repository:
```powershell
python scripts/evaluation_adapter.py --build
python scripts/evaluation_catalog.py --dry-run
python scripts/evaluation_catalog.py --materialize
python scripts/evaluation_catalog.py --verify
python scripts/evaluation_catalog.py --materialize --output datasets/osgf_baseline_evaluation_v0_1/runtime/catalog-replay-v0_1
python -m pytest -q tests/test_evaluation_catalog.py
python scripts/step9_preflight.py --baseline datasets/osgf_transformations_v0_1/baseline.json
python -m ruff check .
python -m ruff format --check .
python -m pytest -q tests
cargo fmt --manifest-path rust_engine/Cargo.toml -- --check
cargo test --locked --manifest-path rust_engine/Cargo.toml
cargo clippy --locked --manifest-path rust_engine/Cargo.toml --all-targets -- -D warnings
cargo build --locked --manifest-path rust_engine/Cargo.toml
python scripts/test_canonical_baseline.py --engine rust_engine/target/debug/rust_engine.exe
python scripts/test_fingerprint_baseline.py --engine rust_engine/target/debug/rust_engine.exe
python scripts/test_similarity_baseline.py --engine rust_engine/target/debug/rust_engine.exe
python scripts/dataset_review.py check
python scripts/validate_dataset_acceptance.py
python scripts/dataset_splits.py datasets/osgf_pairs_v0_1/manifest.json --config datasets/osgf_pairs_v0_1/split_config.json --check
python scripts/test_similarity_real_canonical.py --engine rust_engine/target/debug/rust_engine.exe --canonical-dir reports/canonical-notepad-step5
git diff --check
```
Il confronto indipendente finale ha enumerato i file dei due runtime, verificato identici insiemi di percorsi e confrontato direttamente read_bytes() per tutti i481file; non soltanto i loro hash. La copia versionata graph_catalog.json coincide esattamente con runtime/catalog-v0_1/catalog.json.
Log: .build-cache/step10-3-materialize.log, step10-3-regressions.log, step10-3-regressions-results.json, step10-3-focused-final.log, step10-3-frozen-inventory.log. Risultati mostrati nelle schede PowerShell OSGF-Step10.3 e OSGF-Step10.3-Tests.
NOT RUN: CI hosted/Linux, nuova estrazione Ghidra/fresh replay Step9, scoring delle218coppie, ranking/Recall/MRR/soglie/runtime comparativo Step10.4-10.10. I precedenti risultati Step9 restano storici. Nessuna label, split, semantica Step5-7 o fixture golden modificata; nessun commit/push, freeze finale o Step11.
Checkpoint: Step10.3 concluso. Prossimo microstep10.4: matrice deterministica delle218coppie nelle due condizioni, usando catalogo e protocolli approvati; non ancora implementata.


## 2026-10-22 — Step 10.4 completato: matrice deterministica
Branch codex, HEAD c2fdcced4a19d583d72374a07bd0f5dfb1cda867. Implementati evaluation_pairs.py e 20 test mirati (PASS). Tutte le 218 coppie per A e B: 436 risultati con oracolo Jaccard indipendente PASS; 151 positive e 67 negative per condizione. Componenti confrontabili identici per tutte le 218 coppie. Replay completo: 437 file identici byte per byte. SHA256 matrice d973a21abd951f4d6ef38d94751869b7e8ad32c57a8a18596db5dbc36eab8296. Provenance direzionale conservata, null e warning separati dai punteggi. Nessuna metrica retrieval ancora calcolata.
Risultati reali registrati dal driver: 15 comandi tutti exit 0, Python 412 passed +175 subtests, Rust 252 passed; acceptance e Notepad PASS. Inventari congelati e golden preservati. Nessun commit/push. CI hosted/Linux e nuova estrazione Ghidra NON eseguiti.
Comandi PowerShell dalla root:
```powershell
python scripts/evaluation_pairs.py --score
python scripts/evaluation_pairs.py --verify
python -m pytest -q tests/test_evaluation_pairs.py
powershell -NoProfile -ExecutionPolicy Bypass -File .build-cache/step10-4-regressions.ps1
```
Elenco completo dei 15 comandi ed exit code: .build-cache/step10-4-regressions-results.json; output integrale: step10-4-regressions.log e step10-4-scores.log. Checkpoint: 10.4 completato, prossimo 10.5.

## 2026-10-26 — Step 10.5 completato: judged galleries
Branch codex, HEAD c2fdcced4a19d583d72374a07bd0f5dfb1cda867 invariato. evaluation_galleries.py verifica protocollo, dipendenze, matrice, artifact e oracoli indipendenti prima di costruire gallerie giudicate. Nessuna relazione sconosciuta viene aggiunta come negativa; null esclude l'intera query dal ranking. Tie: score decrescente, graph ID crescente. Il riuso inverso riguarda soltanto il numero simmetrico, con riferimento al record direzionale originale.
17 test mirati PASS (rieseguiti oggi, 0.09 s). Corpus e replay PASS, output identico SHA256 c450049755617f29d549ddad9abd363e808d1112889b24bdcc7a5568c30d1be5. 120 query per condizione, 114 eleggibili comuni: discovery 61, validation 22, held-out 31. Copertura K1/3/5 rispettivamente 61/31/31, 22/16/4, 31/16/15. Sei query per condizione senza positivi restano documentate. Nessun Recall/MRR ancora calcolato. Risultati aperti nella scheda PowerShell OSGF-Step10.5.
Comandi PowerShell (exit 0):
```powershell
python -m pytest -q tests/test_evaluation_galleries.py
python scripts/evaluation_galleries.py
```
Ripetizione corpus verifica byte identici senza sovrascrivere output. Ruff check/format e git diff --check PASS nella sessione del 22 ottobre; regressioni complete 10.4 restano risultati precedenti, non rieseguiti oggi. Log step10-5-focused.log e step10-5-replay.log in .build-cache. Prossimo: 10.6. Nessun commit/push, freeze finale o Step11.

## 2026-10-26 — Step 10.6 completato: metriche query e classificazione
Implementati evaluation_metrics.py e 11 test PASS (0.16 s): oracoli Recall/Hit/MRR, quantili, denominatori query, classi mancanti, tie reject-all, soglia solo discovery, invariabilita rispetto ai dati held-out. Esecuzione reale e replay byte-identico PASS; soglie pubblicate prima delle metriche validation/held-out.
A e B hanno qui metriche retrieval uguali. Discovery Recall@1/3/5 0.579326/0.557348/0.905376 (N61/31/31), MRR0.923497; validation 0.318182/0.9375/1.0 (N22/16/4), MRR0.840909; held-out 0.551613/0.463542/0.773333 (N31/16/15), MRR0.887097. K diversi hanno denominatori diversi: non interpretarli come curva monotona sullo stesso cohort. FPR pairwise A/B discovery0.714286, validation0.461538, held-out1.0; questi risultati non indicano capacita malware e non sono stati usati per ritoccare soglie o metodo. Hit e false-top1 sono riportati separatamente. Distribuzioni positive/negative e per-view, ID e null conservati.
SHA soglie 63b6ee1facb4c7bb95ca82aba181558667e8948ea327b4e7f8b5a6a9e3a3f14d; metriche 6e8e0d89c6fd76629b098257f5204d08923678847e351df4e98c651b8ba56309.
Comandi PowerShell exit0:
```powershell
python -m ruff check scripts/evaluation_metrics.py tests/test_evaluation_metrics.py
python -m pytest -q tests/test_evaluation_metrics.py
python scripts/evaluation_metrics.py
python scripts/evaluation_metrics.py
```
Log .build-cache/step10-6-metrics.log e step10-6-replay.log. Regressioni complete precedenti non presentate come nuove; nessun freeze finale/commit/push. Prossimo: 10.7.

## 2026-10-26 — Step 10.7 completato: feature churn e rank stability
Implementati evaluation_stability.py e 7 test PASS: conteggi/oracoli presenza e molteplicita, inserimenti/rimozioni/delta, vuoti, ordine, ranking invertito, ties, singleton, gallery mismatch e non disponibilita. 302 confronti pair-condition equivalenti, 3 viste ciascuno; dettagli descriptor e warning/completeness conservati separatamente. 114 ranking comuni A/B: differenza normalizzata zero in tutti; correlazioni costanti/singleton restano null. Non e una prova di equivalenza generale dei metodi.
Churn cross-condition non supportato: non esiste mapping scientifico A/B approvato. Churn entro condizione calcolato sui descrittori esatti, mai sugli ID dipendenti dalla versione. Dimensioni compiler/optimization e Step9 senza gallery identiche dichiarate non supportate; nessuna variante Step9 inserita nei dati frozen. Assenza osservata non equiparata a prova di assenza semantica.
Corpus e replay byte-identico PASS, SHA256 f962976cde69674a3e1b692cfd4aff17591750561863de45f36df7cad43d7042.
Comandi PowerShell exit0:
```powershell
python -m ruff check scripts/evaluation_stability.py tests/test_evaluation_stability.py
python -m pytest -q tests/test_evaluation_stability.py
python scripts/evaluation_stability.py
python scripts/evaluation_stability.py
```
Log .build-cache/step10-7-stability.log e step10-7-replay.log. Nessun commit/push/freeze finale. Prossimo: 10.8.

## 2026-10-26 — Step 10.8 completato: strata e review descrittiva
Implementati evaluation_stratification.py, 5 test PASS e PROVISIONAL_REVIEW.md. 105 tabelle con N/ID, condizioni, delta paired, distribuzioni, retrieval su gallerie originali intere e churn; split/label/compiler/optimization/family e strata frozen. Holdout esatti senza spostamenti. FPR specifico holdout dichiarato unsupported per assenza di calibrazione family-excluded preregistrata. Nessun tuning retroattivo.
Sei componenti indipendenti connessi per source/artifact/hash/near-duplicate; sotto il minimo10: solo medie/range descrittivi, nessuna CI inferenziale. Strata sovrapposti non sommabili. 142 errori di classificazione condition-specific con provenance retained. Review leggibile con esempi e limiti: PROVISIONAL_REVIEW.md.
Corpus e replay PASS SHA256 91fb06c0c3e36e664484dc716f586eab3c752ab72e735b775c135d72b36ef2e5. Test leakage/holdout/unknown strata e invariabilita manifest PASS.
Comandi PowerShell exit0:
```powershell
python -m ruff check scripts/evaluation_stratification.py tests/test_evaluation_stratification.py
python -m pytest -q tests/test_evaluation_stratification.py
python scripts/evaluation_stratification.py
python scripts/evaluation_stratification.py
```
Log .build-cache/step10-8-strata.log e step10-8-replay.log. Nessun commit/push/freeze finale. Prossimo: benchmark reale e replay fresh-workspace 10.9.

## 2026-10-26 — Step 10.9 completato: runtime e fresh-workspace replay
Benchmark effettivo runtime-001.json: un warmup + cinque ripetizioni, ordine A/B alternato, tutti i120 grafi e218 coppie, 6948 misurazioni, zero errori. Mediane ms: estrazione combinata A32.456/B60.0503; confronto con validazione/IO A75.3702/B104.69785; ranking completo A1.6341/B1.7628. N misurati:600 estrazioni e1090 confronti per condizione;5 ranking. Warmup escluso dalle statistiche. Python/Rust/toolchain/OS/hardware e dimensioni input registrati. B rigenera canonico e fingerprint; nessun costo cached=0. Substage B separati diagnostici; A CLI approvata non separa adapter/features. Startup/IO e cache OS espliciti; memoria RSS e nuova estrazione Ghidra non misurate.
Il primo tentativo fresh-workspace ha incontrato WinError5 del sandbox nella rename atomica: NON PASS. Il benchmark di sviluppo concorrente e stato interrotto senza pubblicare osservazioni. Benchmark definitivo eseguito da solo; successivo fresh replay con permessi corretti PASS:918 file runtime +7 artefatti scientifici identici byte per byte. SHA replay 86005ef7fb359eeb1aa3dcd23dcf70f7880932de8140d4e2d427f1f1e517c9bf. Workspace nuovo con sorgenti ed eseguibili pinned, non nuova compilazione/clone Git/CI hosted.
Test runtime4 PASS; test finali integrati e osservabilita17 PASS. Suite completa oggi462 passed +175 subtests (208.95s), Rust252 PASS; tutti16 comandi del driver finale exit0, Ruff86file, fmt/clippy/build, acceptance canonical/fingerprint/similarity, review/acceptance/leakage Step8, Notepad25/25 e inventario Step9 (161file) PASS. Nessun golden/input frozen modificato.
Comandi PowerShell:
```powershell
python -m pytest -q tests/test_evaluation_runtime.py
python -m pytest -q tests/test_evaluation_acceptance.py tests/test_evaluation_stability.py tests/test_evaluation_runtime.py
python scripts/evaluation_runtime.py --observation-id runtime-001
python scripts/evaluation_replay.py
powershell -NoProfile -ExecutionPolicy Bypass -File .build-cache/step10-final-regressions.ps1
```
Elenco integrale comandi/exit code: .build-cache/step10-final-regressions-results.json; output .build-cache/step10-final-regressions.log. Log benchmark e replay step10-9-runtime.log e step10-9-fresh-replay.log. Schede PowerShell aperte con risultati reali. Prossimo:10.10, ricostruzione finale e secondo replay prima del freeze. Nessun commit/push/Step11.

## 2026-10-26 — Step 10.10 completato: acceptance e freeze-001
Branch codex; HEAD c2fdcced4a19d583d72374a07bd0f5dfb1cda867 invariato. Nessun commit/push. Step11 NON iniziato.
Accettazione reale: ricostruiti protocollo/input/catalogo/provenance, 436 risultati e tutti i derivati. Secondo replay end-to-end in altra cartella nuova PASS:918file runtime +7artefatti scientifici byte-identici. Runtime6948misurazioni ricontrollate per cohort/ripetizione/stage/summary; osservazioni variabili legate separatamente dal manifest scientifico.
Freeze nuovo e non sovrascrivibile: datasets/osgf_baseline_evaluation_v0_1/freezes/freeze-001/. Contiene scientific_manifest.json, runtime_observation_manifest.json, validation_commands.json e ACCEPTANCE.md. SHA256 manifest scientifico: 77ec300d024ed9fe9dc7b4730ccf148baf2f1db7b866a677155c3d6dca41d7cb. Verifica post-pubblicazione di tutti gli hash PASS.
Protocollo hash esplicito: artefatti scientifici/eseguibili/provenance compilata byte esatti; identita del codice Python UTF-8 LF distinta, coerente con i generatori. Nessun hash delle sorgenti C compilate normalizzato retroattivamente.
Regressioni complete oggi:462Python +175subtests,252Rust,16comandi tutti exit0. Dopo la precisazione del manifest hash, rieseguiti Ruff e4test acceptance PASS. Test nuovi osservabilita/churn inclusi nella suite completa; nessun warning viene trasformato in similarita.
Risultati: A/B score e ranking uguali su questo corpus; 114query comuni. Held-out Recall@1/3/5=0.551613/0.463542/0.773333 con N31/16/15, MRR0.887097. Soglia discovery0.3 per entrambe le condizioni; FPR held-out1.0: debolezza sostanziale documentata, nessun tuning correttivo. Sei componenti indipendenti: niente CI inferenziale. Churn cross-condition, FPR family-holdout non preregistrato, RSS e dimensioni ranking senza gallery identiche sono esplicitamente unsupported, non PASS numerici inventati. Tutti i dettagli e gli esempi di errore con provenance sono negli artefatti.
Comandi PowerShell effettivamente eseguiti, exit0:
```powershell
python -m ruff check .
python -m ruff format --check .
python -m pytest -q tests
cargo fmt --manifest-path rust_engine/Cargo.toml -- --check
cargo test --locked --manifest-path rust_engine/Cargo.toml
cargo clippy --locked --manifest-path rust_engine/Cargo.toml --all-targets -- -D warnings
cargo build --locked --manifest-path rust_engine/Cargo.toml
python scripts/test_canonical_baseline.py --engine rust_engine/target/debug/rust_engine.exe
python scripts/test_fingerprint_baseline.py --engine rust_engine/target/debug/rust_engine.exe
python scripts/test_similarity_baseline.py --engine rust_engine/target/debug/rust_engine.exe
python scripts/dataset_review.py check
python scripts/validate_dataset_acceptance.py
python scripts/dataset_splits.py datasets/osgf_pairs_v0_1/manifest.json --config datasets/osgf_pairs_v0_1/split_config.json --check
python scripts/test_similarity_real_canonical.py --engine rust_engine/target/debug/rust_engine.exe --canonical-dir reports/canonical-notepad-step5
python scripts/step9_preflight.py --baseline datasets/osgf_transformations_v0_1/baseline.json
git diff --check
python -m pytest -q tests/test_evaluation_acceptance.py
python scripts/evaluation_replay.py
python scripts/evaluation_acceptance.py --freeze
```
Log finale .build-cache/step10-10-acceptance.log; regressioni .build-cache/step10-final-regressions.log. Schede PowerShell aperte. Inventario protetto161file, semantica Step5-7 e golden invariati.
NOT RUN: CI hosted/Linux, ricompilazione fresh-workspace, nuova estrazione Ghidra, nuovo esperimento supplementare Step9, misure RSS, real malware pilot. Risultati storici non confusi con verifiche odierne.
Checkpoint definitivo:10.0–10.10 completati nell’ambito preregistrato supportato. Pronto per review utente prima dello Step11. Future REAL MALWARE PILOT separato, nessun campione malware importato. Fermato qui.

