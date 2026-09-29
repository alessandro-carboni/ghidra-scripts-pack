$ErrorActionPreference = "Stop"

Write-Host "`n================================================"
Write-Host "REAL SEEDED LOCAL SUBGRAPH EXPORT — NOTEPAD.EXE"
Write-Host "================================================"

Write-Host "`n=== 1/8 Rust format ==="
cargo fmt --manifest-path rust_engine/Cargo.toml
if ($LASTEXITCODE -ne 0) { throw "cargo fmt failed" }

cargo fmt --manifest-path rust_engine/Cargo.toml -- --check
if ($LASTEXITCODE -ne 0) { throw "cargo fmt --check failed" }

Write-Host "`n=== 2/8 Runtime exporter focused tests ==="
cargo test --manifest-path rust_engine/Cargo.toml runtime_subgraph_export::tests:: -- --nocapture
if ($LASTEXITCODE -ne 0) { throw "runtime_subgraph_export tests failed" }

Write-Host "`n=== 3/8 Full Rust regression ==="
cargo test --manifest-path rust_engine/Cargo.toml
if ($LASTEXITCODE -ne 0) { throw "full Rust tests failed" }

Write-Host "`n=== 4/8 Clippy ==="
cargo clippy --manifest-path rust_engine/Cargo.toml -- -D warnings
if ($LASTEXITCODE -ne 0) { throw "cargo clippy failed" }

Write-Host "`n=== 5/8 Rust build ==="
cargo build --manifest-path rust_engine/Cargo.toml
if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }

Write-Host "`n=== 6/8 Find latest real Notepad raw report ==="
$rawReport = Get-ChildItem .\reports\notepad_*_raw.json |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if ($null -eq $rawReport) {
    throw "No notepad_*_raw.json report found in .\reports"
}

Write-Host "[OK] Input report:" $rawReport.FullName

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outDir = Join-Path .\reports ($rawReport.BaseName + "_seeded_subgraphs_" + $stamp)

Write-Host "`n=== 7/8 Export real seeded local subgraphs ==="
.\rust_engine\target\debug\rust_engine.exe export-local-subgraphs `
    $rawReport.FullName `
    $outDir `
    --rules .\rules\seed_rules.json

if ($LASTEXITCODE -ne 0) { throw "real seeded local-subgraph export failed" }

$manifestPath = Join-Path $outDir "manifest.json"
if (-not (Test-Path $manifestPath)) {
    throw "manifest.json was not produced"
}

$manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json

Write-Host "`n=== 8/8 Validate exported GUI contract ==="

if ($manifest.schema_version -ne "0.1.0") {
    throw "Unexpected manifest schema version: $($manifest.schema_version)"
}
if ($manifest.local_subgraph_schema_version -ne "0.1.0") {
    throw "Unexpected local subgraph schema version: $($manifest.local_subgraph_schema_version)"
}
if ($manifest.graph_version -ne "0.12.0") {
    throw "Unexpected graph version: $($manifest.graph_version)"
}
if ($manifest.seed_rules_version -ne "0.4.0") {
    throw "Unexpected seed rules version: $($manifest.seed_rules_version)"
}
if ($manifest.seed_detection.returned -ne $manifest.subgraphs.Count) {
    throw "Manifest returned seed count does not match subgraph entries"
}

$subgraphFiles = @(Get-ChildItem $outDir -Filter "seed_*.json")
if ($subgraphFiles.Count -ne $manifest.subgraphs.Count) {
    throw "Number of subgraph JSON files does not match manifest"
}

foreach ($entry in $manifest.subgraphs) {
    $path = Join-Path $outDir $entry.file
    if (-not (Test-Path $path)) {
        throw "Missing subgraph file: $($entry.file)"
    }

    $doc = Get-Content $path -Raw | ConvertFrom-Json

    if ($doc.schema_version -ne "0.1.0") {
        throw "Bad local schema in $($entry.file)"
    }
    if ($doc.graph_version -ne "0.12.0") {
        throw "Bad graph version in $($entry.file)"
    }
    if ($doc.seed_id -ne $entry.seed_id) {
        throw "seed_id mismatch in $($entry.file)"
    }
    if ($doc.anchor_function_id -ne $entry.anchor_function_id) {
        throw "anchor mismatch in $($entry.file)"
    }
    if ($doc.nodes.Count -ne $entry.total_nodes) {
        throw "node count mismatch in $($entry.file)"
    }
    if ($doc.edges.Count -ne $entry.edges) {
        throw "edge count mismatch in $($entry.file)"
    }
    if ($doc.unresolved_calls.Count -ne $entry.unresolved_calls) {
        throw "unresolved count mismatch in $($entry.file)"
    }

    $nodeIds = @{}
    foreach ($node in $doc.nodes) {
        $nodeIds[$node.id] = $true
    }
    foreach ($edge in $doc.edges) {
        if (-not $nodeIds.ContainsKey($edge.source) -or -not $nodeIds.ContainsKey($edge.target)) {
            throw "edge with endpoint outside local nodes in $($entry.file)"
        }
    }
    foreach ($call in $doc.unresolved_calls) {
        if ($null -ne $call.callee) {
            throw "unresolved call invented a callee in $($entry.file)"
        }
        if ($call.unresolved -ne $true) {
            throw "unresolved call lost unresolved=true in $($entry.file)"
        }
    }
}

Write-Host "`n=== MANIFEST SUMMARY ==="
[PSCustomObject]@{
    Sample             = $manifest.sample_name
    SourceReport       = $manifest.source_report
    GraphVersion       = $manifest.graph_version
    SeedRulesVersion   = $manifest.seed_rules_version
    SeedModelVersion   = $manifest.seed_detection.model_version
    SeedsDetected      = $manifest.seed_detection.total_detected
    SeedsReturned      = $manifest.seed_detection.returned
    SeedListTruncated  = $manifest.seed_detection.truncated
    LocalSubgraphs     = $manifest.subgraphs.Count
    RelatedSeedGroups  = $manifest.related_seed_groups.Count
    OutputDirectory    = $outDir
} | Format-List

Write-Host "`n=== FIRST 10 REAL SEEDS ==="
$manifest.seed_detection.seeds | Select-Object -First 10 | ForEach-Object {
    [PSCustomObject]@{
        Seed       = $_.seed_id
        Anchor     = $_.anchor_function_id
        Triggers   = ($_.trigger_ids -join ", ")
        Families   = ($_.families -join ", ")
        Evidence   = $_.evidence.Count
    }
} | Format-Table -AutoSize

if ($manifest.subgraphs.Count -gt 0) {
    $firstEntry = $manifest.subgraphs[0]
    $firstPath = Join-Path $outDir $firstEntry.file
    $first = Get-Content $firstPath -Raw | ConvertFrom-Json

    Write-Host "`n=== FIRST REAL LOCAL SUBGRAPH ==="
    [PSCustomObject]@{
        File             = $firstEntry.file
        Seed             = $first.seed_id
        Anchor           = $first.anchor_function_id
        Functions        = $first.truncation.counts.function_nodes
        EvidenceNodes    = $first.truncation.counts.evidence_nodes
        TotalNodes       = $first.truncation.counts.total_nodes
        Edges            = $first.truncation.counts.edges
        UnresolvedCalls  = $first.truncation.counts.unresolved_calls
        Truncated        = $first.truncation.truncated
        CallerDepth      = $first.extraction_config.caller_depth
        CalleeDepth      = $first.extraction_config.callee_depth
    } | Format-List

    Write-Host "`nNode types:"
    $first.nodes |
        Group-Object type |
        Sort-Object Name |
        Select-Object Name, Count |
        Format-Table -AutoSize

    Write-Host "`nEdge types:"
    $first.edges |
        Group-Object type |
        Sort-Object Name |
        Select-Object Name, Count |
        Format-Table -AutoSize
}

Write-Host "`n================================================"
Write-Host "REAL SEEDED LOCAL SUBGRAPH EXPORT PASSED"
Write-Host "GUI DATASET READY:" $outDir
Write-Host "================================================"
