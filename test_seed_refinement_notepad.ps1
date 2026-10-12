param(
    [string]$RawReport = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Require-ExitCode([string]$Label) {
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE"
    }
}

function Require([bool]$Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

$repo = (Get-Location).Path
Require (Test-Path (Join-Path $repo "rust_engine\Cargo.toml")) "Run this script from the repository root."
Require (Test-Path (Join-Path $repo "rules\seed_rules.json")) "rules\seed_rules.json not found."

Write-Host "`n================================================"
Write-Host "STEP 3R - REAL NOTEPAD SEED REFINEMENT"
Write-Host "================================================"

Write-Host "`n=== 1/8 Bundled policy contract ==="
$rules = Get-Content .\rules\seed_rules.json -Raw | ConvertFrom-Json
Require ($rules.schema_version -eq "0.4.0") "Unexpected seed-rules schema version."
Require ($rules.rules.Count -eq 42) "Expected 42 bundled seed-generating rules after Step 3R."
$forbiddenDefaultTriggers = @(
    "visibility_signal.indirect_call",
    "unresolved_call.present"
)
foreach ($trigger in $forbiddenDefaultTriggers) {
    Require (-not ($rules.rules.id -contains $trigger)) "Observability-only trigger still exists in bundled default policy: $trigger"
}
Write-Host "[OK] 42 bundled seed-generating rules; call-visibility observations are context-only by default."

Write-Host "`n=== 2/8 Rust format ==="
cargo fmt --manifest-path .\rust_engine\Cargo.toml
Require-ExitCode "cargo fmt"
cargo fmt --manifest-path .\rust_engine\Cargo.toml -- --check
Require-ExitCode "cargo fmt --check"

Write-Host "`n=== 3/8 Focused seed tests ==="
cargo test --manifest-path .\rust_engine\Cargo.toml seed_rules::tests:: -- --nocapture
Require-ExitCode "seed_rules tests"
cargo test --manifest-path .\rust_engine\Cargo.toml seed_detection_tests:: -- --nocapture
Require-ExitCode "seed_detection integration tests"
cargo test --manifest-path .\rust_engine\Cargo.toml seed_validation::tests:: -- --nocapture
Require-ExitCode "seed_validation tests"

Write-Host "`n=== 4/8 Full Rust regression + Clippy ==="
cargo test --manifest-path .\rust_engine\Cargo.toml
Require-ExitCode "full Rust regression"
cargo clippy --manifest-path .\rust_engine\Cargo.toml -- -D warnings
Require-ExitCode "cargo clippy"

Write-Host "`n=== 5/8 Build Rust engine ==="
cargo build --manifest-path .\rust_engine\Cargo.toml
Require-ExitCode "cargo build"

if ([string]::IsNullOrWhiteSpace($RawReport)) {
    $candidate = Get-ChildItem .\reports -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -eq "raw_report.json" -or
            ($_.Name -like "notepad_*_raw.json")
        } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    if ($null -eq $candidate) {
        throw "No existing raw Notepad report found. Pass -RawReport <path>."
    }
    $RawReport = $candidate.FullName
}

$RawReport = (Resolve-Path $RawReport).Path
Write-Host "`nUsing raw report: $RawReport"

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$output = Join-Path $repo "reports\seed-refinement-notepad-$stamp"

Write-Host "`n=== 6/8 Real export from existing raw report ==="
& .\rust_engine\target\debug\rust_engine.exe export-local-subgraphs `
    $RawReport `
    $output `
    --rules .\rules\seed_rules.json
Require-ExitCode "real local-subgraph export"

$manifestPath = Join-Path $output "manifest.json"
Require (Test-Path $manifestPath) "manifest.json was not produced."
$manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json

Write-Host "`n=== 7/8 Validate real refined result ==="
Require (-not $manifest.seed_detection.truncated) "Real seed output is unexpectedly truncated."
Require ($manifest.seed_detection.returned -eq $manifest.seed_detection.total_detected) "Returned/detected seed counts differ without truncation."
Require ($manifest.subgraphs.Count -eq $manifest.seed_detection.returned) "Subgraph count does not match returned seed count."

$allTriggers = @($manifest.seed_detection.seeds | ForEach-Object { $_.trigger_ids } | ForEach-Object { $_ })
foreach ($trigger in $forbiddenDefaultTriggers) {
    Require (-not ($allTriggers -contains $trigger)) "Context-only trigger leaked into default seed output: $trigger"
}

$callVisibilitySeeds = @($manifest.seed_detection.seeds | Where-Object { $_.families -contains "call_visibility" })
Require ($callVisibilitySeeds.Count -eq 0) "Bundled default output still contains call_visibility seeds."

$visibilityNodeCount = 0
$unresolvedRecordCount = 0
foreach ($entry in $manifest.subgraphs) {
    $graphPath = Join-Path $output $entry.file
    Require (Test-Path $graphPath) "Missing exported local subgraph: $($entry.file)"
    $graph = Get-Content $graphPath -Raw | ConvertFrom-Json
    $visibilityNodeCount += @($graph.nodes | Where-Object { $_.type -eq "VISIBILITY_INDICATOR" }).Count
    $unresolvedRecordCount += @($graph.unresolved_calls).Count
}

Require ($visibilityNodeCount -gt 0) "Visibility indicators disappeared from local contexts; Step 3R must not delete observability evidence."
Require ($unresolvedRecordCount -gt 0) "Unresolved-call records disappeared from local contexts; Step 3R must preserve them."

Write-Host "`nBEFORE baseline (previous Notepad export): 264 seeds"
Write-Host "AFTER  refined bundled policy:          $($manifest.seed_detection.returned) seeds"
Write-Host "Visibility nodes retained in exported local contexts: $visibilityNodeCount"
Write-Host "Unresolved records retained in exported local contexts: $unresolvedRecordCount"

Write-Host "`nFamilies:"
$manifest.seed_detection.seeds |
    ForEach-Object { $_.families } |
    ForEach-Object { $_ } |
    Group-Object |
    Sort-Object Count -Descending |
    Select-Object Count, Name |
    Format-Table -AutoSize

Write-Host "Triggers:"
$allTriggers |
    Group-Object |
    Sort-Object Count -Descending |
    Select-Object Count, Name |
    Format-Table -AutoSize

Write-Host "First 10 refined seeds:"
$manifest.seed_detection.seeds |
    Select-Object -First 10 |
    ForEach-Object {
        [PSCustomObject]@{
            Anchor = $_.anchor_function_id
            Families = ($_.families -join ", ")
            Triggers = ($_.trigger_ids -join ", ")
            Evidence = @($_.evidence).Count
        }
    } |
    Format-Table -AutoSize

Write-Host "`n=== 8/8 Git diff check ==="
git diff --check
Require-ExitCode "git diff --check"

Write-Host "`n================================================"
Write-Host "STEP 3R REAL REFINEMENT PASSED"
Write-Host "Manifest: $manifestPath"
Write-Host "================================================"
