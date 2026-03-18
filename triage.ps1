param(
    [Parameter(Position = 0)]
    [ValidateSet("run")]
    [string]$Command,

    [Alias("f")]
    [string]$FilePath,

    [Alias("d")]
    [string]$GhidraDir,

    [string]$ProjectDir = "C:\ghidra-projects",
    [string]$ProjectName = "TestProject",
    [string]$PostScript = "export_report.py"
)

$ProjectRoot = $PSScriptRoot
$ScriptPath  = Join-Path $ProjectRoot "ghidra_scripts"
$OutputDir   = Join-Path $ProjectRoot "reports"
$OutputFile  = Join-Path $OutputDir "raw_report.json"
$PyGhidraRun = Join-Path $GhidraDir "support\pyghidraRun.bat"

function Show-Usage {
    Write-Host ""
    Write-Host "Usage:"
    Write-Host '  .\triage.ps1 run -f ".\samples\sample.exe" -d "C:\path\ghidra_12.0.4_PUBLIC"'
    Write-Host ""
    Write-Host "Optional parameters:"
    Write-Host '  -ProjectDir  "C:\ghidra-projects"'
    Write-Host '  -ProjectName "TestProject"'
    Write-Host '  -PostScript  "export_report.py"'
    Write-Host ""
}

if (-not $Command) {
    Write-Error "Missing command."
    Show-Usage
    exit 1
}

if (-not $FilePath) {
    Write-Error "Missing -f / -FilePath parameter."
    Show-Usage
    exit 1
}

if (-not $GhidraDir) {
    Write-Error "Missing -d / -GhidraDir parameter."
    Show-Usage
    exit 1
}

$ResolvedFilePath = (Resolve-Path $FilePath -ErrorAction SilentlyContinue).Path
if (-not $ResolvedFilePath) {
    Write-Error "Input file not found: $FilePath"
    exit 1
}

$ResolvedGhidraDir = (Resolve-Path $GhidraDir -ErrorAction SilentlyContinue).Path
if (-not $ResolvedGhidraDir) {
    Write-Error "Ghidra directory not found: $GhidraDir"
    exit 1
}

$PyGhidraRun = Join-Path $ResolvedGhidraDir "support\pyghidraRun.bat"
if (-not (Test-Path $PyGhidraRun)) {
    Write-Error "pyghidraRun.bat not found at: $PyGhidraRun"
    exit 1
}

if (-not (Test-Path $ProjectDir)) {
    New-Item -ItemType Directory -Path $ProjectDir | Out-Null
}

if (-not (Test-Path $ScriptPath)) {
    Write-Error "Script path not found: $ScriptPath"
    exit 1
}

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

if (Test-Path $OutputFile) {
    Remove-Item $OutputFile -Force
}

Write-Host "[*] Running Ghidra headless with PyGhidra..."
Write-Host "[*] Project root : $ProjectRoot"
Write-Host "[*] File         : $ResolvedFilePath"
Write-Host "[*] Ghidra dir   : $ResolvedGhidraDir"
Write-Host "[*] Project dir  : $ProjectDir"
Write-Host "[*] Script path  : $ScriptPath"
Write-Host "[*] Output dir   : $OutputDir"
Write-Host "[*] Post script  : $PostScript"
Write-Host ""

& $PyGhidraRun `
    -H `
    $ProjectDir `
    $ProjectName `
    "-import" $ResolvedFilePath `
    "-scriptPath" $ScriptPath `
    "-postScript" $PostScript $OutputDir `
    "-deleteProject"

$ExitCode = $LASTEXITCODE

Write-Host ""
Write-Host "[*] Ghidra exit code: $ExitCode"

if ($ExitCode -ne 0) {
    Write-Error "Ghidra execution failed."
    exit $ExitCode
}

if (-not (Test-Path $OutputFile)) {
    Write-Error "Execution ended, but report was not generated: $OutputFile"
    exit 2
}

Write-Host "[+] Report generated successfully: $OutputFile"