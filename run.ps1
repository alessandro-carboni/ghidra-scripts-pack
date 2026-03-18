param(
    [Parameter(Position = 0)]
    [ValidateSet("run", "report", "reports", "delete", "open")]
    [string]$Command,

    [Alias("f")]
    [string]$FilePath,

    [Alias("d")]
    [string]$GhidraDir,

    [Alias("o")]
    [string]$OutputField,

    [string]$ProjectDir = "C:\ghidra-projects",
    [string]$ProjectName = "TestProject",
    [string]$PostScript = "export_report.py",

    [switch]$Last,
    [switch]$All,

    [string]$Name
)

$ProjectRoot = $PSScriptRoot
$ScriptPath  = Join-Path $ProjectRoot "ghidra_scripts"
$OutputDir   = Join-Path $ProjectRoot "reports"
$OutputFile  = Join-Path $OutputDir "raw_report.json"

function Show-Usage {
    Write-Host ""
    Write-Host "Usage examples:"
    Write-Host '  .\run.ps1 run -f ".\samples\sample.exe" -d "C:\path\ghidra_12.0.4_PUBLIC"'
    Write-Host '  .\run.ps1 report -Last'
    Write-Host '  .\run.ps1 report -Last -o summary'
    Write-Host '  .\run.ps1 report -Last -o functions'
    Write-Host '  .\run.ps1 reports'
    Write-Host '  .\run.ps1 open -Last'
    Write-Host '  .\run.ps1 delete -Last'
    Write-Host '  .\run.ps1 delete -All'
    Write-Host '  .\run.ps1 delete -Name "raw_report.json"'
    Write-Host ""
}

function Ensure-OutputDir {
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir | Out-Null
    }
}

function Get-ReportFiles {
    Ensure-OutputDir
    Get-ChildItem -Path $OutputDir -File -Filter "*.json" | Sort-Object LastWriteTime
}

function Get-LastReportFile {
    $files = Get-ReportFiles
    if (-not $files -or $files.Count -eq 0) {
        return $null
    }
    return $files[-1]
}

function Read-JsonFile([string]$Path) {
    Get-Content $Path -Raw | ConvertFrom-Json
}

function Write-PrettyJson($Object) {
    $Object | ConvertTo-Json -Depth 20
}

function Resolve-RequestedReport {
    if ($Last) {
        $lastFile = Get-LastReportFile
        if (-not $lastFile) {
            Write-Error "No report files found in $OutputDir"
            exit 1
        }
        return $lastFile.FullName
    }

    if ($Name) {
        $namedPath = Join-Path $OutputDir $Name
        if (-not (Test-Path $namedPath)) {
            Write-Error "Report not found: $namedPath"
            exit 1
        }
        return $namedPath
    }

    $defaultPath = Join-Path $OutputDir "raw_report.json"
    if (Test-Path $defaultPath) {
        return $defaultPath
    }

    $fallback = Get-LastReportFile
    if ($fallback) {
        return $fallback.FullName
    }

    Write-Error "No report found."
    exit 1
}

function Run-Analysis {
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

    Ensure-OutputDir

    if (Test-Path $OutputFile) {
        Remove-Item $OutputFile -Force
    }

    Write-Host "[*] Running Ghidra headless with PyGhidra..."
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

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $sampleBase = [System.IO.Path]::GetFileNameWithoutExtension($ResolvedFilePath)
    $finalReportName = "${sampleBase}_${timestamp}.json"
    $finalReportPath = Join-Path $OutputDir $finalReportName

    Move-Item -Path $OutputFile -Destination $finalReportPath -Force

    Write-Host "[+] Report generated successfully: $finalReportPath"
}

function Show-Report {
    $reportPath = Resolve-RequestedReport
    $report = Read-JsonFile $reportPath

    Write-Host "[*] Report file: $reportPath"
    Write-Host ""

    if (-not $OutputField) {
        Write-PrettyJson $report
        return
    }

    $allowedFields = @("sample", "summary", "external_symbols", "suspicious_apis", "capabilities", "strings", "functions")
    if ($allowedFields -notcontains $OutputField) {
        Write-Error "Unsupported output field: $OutputField"
        Write-Host "Allowed fields: $($allowedFields -join ', ')"
        exit 1
    }

    $selected = $report.$OutputField
    Write-PrettyJson $selected
}

function List-Reports {
    $files = Get-ReportFiles

    if (-not $files -or $files.Count -eq 0) {
        Write-Host "[*] No reports found."
        return
    }

    $files |
        Select-Object Name, LastWriteTime, Length |
        Format-Table -AutoSize
}

function Open-Report {
    $reportPath = Resolve-RequestedReport
    Invoke-Item $reportPath
}

function Delete-Reports {
    Ensure-OutputDir

    if ($All) {
        Get-ChildItem -Path $OutputDir -File -Filter "*.json" | Remove-Item -Force
        Write-Host "[+] All reports deleted."
        return
    }

    if ($Last) {
        $lastFile = Get-LastReportFile
        if (-not $lastFile) {
            Write-Error "No report files found."
            exit 1
        }
        Remove-Item $lastFile.FullName -Force
        Write-Host "[+] Deleted last report: $($lastFile.Name)"
        return
    }

    if ($Name) {
        $namedPath = Join-Path $OutputDir $Name
        if (-not (Test-Path $namedPath)) {
            Write-Error "Report not found: $namedPath"
            exit 1
        }
        Remove-Item $namedPath -Force
        Write-Host "[+] Deleted report: $Name"
        return
    }

    Write-Error "Specify one of: -All, -Last, -Name <file>"
    exit 1
}

if (-not $Command) {
    Show-Usage
    exit 1
}

switch ($Command) {
    "run"    { Run-Analysis }
    "report" { Show-Report }
    "reports"{ List-Reports }
    "open"   { Open-Report }
    "delete" { Delete-Reports }
    default  {
        Show-Usage
        exit 1
    }
}