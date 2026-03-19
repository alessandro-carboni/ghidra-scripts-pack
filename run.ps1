param(
    [Parameter(Position = 0)]
    [ValidateSet("run", "fast", "report", "reports", "delete", "open", "markdown", "inspect", "diff", "state")]
    [string]$Command,

    [Alias("f")]
    [string]$FilePath,

    [Alias("d")]
    [string]$GhidraDir,

    [Alias("o")]
    [string]$OutputField,

    [string]$ProjectDir = "C:\ghidra-projects",
    [string]$ProjectName = "TriageProject",
    [string]$PostScript = "export_report.py",

    [switch]$Last,
    [switch]$All,

    [string]$Name,
    [string]$FunctionName,
    [string]$CapabilityName,
    [switch]$Packer,
    [switch]$Strings,
    [string]$LeftName,
    [string]$RightName,
    [string]$RuleDir
)

$ProjectRoot = $PSScriptRoot
$ScriptPath  = Join-Path $ProjectRoot "ghidra_scripts"
$OutputDir   = Join-Path $ProjectRoot "reports"
$OutputFile  = Join-Path $OutputDir "raw_report.json"
$StateFile   = Join-Path $ProjectRoot ".runstate.json"

function Show-Usage {
    Write-Host ""
    Write-Host "Usage examples:"
    Write-Host '  .\run.ps1 run -f ".\samples\sample.exe" -d "C:\path\ghidra_12.0.4_PUBLIC"'
    Write-Host '  .\run.ps1 run -f ".\samples\sample.exe" -d "C:\path\ghidra_12.0.4_PUBLIC" -RuleDir ".\rules"'
    Write-Host '  .\run.ps1 fast -d "C:\path\ghidra_version.x.y.z_PUBLIC"'
    Write-Host '  .\run.ps1 fast -RuleDir ".\rules"'
    Write-Host '  .\run.ps1 report -Last'
    Write-Host '  .\run.ps1 report -Last -o summary'
    Write-Host '  .\run.ps1 report -Last -o global_analysis'
    Write-Host '  .\run.ps1 report -Last -o function_analysis'
    Write-Host '  .\run.ps1 report -Last -o behavior_analysis'
    Write-Host '  .\run.ps1 report -Last -o binary_structure'
    Write-Host '  .\run.ps1 report -Last -o analyst_output'
    Write-Host '  .\run.ps1 report -Last -o capabilities'
    Write-Host '  .\run.ps1 report -Last -o top_functions'
    Write-Host '  .\run.ps1 report -Last -o packer_analysis'
    Write-Host '  .\run.ps1 reports'
    Write-Host '  .\run.ps1 inspect -Last -FunctionName FUN_401000'
    Write-Host '  .\run.ps1 inspect -Last -CapabilityName process_injection'
    Write-Host '  .\run.ps1 inspect -Last -Packer'
    Write-Host '  .\run.ps1 inspect -Last -Strings'
    Write-Host '  .\run.ps1 diff -LeftName report_old.json -RightName report_new.json'
    Write-Host '  .\run.ps1 state'
    Write-Host '  .\run.ps1 markdown -Last'
    Write-Host '  .\run.ps1 open -Last'
    Write-Host '  .\run.ps1 delete -Last'
    Write-Host '  .\run.ps1 delete -All'
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
    $Object | ConvertTo-Json -Depth 60
}

function Exit-InspectError([string]$Message) {
    Write-Error $Message
    exit 1
}

function Exit-DiffError([string]$Message) {
    Write-Error $Message
    exit 1
}

function Resolve-ReportPathByName([string]$ReportName) {
    if (-not $ReportName) {
        return $null
    }

    $fullPath = Join-Path $OutputDir $ReportName
    if (-not (Test-Path $fullPath)) {
        Exit-DiffError "Report not found: $fullPath"
    }

    return $fullPath
}

function Get-SafeArray($Value) {
    if ($null -eq $Value) {
        return @()
    }
    return @($Value)
}

function Get-NameList($Items) {
    $names = @()

    foreach ($item in (Get-SafeArray $Items)) {
        if ($null -eq $item) {
            continue
        }

        if ($item.PSObject.Properties["name"]) {
            $names += [string]$item.name
        }
        elseif ($item -is [string]) {
            $names += [string]$item
        }
    }

    return @($names | Sort-Object -Unique)
}

function Get-ValueList($Items, [string]$PropertyName) {
    $values = @()

    foreach ($item in (Get-SafeArray $Items)) {
        if ($null -eq $item) {
            continue
        }

        if ($item.PSObject.Properties[$PropertyName]) {
            $values += [string]$item.$PropertyName
        }
    }

    return @($values | Sort-Object -Unique)
}

function Compare-StringSets($LeftItems, $RightItems) {
    $left = Get-SafeArray $LeftItems
    $right = Get-SafeArray $RightItems

    $added = @($right | Where-Object { $_ -notin $left } | Sort-Object -Unique)
    $removed = @($left | Where-Object { $_ -notin $right } | Sort-Object -Unique)

    return [ordered]@{
        added   = $added
        removed = $removed
    }
}

function Save-State($State) {
    $State | ConvertTo-Json -Depth 20 | Set-Content -Path $StateFile -Encoding UTF8
}

function Load-State {
    if (-not (Test-Path $StateFile)) {
        return $null
    }

    try {
        return Get-Content $StateFile -Raw | ConvertFrom-Json
    }
    catch {
        Write-Error "Failed to read state file: $StateFile"
        return $null
    }
}

function Show-State {
    $state = Load-State
    if (-not $state) {
        Write-Host "[*] No saved state found."
        return
    }

    Write-PrettyJson $state
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

function Build-ReportName([string]$ResolvedFilePath) {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $sampleBase = [System.IO.Path]::GetFileNameWithoutExtension($ResolvedFilePath)
    return "${sampleBase}_${timestamp}.json"
}

function Finalize-Report([string]$ResolvedFilePath) {
    if (-not (Test-Path $OutputFile)) {
        Write-Error "Execution ended, but report was not generated: $OutputFile"
        exit 2
    }

    $finalReportName = Build-ReportName $ResolvedFilePath
    $finalReportPath = Join-Path $OutputDir $finalReportName

    Move-Item -Path $OutputFile -Destination $finalReportPath -Force
    return $finalReportPath
}

function Resolve-RuleDir {
    if ($RuleDir) {
        $resolved = (Resolve-Path $RuleDir -ErrorAction SilentlyContinue).Path
        if (-not $resolved) {
            Write-Error "Rule directory not found: $RuleDir"
            exit 1
        }
        return $resolved
    }

    $defaultRuleDir = Join-Path $ProjectRoot "rules"
    return $defaultRuleDir
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

    $ResolvedRuleDir = Resolve-RuleDir

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

    $ProgramName = [System.IO.Path]::GetFileName($ResolvedFilePath)

    Write-Host "[*] Running full analysis..."
    Write-Host "[*] File         : $ResolvedFilePath"
    Write-Host "[*] Program name : $ProgramName"
    Write-Host "[*] Ghidra dir   : $ResolvedGhidraDir"
    Write-Host "[*] Project dir  : $ProjectDir"
    Write-Host "[*] Project name : $ProjectName"
    Write-Host "[*] Script path  : $ScriptPath"
    Write-Host "[*] Rule dir     : $ResolvedRuleDir"
    Write-Host "[*] Output dir   : $OutputDir"
    Write-Host ""

    & $PyGhidraRun `
        -H `
        $ProjectDir `
        $ProjectName `
        "-import" $ResolvedFilePath `
        "-overwrite" `
        "-scriptPath" $ScriptPath `
        "-postScript" $PostScript $OutputDir $ResolvedRuleDir

    $ExitCode = $LASTEXITCODE

    Write-Host ""
    Write-Host "[*] Ghidra exit code: $ExitCode"

    if ($ExitCode -ne 0) {
        Write-Error "Ghidra execution failed."
        exit $ExitCode
    }

    $finalReportPath = Finalize-Report $ResolvedFilePath

    Save-State @{
        ghidra_dir      = $ResolvedGhidraDir
        project_dir     = $ProjectDir
        project_name    = $ProjectName
        post_script     = $PostScript
        script_path     = $ScriptPath
        rule_dir        = $ResolvedRuleDir
        output_dir      = $OutputDir
        last_file_path  = $ResolvedFilePath
        last_program    = $ProgramName
        last_report     = $finalReportPath
        updated_at      = (Get-Date).ToString("o")
    }

    Write-Host "[+] Report generated successfully: $finalReportPath"
}

function Run-Fast {
    $state = Load-State
    if (-not $state) {
        Write-Error "No saved state found. Run a full analysis first."
        exit 1
    }

    if ($GhidraDir) {
        $ResolvedGhidraDir = (Resolve-Path $GhidraDir -ErrorAction SilentlyContinue).Path
        if (-not $ResolvedGhidraDir) {
            Write-Error "Ghidra directory not found: $GhidraDir"
            exit 1
        }
    }
    else {
        $ResolvedGhidraDir = $state.ghidra_dir
    }

    if ($RuleDir) {
        $ResolvedRuleDir = (Resolve-Path $RuleDir -ErrorAction SilentlyContinue).Path
        if (-not $ResolvedRuleDir) {
            Write-Error "Rule directory not found: $RuleDir"
            exit 1
        }
    }
    elseif ($state.rule_dir) {
        $ResolvedRuleDir = $state.rule_dir
    }
    else {
        $ResolvedRuleDir = Join-Path $ProjectRoot "rules"
    }

    $SavedProjectDir   = $state.project_dir
    $SavedProjectName  = $state.project_name
    $SavedProgramName  = $state.last_program
    $SavedFilePath     = $state.last_file_path
    $SavedPostScript   = $state.post_script
    $SavedScriptPath   = $state.script_path

    if (-not $ResolvedGhidraDir) {
        Write-Error "Missing Ghidra directory in saved state. Run a full analysis first or pass -d."
        exit 1
    }

    $PyGhidraRun = Join-Path $ResolvedGhidraDir "support\pyghidraRun.bat"
    if (-not (Test-Path $PyGhidraRun)) {
        Write-Error "pyghidraRun.bat not found at: $PyGhidraRun"
        Write-Host "Tip: run a full analysis with -d or use: .\run.ps1 fast -d `"<ghidra_dir>`""
        exit 1
    }

    Ensure-OutputDir

    if (Test-Path $OutputFile) {
        Remove-Item $OutputFile -Force
    }

    Write-Host "[*] Running FAST mode (reuse analyzed project, no re-analysis)..."
    Write-Host "[*] Program name : $SavedProgramName"
    Write-Host "[*] Ghidra dir   : $ResolvedGhidraDir"
    Write-Host "[*] Project dir  : $SavedProjectDir"
    Write-Host "[*] Project name : $SavedProjectName"
    Write-Host "[*] Rule dir     : $ResolvedRuleDir"
    Write-Host ""

    & $PyGhidraRun `
        -H `
        $SavedProjectDir `
        $SavedProjectName `
        "-process" $SavedProgramName `
        "-noanalysis" `
        "-scriptPath" $SavedScriptPath `
        "-postScript" $SavedPostScript $OutputDir $ResolvedRuleDir

    $ExitCode = $LASTEXITCODE

    Write-Host ""
    Write-Host "[*] Ghidra exit code: $ExitCode"

    if ($ExitCode -ne 0) {
        Write-Error "FAST execution failed."
        exit $ExitCode
    }

    $finalReportPath = Finalize-Report $SavedFilePath

    $state.ghidra_dir   = $ResolvedGhidraDir
    $state.rule_dir     = $ResolvedRuleDir
    $state.last_report  = $finalReportPath
    $state.updated_at   = (Get-Date).ToString("o")
    Save-State $state

    Write-Host "[+] Fast report generated successfully: $finalReportPath"
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

    $fieldMap = @{
        "analysis_metadata"         = $report.analysis_metadata
        "sample"                    = $report.sample
        "summary"                   = $report.summary

        "global_analysis"           = $report.global_analysis
        "external_symbols"          = $report.global_analysis.external_symbols
        "suspicious_apis"           = $report.global_analysis.suspicious_apis
        "capabilities"              = $report.global_analysis.capabilities
        "interesting_strings"       = $report.global_analysis.interesting_strings
        "strings"                   = $report.global_analysis.strings
        "benign_contexts"           = $report.global_analysis.benign_contexts
        "score_adjustments"         = $report.global_analysis.score_adjustments

        "function_analysis"         = $report.function_analysis
        "functions"                 = $report.function_analysis.functions
        "top_functions"             = $report.function_analysis.top_functions
        "function_role_summary"     = $report.function_analysis.function_role_summary

        "behavior_analysis"         = $report.behavior_analysis
        "callgraph"                 = $report.behavior_analysis.callgraph
        "behavior_clusters"         = $report.behavior_analysis.behavior_clusters
        "execution_flow_hypotheses" = $report.behavior_analysis.execution_flow_hypotheses
        "three_hop_flows"           = $report.behavior_analysis.three_hop_flows
        "behavior_summary"          = $report.behavior_analysis.behavior_summary
        "behavior_story"            = $report.behavior_analysis.behavior_story

        "binary_structure"          = $report.binary_structure
        "packer_analysis"           = $report.binary_structure.packer_analysis
        "entrypoint_info"           = $report.binary_structure.entrypoint_info
        "entrypoint_window"         = $report.binary_structure.entrypoint_window
        "oep_candidates"            = $report.binary_structure.oep_candidates
        "section_info"              = $report.binary_structure.section_info

        "analyst_output"            = $report.analyst_output
        "analyst_summary"           = $report.analyst_output.analyst_summary
        "analyst_targets"           = $report.analyst_output.analyst_targets
        "analyst_playbook"          = $report.analyst_output.analyst_playbook
    }

    $allowedFields = $fieldMap.Keys | Sort-Object

    if (-not $fieldMap.ContainsKey($OutputField)) {
        Write-Error "Unsupported output field: $OutputField"
        Write-Host "Allowed fields: $($allowedFields -join ', ')"
        exit 1
    }

    $selected = $fieldMap[$OutputField]
    Write-PrettyJson $selected
}

function Inspect-Report {
    $reportPath = Resolve-RequestedReport
    $report = Read-JsonFile $reportPath

    Write-Host "[*] Report file: $reportPath"
    Write-Host ""

    $modeCount = 0
    if ($FunctionName) { $modeCount++ }
    if ($CapabilityName) { $modeCount++ }
    if ($Packer) { $modeCount++ }
    if ($Strings) { $modeCount++ }

    if ($modeCount -eq 0) {
        Exit-InspectError "Specify one inspect target: -FunctionName, -CapabilityName, -Packer, or -Strings"
    }

    if ($modeCount -gt 1) {
        Exit-InspectError "Use only one inspect target at a time"
    }

    if ($FunctionName) {
        $functions = $report.function_analysis.functions
        if (-not $functions) {
            Exit-InspectError "No function analysis found in report"
        }

        $match = $functions | Where-Object { $_.name -eq $FunctionName } | Select-Object -First 1
        if (-not $match) {
            Exit-InspectError "Function not found: $FunctionName"
        }

        $result = [ordered]@{
            inspect_type         = "function"
            name                 = $match.name
            entry                = $match.entry
            score                = $match.score
            risk_level           = $match.risk_level
            structure_role       = $match.structure_role
            roles                = $match.roles
            tags                 = $match.tags
            matched_capabilities = $match.matched_capabilities
            local_api_hits       = $match.local_api_hits
            external_calls       = $match.external_calls
            internal_calls       = $match.internal_calls
            incoming_calls       = $match.incoming_calls
            referenced_strings   = $match.referenced_strings
            score_breakdown      = $match.score_breakdown
        }

        Write-PrettyJson $result
        return
    }

    if ($CapabilityName) {
        if (-not $report.global_analysis) {
            Exit-InspectError "No global_analysis section found in report"
        }

        $capabilities = @()
        if ($null -ne $report.global_analysis.capabilities) {
            $capabilities = @($report.global_analysis.capabilities)
        }

        $functions = @()
        if ($report.function_analysis -and $null -ne $report.function_analysis.functions) {
            $functions = @($report.function_analysis.functions)
        }

        $capability = $capabilities | Where-Object { $_.name -eq $CapabilityName } | Select-Object -First 1
        if (-not $capability) {
            $capability = $null
        }

        $relatedFunctions = @()
        if ($functions.Count -gt 0) {
            $relatedFunctions = @(
                $functions |
                    Where-Object {
                        ($_.matched_capabilities -contains $CapabilityName) -or
                        ($_.tags -contains $CapabilityName) -or
                        ($_.roles -contains $CapabilityName) -or
                        (($CapabilityName -eq "networking") -and ($_.roles -contains "network")) -or
                        (($CapabilityName -eq "process_injection") -and ($_.roles -contains "injection")) -or
                        (($CapabilityName -eq "dynamic_loading") -and ($_.roles -contains "loader"))
                    } |
                    Sort-Object @{Expression="score";Descending=$true}, @{Expression="name";Descending=$false} |
                    Select-Object -First 12
            )
        }

        if (-not $capability -and $relatedFunctions.Count -eq 0) {
            Exit-InspectError "Capability not found and no related functions matched: $CapabilityName"
        }

        $result = [ordered]@{
            inspect_type                        = "capability"
            requested_capability                = $CapabilityName
            capability_found_in_global_analysis = ($null -ne $capability)
            capability                          = $capability
            related_function_count              = $relatedFunctions.Count
            related_functions                   = @(
                $relatedFunctions | ForEach-Object {
                    [ordered]@{
                        name                 = $_.name
                        entry                = $_.entry
                        score                = $_.score
                        risk_level           = $_.risk_level
                        structure_role       = $_.structure_role
                        roles                = $_.roles
                        tags                 = $_.tags
                        matched_capabilities = $_.matched_capabilities
                        local_api_hits       = $_.local_api_hits
                    }
                }
            )
        }

        Write-PrettyJson $result
        return
    }

    if ($Packer) {
        if (-not $report.binary_structure -or -not $report.binary_structure.packer_analysis) {
            Exit-InspectError "No packer analysis found in report"
        }

        $result = [ordered]@{
            inspect_type    = "packer"
            packer_analysis = $report.binary_structure.packer_analysis
            entrypoint_info = $report.binary_structure.entrypoint_info
            oep_candidates  = $report.binary_structure.oep_candidates
            section_info    = $report.binary_structure.section_info
        }

        Write-PrettyJson $result
        return
    }

    if ($Strings) {
        $interestingStrings = $report.global_analysis.interesting_strings
        if (-not $interestingStrings) {
            Exit-InspectError "No interesting strings found in report"
        }

        $result = [ordered]@{
            inspect_type = "interesting_strings"
            count        = @($interestingStrings).Count
            items        = $interestingStrings
        }

        Write-PrettyJson $result
        return
    }
}

function Diff-Reports {
    if (-not $LeftName -or -not $RightName) {
        Exit-DiffError "Specify both -LeftName and -RightName"
    }

    $leftPath = Resolve-ReportPathByName $LeftName
    $rightPath = Resolve-ReportPathByName $RightName

    $leftReport = Read-JsonFile $leftPath
    $rightReport = Read-JsonFile $rightPath

    $leftSummary = $leftReport.summary
    $rightSummary = $rightReport.summary

    $leftCapabilities = Get-NameList $leftReport.global_analysis.capabilities
    $rightCapabilities = Get-NameList $rightReport.global_analysis.capabilities

    $leftTopFunctions = Get-NameList $leftReport.function_analysis.top_functions
    $rightTopFunctions = Get-NameList $rightReport.function_analysis.top_functions

    $leftStrings = Get-ValueList $leftReport.global_analysis.interesting_strings "value"
    $rightStrings = Get-ValueList $rightReport.global_analysis.interesting_strings "value"

    $leftPacker = $leftReport.binary_structure.packer_analysis
    $rightPacker = $rightReport.binary_structure.packer_analysis

    $result = [ordered]@{
        inspect_type = "report_diff"
        left_report = [ordered]@{
            name        = [System.IO.Path]::GetFileName($leftPath)
            sample_name = $leftReport.sample.name
        }
        right_report = [ordered]@{
            name        = [System.IO.Path]::GetFileName($rightPath)
            sample_name = $rightReport.sample.name
        }
        summary_diff = [ordered]@{
            left_risk_level                = $leftSummary.risk_level
            right_risk_level               = $rightSummary.risk_level
            left_overall_score             = [int]$leftSummary.overall_score
            right_overall_score            = [int]$rightSummary.overall_score
            overall_score_delta            = ([int]$rightSummary.overall_score - [int]$leftSummary.overall_score)
            left_raw_score                 = [int]$leftSummary.raw_score
            right_raw_score                = [int]$rightSummary.raw_score
            raw_score_delta                = ([int]$rightSummary.raw_score - [int]$leftSummary.raw_score)
            left_capability_count          = [int]$leftSummary.capability_count
            right_capability_count         = [int]$rightSummary.capability_count
            capability_count_delta         = ([int]$rightSummary.capability_count - [int]$leftSummary.capability_count)
            left_suspicious_api_count      = [int]$leftSummary.suspicious_api_count
            right_suspicious_api_count     = [int]$rightSummary.suspicious_api_count
            suspicious_api_count_delta     = ([int]$rightSummary.suspicious_api_count - [int]$leftSummary.suspicious_api_count)
            left_interesting_string_count  = [int]$leftSummary.interesting_string_count
            right_interesting_string_count = [int]$rightSummary.interesting_string_count
            interesting_string_count_delta = ([int]$rightSummary.interesting_string_count - [int]$leftSummary.interesting_string_count)
        }
        capability_diff = Compare-StringSets $leftCapabilities $rightCapabilities
        top_function_diff = Compare-StringSets $leftTopFunctions $rightTopFunctions
        interesting_string_diff = Compare-StringSets $leftStrings $rightStrings
        packer_diff = [ordered]@{
            left_likely_packed           = $leftPacker.likely_packed
            right_likely_packed          = $rightPacker.likely_packed
            left_packed_likelihood_score = [int]$leftPacker.packed_likelihood_score
            right_packed_likelihood_score = [int]$rightPacker.packed_likelihood_score
            packed_likelihood_score_delta = ([int]$rightPacker.packed_likelihood_score - [int]$leftPacker.packed_likelihood_score)
            left_family_hint             = $leftPacker.packer_family_hint
            right_family_hint            = $rightPacker.packer_family_hint
        }
    }

    Write-Host "[*] Left report : $leftPath"
    Write-Host "[*] Right report: $rightPath"
    Write-Host ""

    Write-PrettyJson $result
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
        Get-ChildItem -Path $OutputDir -File -Filter "*.md" | Remove-Item -Force
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

        $mdCandidate = [System.IO.Path]::ChangeExtension($lastFile.FullName, ".md")
        if (Test-Path $mdCandidate) {
            Remove-Item $mdCandidate -Force
        }

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

        $mdCandidate = [System.IO.Path]::ChangeExtension($namedPath, ".md")
        if (Test-Path $mdCandidate) {
            Remove-Item $mdCandidate -Force
        }

        Write-Host "[+] Deleted report: $Name"
        return
    }

    Write-Error "Specify one of: -All, -Last, -Name <file>"
    exit 1
}

function New-MarkdownReport {
    $reportPath = Resolve-RequestedReport
    $report = Read-JsonFile $reportPath

    $sampleName = $report.sample.name
    $samplePath = $report.sample.path
    $sampleFormat = $report.sample.format
    $summary = $report.summary

    $capabilities = $report.global_analysis.capabilities
    $suspiciousApis = $report.global_analysis.suspicious_apis
    $interestingStrings = $report.global_analysis.interesting_strings

    $analystSummary = $report.analyst_output.analyst_summary
    $analystTargets = $report.analyst_output.analyst_targets

    $mdPath = [System.IO.Path]::ChangeExtension($reportPath, ".md")

    $lines = New-Object System.Collections.Generic.List[string]

    $lines.Add("# Malware Triage Report")
    $lines.Add("")
    $lines.Add("## Sample")
    $lines.Add("")
    $lines.Add("- **Name:** $sampleName")
    $lines.Add("- **Path:** $samplePath")
    $lines.Add("- **Format:** $sampleFormat")
    $lines.Add("")

    if ($report.analysis_metadata) {
        $lines.Add("## Analysis Metadata")
        $lines.Add("")
        $lines.Add("- **Schema version:** $($report.analysis_metadata.schema_version)")
        $lines.Add("- **Analysis mode:** $($report.analysis_metadata.analysis_mode)")
        if ($report.analysis_metadata.rules_metadata) {
            $lines.Add("- **Rules dir:** $($report.analysis_metadata.rules_metadata.rules_dir)")
        }
        $lines.Add("")
    }

    $lines.Add("## Summary")
    $lines.Add("")
    $lines.Add("- **Risk level:** $($summary.risk_level)")
    $lines.Add("- **Overall score:** $($summary.overall_score)")
    $lines.Add("- **Raw score:** $($summary.raw_score)")
    $lines.Add("- **Adjustment total:** $($summary.score_adjustment_total)")
    $lines.Add("- **Contract version:** $($summary.contract_version)")
    $lines.Add("")

    if ($summary.packed_warning) {
        $lines.Add("> $($summary.packed_warning)")
        $lines.Add("")
    }

    if ($analystSummary) {
        $lines.Add("## Analyst Summary")
        $lines.Add("")

        if ($analystSummary.key_points) {
            foreach ($line in $analystSummary.key_points) {
                $lines.Add("- $line")
            }
        }

        $lines.Add("")
    }

    $lines.Add("## Top Indicators")
    $lines.Add("")
    foreach ($indicator in $summary.top_indicators) {
        $lines.Add("- $indicator")
    }

    $lines.Add("")
    $lines.Add("## Capabilities")
    $lines.Add("")

    if (-not $capabilities -or @($capabilities).Count -eq 0) {
        $lines.Add("- None detected")
    }
    else {
        foreach ($cap in $capabilities) {
            $lines.Add("- **$($cap.name)** (+$($cap.score))")
            $lines.Add("  - Confidence: $($cap.confidence)")
            $lines.Add("  - Matched APIs: $($cap.matched_apis -join ', ')")
        }
    }

    $lines.Add("")
    $lines.Add("## Top Suspicious APIs")
    $lines.Add("")

    if (-not $suspiciousApis -or @($suspiciousApis).Count -eq 0) {
        $lines.Add("- None detected")
    }
    else {
        foreach ($api in ($suspiciousApis | Select-Object -First 15)) {
            $lines.Add("- **$($api.name)** (+$($api.weight))")
            if ($api.variants -and @($api.variants).Count -gt 0) {
                $lines.Add("  - Variants: $($api.variants -join ', ')")
            }
        }
    }

    $lines.Add("")
    $lines.Add("## Top Interesting Strings")
    $lines.Add("")

    if (-not $interestingStrings -or @($interestingStrings).Count -eq 0) {
        $lines.Add("- None detected")
    }
    else {
        foreach ($item in ($interestingStrings | Select-Object -First 10)) {
            $lines.Add("- **$($item.value)** (+$($item.score))")
            $lines.Add("  - Tags: $($item.tags -join ', ')")
            if ($item.benign_hint -eq $true) {
                $lines.Add("  - Benign hint: true")
            }
        }
    }

    if ($analystTargets) {
        $lines.Add("")
        $lines.Add("## Analyst Targets")
        $lines.Add("")
        foreach ($target in $analystTargets) {
            $lines.Add("- **$($target.name)** @ $($target.entry)")
            $lines.Add("  - Score: $($target.score) | Risk: $($target.risk_level)")
            $lines.Add("  - Why: $($target.why)")
            $lines.Add("  - What to check: $($target.what_to_check)")
        }
    }

    if ($report.binary_structure -and $report.binary_structure.packer_analysis) {
        $packer = $report.binary_structure.packer_analysis

        $lines.Add("")
        $lines.Add("## Packer Analysis")
        $lines.Add("")
        $lines.Add("- **Likely packed:** $($packer.likely_packed)")
        $lines.Add("- **Packed likelihood score:** $($packer.packed_likelihood_score)")
        if ($packer.confidence) {
            $lines.Add("- **Confidence:** $($packer.confidence)")
        }
        if ($packer.packer_family_hint) {
            $lines.Add("- **Family hint:** $($packer.packer_family_hint)")
        }
    }

    Set-Content -Path $mdPath -Value $lines -Encoding UTF8
    Write-Host "[+] Markdown report generated: $mdPath"
}

if (-not $Command) {
    Show-Usage
    exit 1
}

switch ($Command) {
    "run"      { Run-Analysis }
    "fast"     { Run-Fast }
    "report"   { Show-Report }
    "reports"  { List-Reports }
    "inspect"  { Inspect-Report }
    "diff"     { Diff-Reports }
    "state"    { Show-State }
    "open"     { Open-Report }
    "delete"   { Delete-Reports }
    "markdown" { New-MarkdownReport }
    default    {
        Show-Usage
        exit 1
    }
}