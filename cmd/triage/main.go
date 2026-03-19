package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"ghidra-malware-triage/internal/config"
	"ghidra-malware-triage/internal/report"
	"ghidra-malware-triage/internal/runner"
	"ghidra-malware-triage/internal/state"
)

func main() {
	if len(os.Args) < 2 {
		showUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "scan":
		runScan(os.Args[2:])
	case "fast":
		runFast(os.Args[2:])
	case "report":
		runReport(os.Args[2:])
	case "reports":
		runReports(os.Args[2:])
	case "inspect":
		runInspect(os.Args[2:])
	case "diff":
		runDiff(os.Args[2:])
	case "state":
		runState(os.Args[2:])
	case "open":
		runOpen(os.Args[2:])
	case "delete":
		runDelete(os.Args[2:])
	case "markdown":
		runMarkdown(os.Args[2:])
	default:
		showUsage()
		os.Exit(1)
	}
}

func showUsage() {
	fmt.Println("")
	fmt.Println("Usage examples:")
	fmt.Println(`  triage scan -input .\samples\sample.exe -ghidra-dir C:\path\ghidra_12.0.4_PUBLIC`)
	fmt.Println(`  triage scan -input .\samples\sample.exe -ghidra-dir C:\path\ghidra_12.0.4_PUBLIC -rule-dir .\rules`)
	fmt.Println(`  triage scan -input .\samples\sample.exe -ghidra-dir C:\path\ghidra_12.0.4_PUBLIC -rust-engine .\rust_engine\target\debug\rust_engine.exe`)
	fmt.Println(`  triage fast -ghidra-dir C:\path\ghidra_12.0.4_PUBLIC`)
	fmt.Println(`  triage fast -rule-dir .\rules`)
	fmt.Println(`  triage report -last`)
	fmt.Println(`  triage report -last -o summary`)
	fmt.Println(`  triage report -last -o rust_enrichment`)
	fmt.Println(`  triage reports`)
	fmt.Println(`  triage inspect -last -function FUN_401000`)
	fmt.Println(`  triage inspect -last -capability process_injection`)
	fmt.Println(`  triage inspect -last -packer`)
	fmt.Println(`  triage inspect -last -strings`)
	fmt.Println(`  triage inspect -last -rust`)
	fmt.Println(`  triage diff -left report_old.json -right report_new.json`)
	fmt.Println(`  triage state`)
	fmt.Println(`  triage markdown -last`)
	fmt.Println(`  triage open -last`)
	fmt.Println(`  triage delete -last`)
	fmt.Println(`  triage delete -all`)
	fmt.Println("")
}

func buildConfigAndProjectRoot(
	ghidraDir, projectDir, projectName, scriptPath, postScript, ruleDir, outputDir, rustEnginePath string,
) (config.Config, string, error) {
	projectRoot, err := config.ProjectRootFromWD()
	if err != nil {
		return config.Config{}, "", err
	}

	cfg := config.Default(projectRoot)
	cfg.ApplyOverrides(
		ghidraDir,
		projectDir,
		projectName,
		scriptPath,
		postScript,
		ruleDir,
		outputDir,
		rustEnginePath,
	)

	return cfg, projectRoot, nil
}

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)

	input := fs.String("input", "", "input file or directory")
	ghidraDir := fs.String("ghidra-dir", "", "ghidra installation directory")
	projectDir := fs.String("project-dir", `C:\ghidra-projects`, "ghidra project directory")
	projectName := fs.String("project-name", "TriageProject", "ghidra project name")
	scriptPath := fs.String("script-path", "", "ghidra script path")
	postScript := fs.String("post-script", "export_report.py", "post script file name")
	ruleDir := fs.String("rule-dir", "", "rule directory")
	outputDir := fs.String("output-dir", "", "output/report directory")
	rustEnginePath := fs.String("rust-engine", "", "rust engine executable path")

	_ = fs.Parse(args)

	if *input == "" {
		fmt.Fprintln(os.Stderr, "missing -input")
		os.Exit(1)
	}
	if *ghidraDir == "" {
		fmt.Fprintln(os.Stderr, "missing -ghidra-dir")
		os.Exit(1)
	}

	cfg, projectRoot, err := buildConfigAndProjectRoot(
		*ghidraDir, *projectDir, *projectName, *scriptPath, *postScript, *ruleDir, *outputDir, *rustEnginePath,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build config: %v\n", err)
		os.Exit(1)
	}

	if err := cfg.ValidateForScan(); err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	if err := config.EnsureDirs(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "ensure dirs: %v\n", err)
		os.Exit(1)
	}

	if err := runner.EnsureExecutablePaths(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "path validation failed: %v\n", err)
		os.Exit(1)
	}

	inputs, err := runner.CollectInputs(*input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "collect inputs: %v\n", err)
		os.Exit(1)
	}

	if len(inputs) == 0 {
		fmt.Fprintln(os.Stderr, "no input files found")
		os.Exit(1)
	}

	fmt.Printf("[*] Batch size: %d\n", len(inputs))

	failures := 0
	for _, inputPath := range inputs {
		fmt.Println("")
		fmt.Printf("[*] Scanning: %s\n", inputPath)

		result, err := runner.ScanFile(cfg, inputPath)
		if err != nil {
			failures++
			fmt.Fprintf(os.Stderr, "[!] Scan failed for %s: %v\n", inputPath, err)
			continue
		}

		if err := runner.SaveStateFromScan(projectRoot, cfg, result); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Save state warning: %v\n", err)
		}

		fmt.Printf("[+] Raw report: %s\n", result.RawReportPath)
		fmt.Printf("[+] Enriched report: %s\n", result.EnrichedReportPath)

		rep, err := report.Load(result.FinalReportPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Report load failed for %s: %v\n", result.FinalReportPath, err)
			continue
		}

		fmt.Printf("[+] Summary: sample=%s risk=%s score=%d capabilities=%d suspicious_apis=%d\n",
			rep.Sample.Name,
			rep.Summary.RiskLevel,
			rep.Summary.OverallScore,
			rep.Summary.CapabilityCount,
			rep.Summary.SuspiciousAPICount,
		)
	}

	if failures > 0 {
		os.Exit(2)
	}
}

func runFast(args []string) {
	fs := flag.NewFlagSet("fast", flag.ExitOnError)

	ghidraDir := fs.String("ghidra-dir", "", "ghidra installation directory")
	projectDir := fs.String("project-dir", "", "ghidra project directory")
	projectName := fs.String("project-name", "", "ghidra project name")
	scriptPath := fs.String("script-path", "", "ghidra script path")
	postScript := fs.String("post-script", "", "post script file name")
	ruleDir := fs.String("rule-dir", "", "rule directory")
	outputDir := fs.String("output-dir", "", "output/report directory")
	rustEnginePath := fs.String("rust-engine", "", "rust engine executable path")

	_ = fs.Parse(args)

	projectRoot, err := config.ProjectRootFromWD()
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve project root: %v\n", err)
		os.Exit(1)
	}

	st, err := state.Load(projectRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load state: %v\n", err)
		os.Exit(1)
	}
	if st == nil {
		fmt.Fprintln(os.Stderr, "no saved state found; run a full scan first")
		os.Exit(1)
	}

	resolvedGhidraDir := st.GhidraDir
	if *ghidraDir != "" {
		resolvedGhidraDir = *ghidraDir
	}

	resolvedProjectDir := st.ProjectDir
	if *projectDir != "" {
		resolvedProjectDir = *projectDir
	}

	resolvedProjectName := st.ProjectName
	if *projectName != "" {
		resolvedProjectName = *projectName
	}

	resolvedScriptPath := st.ScriptPath
	if *scriptPath != "" {
		resolvedScriptPath = *scriptPath
	}

	resolvedPostScript := st.PostScript
	if *postScript != "" {
		resolvedPostScript = *postScript
	}

	resolvedRuleDir := st.RuleDir
	if *ruleDir != "" {
		resolvedRuleDir = *ruleDir
	}

	resolvedOutputDir := st.OutputDir
	if *outputDir != "" {
		resolvedOutputDir = *outputDir
	}

	resolvedRustEnginePath := st.RustEnginePath
	if *rustEnginePath != "" {
		resolvedRustEnginePath = *rustEnginePath
	}

	cfg, _, err := buildConfigAndProjectRoot(
		resolvedGhidraDir,
		resolvedProjectDir,
		resolvedProjectName,
		resolvedScriptPath,
		resolvedPostScript,
		resolvedRuleDir,
		resolvedOutputDir,
		resolvedRustEnginePath,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build config: %v\n", err)
		os.Exit(1)
	}

	if err := cfg.ValidateForScan(); err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	if err := config.EnsureDirs(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "ensure dirs: %v\n", err)
		os.Exit(1)
	}

	if err := runner.EnsureExecutablePaths(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "path validation failed: %v\n", err)
		os.Exit(1)
	}

	result, err := runner.FastScan(cfg, *st)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fast scan failed: %v\n", err)
		os.Exit(1)
	}

	if err := runner.SaveStateAfterFast(projectRoot, *st, cfg, result); err != nil {
		fmt.Fprintf(os.Stderr, "save state warning: %v\n", err)
	}

	fmt.Printf("[+] Raw report: %s\n", result.RawReportPath)
	fmt.Printf("[+] Enriched report: %s\n", result.EnrichedReportPath)
}

func runReport(args []string) {
	fs := flag.NewFlagSet("report", flag.ExitOnError)

	last := fs.Bool("last", false, "use last report")
	name := fs.String("name", "", "report file name")
	outputField := fs.String("o", "", "output field alias")
	reportsDir := fs.String("reports-dir", ".\\reports", "reports directory")

	_ = fs.Parse(args)

	reportPath, err := report.ResolveReportPath(*reportsDir, *name, *last)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	raw, err := report.LoadRaw(reportPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load report: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[*] Report file: %s\n\n", reportPath)

	if *outputField == "" {
		fmt.Println(report.Pretty(raw))
		return
	}

	selected, allowed, err := report.SelectOutputField(raw, *outputField)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		fmt.Fprintf(os.Stderr, "Allowed fields: %v\n", allowed)
		os.Exit(1)
	}

	fmt.Println(report.Pretty(selected))
}

func runReports(args []string) {
	fs := flag.NewFlagSet("reports", flag.ExitOnError)
	reportsDir := fs.String("reports-dir", ".\\reports", "reports directory")
	_ = fs.Parse(args)

	infos, err := report.ListReportInfos(*reportsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "list reports: %v\n", err)
		os.Exit(1)
	}

	if len(infos) == 0 {
		fmt.Println("[*] No reports found.")
		return
	}

	for _, info := range infos {
		fmt.Printf("%-40s  %s  %d\n", info.Name, info.ModTime.Format("2006-01-02 15:04:05"), info.Size)
	}
}

func runInspect(args []string) {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)

	last := fs.Bool("last", false, "use last report")
	name := fs.String("name", "", "report file name")
	functionName := fs.String("function", "", "function name")
	capabilityName := fs.String("capability", "", "capability name")
	packer := fs.Bool("packer", false, "inspect packer analysis")
	stringsFlag := fs.Bool("strings", false, "inspect interesting strings")
	rustFlag := fs.Bool("rust", false, "inspect rust enrichment")
	reportsDir := fs.String("reports-dir", ".\\reports", "reports directory")

	_ = fs.Parse(args)

	reportPath, err := report.ResolveReportPath(*reportsDir, *name, *last)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	raw, err := report.LoadRaw(reportPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load report: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[*] Report file: %s\n\n", reportPath)

	modeCount := 0
	if *functionName != "" {
		modeCount++
	}
	if *capabilityName != "" {
		modeCount++
	}
	if *packer {
		modeCount++
	}
	if *stringsFlag {
		modeCount++
	}
	if *rustFlag {
		modeCount++
	}

	if modeCount == 0 {
		fmt.Fprintln(os.Stderr, "specify one inspect target: -function, -capability, -packer, -strings, or -rust")
		os.Exit(1)
	}
	if modeCount > 1 {
		fmt.Fprintln(os.Stderr, "use only one inspect target at a time")
		os.Exit(1)
	}

	if *functionName != "" {
		out, err := report.InspectFunction(raw, *functionName)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(report.Pretty(out))
		return
	}

	if *capabilityName != "" {
		out, err := report.InspectCapability(raw, *capabilityName)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(report.Pretty(out))
		return
	}

	if *packer {
		out, err := report.InspectPacker(raw)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(report.Pretty(out))
		return
	}

	if *stringsFlag {
		out, err := report.InspectStrings(raw)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(report.Pretty(out))
		return
	}

	if *rustFlag {
		out, err := report.InspectRust(raw)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(report.Pretty(out))
		return
	}
}

func runDiff(args []string) {
	fs := flag.NewFlagSet("diff", flag.ExitOnError)

	left := fs.String("left", "", "left report file name")
	right := fs.String("right", "", "right report file name")
	reportsDir := fs.String("reports-dir", ".\\reports", "reports directory")

	_ = fs.Parse(args)

	if *left == "" || *right == "" {
		fmt.Fprintln(os.Stderr, "specify both -left and -right")
		os.Exit(1)
	}

	leftPath := filepath.Join(*reportsDir, *left)
	rightPath := filepath.Join(*reportsDir, *right)

	leftRaw, err := report.LoadRaw(leftPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load left report: %v\n", err)
		os.Exit(1)
	}

	rightRaw, err := report.LoadRaw(rightPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load right report: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[*] Left report : %s\n", leftPath)
	fmt.Printf("[*] Right report: %s\n\n", rightPath)

	out := report.BuildDiff(leftRaw, rightRaw, leftPath, rightPath)
	fmt.Println(report.Pretty(out))
}

func runState(args []string) {
	projectRoot, err := config.ProjectRootFromWD()
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve project root: %v\n", err)
		os.Exit(1)
	}

	st, err := state.Load(projectRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load state: %v\n", err)
		os.Exit(1)
	}

	if st == nil {
		fmt.Println("[*] No saved state found.")
		return
	}

	fmt.Println(report.Pretty(st))
}

func runOpen(args []string) {
	fs := flag.NewFlagSet("open", flag.ExitOnError)

	last := fs.Bool("last", false, "use last report")
	name := fs.String("name", "", "report file name")
	reportsDir := fs.String("reports-dir", ".\\reports", "reports directory")

	_ = fs.Parse(args)

	reportPath, err := report.ResolveReportPath(*reportsDir, *name, *last)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	cmd := exec.Command("cmd", "/c", "start", "", reportPath)
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "open report: %v\n", err)
		os.Exit(1)
	}
}

func runDelete(args []string) {
	fs := flag.NewFlagSet("delete", flag.ExitOnError)

	last := fs.Bool("last", false, "delete last report")
	all := fs.Bool("all", false, "delete all reports")
	name := fs.String("name", "", "report file name")
	reportsDir := fs.String("reports-dir", ".\\reports", "reports directory")

	_ = fs.Parse(args)

	modeCount := 0
	if *last {
		modeCount++
	}
	if *all {
		modeCount++
	}
	if *name != "" {
		modeCount++
	}

	if modeCount != 1 {
		fmt.Fprintln(os.Stderr, "specify one of: -all, -last, -name <file>")
		os.Exit(1)
	}

	if *all {
		if err := report.DeleteAllReportsWithMarkdown(*reportsDir); err != nil {
			fmt.Fprintf(os.Stderr, "delete all reports: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[+] All reports deleted.")
		return
	}

	reportPath, err := report.ResolveReportPath(*reportsDir, *name, *last)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	baseName := filepath.Base(reportPath)
	if err := report.DeleteReportWithMarkdown(reportPath); err != nil {
		fmt.Fprintf(os.Stderr, "delete report: %v\n", err)
		os.Exit(1)
	}

	if *last {
		fmt.Printf("[+] Deleted last report: %s\n", baseName)
	} else {
		fmt.Printf("[+] Deleted report: %s\n", baseName)
	}
}

func runMarkdown(args []string) {
	fs := flag.NewFlagSet("markdown", flag.ExitOnError)

	last := fs.Bool("last", false, "use last report")
	name := fs.String("name", "", "report file name")
	reportsDir := fs.String("reports-dir", ".\\reports", "reports directory")

	_ = fs.Parse(args)

	reportPath, err := report.ResolveReportPath(*reportsDir, *name, *last)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	raw, err := report.LoadRaw(reportPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load report: %v\n", err)
		os.Exit(1)
	}

	mdPath, err := report.WriteMarkdownFromRaw(reportPath, raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "write markdown: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[+] Markdown report generated: %s\n", mdPath)
}