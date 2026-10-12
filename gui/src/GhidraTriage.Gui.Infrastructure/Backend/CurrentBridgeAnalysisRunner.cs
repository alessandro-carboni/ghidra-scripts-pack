using GhidraTriage.Gui.Core.Services;
namespace GhidraTriage.Gui.Infrastructure.Backend;

public static class ProcessOutputPaths
{
  public static string? Read(string line, string prefix)
  {
    if (!line.StartsWith(prefix, StringComparison.Ordinal)) return null;
    var path = line[prefix.Length..].Trim();
    if (path.Length == 0 || !Path.IsPathFullyQualified(path) || path.IndexOfAny(Path.GetInvalidPathChars()) >= 0) throw new InvalidDataException("Malformed backend output path: " + line);
    return Path.GetFullPath(path);
  }
}
public sealed class CurrentBridgeAnalysisRunner(IProcessExecutionService process) : IAnalysisRunner
{
  public async Task<AnalysisRunResult> RunAsync(AnalysisRunRequest r, IProgress<AnalysisProgress> progress, CancellationToken ct)
  {
    var state = AnalysisRunState.ValidatingConfiguration;
    void State(AnalysisRunState value, string message) { state = value; progress.Report(new(state, message)); }
    State(state, "Validating backend configuration");
    try
    {
      ct.ThrowIfCancellationRequested();
      foreach (var file in new[] { r.Sample, r.TriageExecutable, r.RustExecutable, Path.Combine(r.GhidraDirectory, "support", "pyghidraRun.bat"), Path.Combine(r.RuleDirectory, "seed_rules.json") })
        if (!File.Exists(file)) throw new FileNotFoundException("Required file missing: " + file, file);
      if (!Directory.Exists(Path.Combine(r.WorkingDirectory, "ghidra_scripts"))) throw new DirectoryNotFoundException("Repository ghidra_scripts directory missing.");
      var run = Path.Combine(Path.GetFullPath(r.OutputRoot), "gui-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N")[..8]);
      Directory.CreateDirectory(run);
      var logGate = new object(); void Log(string line) { lock (logGate) File.AppendAllText(Path.Combine(run, "process.jsonl"), System.Text.Json.JsonSerializer.Serialize(new { time = DateTimeOffset.UtcNow, state = state.ToString(), message = line }) + Environment.NewLine); progress.Report(new(state, line)); }
      string? raw = null; string? manifest = null;
      State(AnalysisRunState.RunningGhidra, "Running triage scan -seeded");
      var scan = new ProcessRequest(r.TriageExecutable, ["scan", "-input", r.Sample, "-ghidra-dir", r.GhidraDirectory, "-rule-dir", r.RuleDirectory, "-rust-engine", r.RustExecutable, "-output-dir", run, "-project-dir", Path.Combine(run, "ghidra-project"), "-project-name", "GuiAnalysis", "-seeded"], r.WorkingDirectory);
      var exit = await process.ExecuteAsync(scan, line => { var parsed = ProcessOutputPaths.Read(line, "[+] Raw report: "); if (parsed != null) raw = parsed; Log(line); }, ct);
      if (exit != 0) throw new InvalidOperationException("Ghidra scan failed with exit code " + exit);
      if (raw == null || !File.Exists(raw)) throw new InvalidDataException("Backend did not provide an existing raw report path.");
      State(AnalysisRunState.RunningRustExport, "Exporting backend local subgraphs");
      var export = new ProcessRequest(r.RustExecutable, ["export-local-subgraphs", raw, Path.Combine(run, "seeded"), "--rules", Path.Combine(r.RuleDirectory, "seed_rules.json")], r.WorkingDirectory);
      exit = await process.ExecuteAsync(export, line => { var parsed = ProcessOutputPaths.Read(line, "[+] Manifest: "); if (parsed != null) manifest = parsed; Log(line); }, ct);
      if (exit != 0) throw new InvalidOperationException("Rust export failed with exit code " + exit);
      if (manifest == null || !File.Exists(manifest)) throw new InvalidDataException("Backend did not provide an existing manifest path.");
      State(AnalysisRunState.LoadingDataset, manifest);
      return new(manifest, raw);
    }
    catch (OperationCanceledException) { State(AnalysisRunState.Cancelled, "Analysis cancelled"); throw; }
    catch (Exception ex) { State(AnalysisRunState.Failed, ex.Message); throw; }
  }
}


