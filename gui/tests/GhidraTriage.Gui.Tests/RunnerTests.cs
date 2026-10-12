using GhidraTriage.Gui.Core.Services;
using GhidraTriage.Gui.Infrastructure.Backend;
namespace GhidraTriage.Gui.Tests;

public sealed class RunnerTests : IDisposable
{
  private readonly string folder = Path.Combine(Path.GetTempPath(), "seeded-runner-" + Guid.NewGuid().ToString("N"));
  public RunnerTests() { Directory.CreateDirectory(Path.Combine(folder, "support")); Directory.CreateDirectory(Path.Combine(folder, "ghidra_scripts")); foreach (var f in new[] { "sample.exe", "triage.exe", "rust.exe", "seed_rules.json", "support/pyghidraRun.bat", "raw.json", "manifest.json" }) File.WriteAllText(Path.Combine(folder, f), ""); }
  public void Dispose() => Directory.Delete(folder, true);
  private AnalysisRunRequest Request => new(Path.Combine(folder, "sample.exe"), Path.Combine(folder, "triage.exe"), folder, folder, Path.Combine(folder, "rust.exe"), Path.Combine(folder, "output"), folder);
  private sealed class ProgressLog : IProgress<AnalysisProgress> { public List<AnalysisRunState> States { get; } = []; public void Report(AnalysisProgress value) => States.Add(value.State); }
  private sealed class FakeProcess(Func<ProcessRequest, Action<string>, CancellationToken, Task<int>> run) : IProcessExecutionService { public Task<int> ExecuteAsync(ProcessRequest request, Action<string> output, CancellationToken ct) => run(request, output, ct); }
  [Fact]
  public async Task SuccessfulBridgeUsesExactReportedPathsAndSeededFlag()
  {
    var calls = new List<ProcessRequest>(); var log = new ProgressLog();
    var runner = new CurrentBridgeAnalysisRunner(new FakeProcess((r, output, _) => { calls.Add(r); output(calls.Count == 1 ? "[+] Raw report: " + Path.Combine(folder, "raw.json") : "[+] Manifest: " + Path.Combine(folder, "manifest.json")); return Task.FromResult(0); }));
    var result = await runner.RunAsync(Request, log, CancellationToken.None);
    Assert.Equal(Path.Combine(folder, "manifest.json"), result.Manifest); Assert.Contains("-seeded", calls[0].Arguments); Assert.Equal("export-local-subgraphs", calls[1].Arguments[0]); Assert.Equal(Path.Combine(folder, "raw.json"), calls[1].Arguments[1]);
    Assert.Equal(new[] { AnalysisRunState.ValidatingConfiguration, AnalysisRunState.RunningGhidra, AnalysisRunState.RunningRustExport, AnalysisRunState.LoadingDataset }, log.States.Distinct());
  }
  [Fact]
  public async Task FailureStopsBeforeExport()
  {
    var count = 0; var log = new ProgressLog(); var runner = new CurrentBridgeAnalysisRunner(new FakeProcess((_, _, _) => { count++; return Task.FromResult(7); }));
    await Assert.ThrowsAsync<InvalidOperationException>(() => runner.RunAsync(Request, log, CancellationToken.None)); Assert.Equal(1, count); Assert.Equal(AnalysisRunState.Failed, log.States.Last());
  }
  [Fact]
  public async Task MissingExecutableFailsBeforeProcess()
  {
    var runner = new CurrentBridgeAnalysisRunner(new FakeProcess((_, _, _) => throw new Exception("Should not launch")));
    await Assert.ThrowsAsync<FileNotFoundException>(() => runner.RunAsync(Request with { TriageExecutable = Path.Combine(folder, "missing.exe") }, new ProgressLog(), CancellationToken.None));
  }
  [Fact]
  public async Task MissingPathOutputFails()
  {
    var runner = new CurrentBridgeAnalysisRunner(new FakeProcess((_, output, _) => { output("success without a path"); return Task.FromResult(0); }));
    await Assert.ThrowsAsync<InvalidDataException>(() => runner.RunAsync(Request, new ProgressLog(), CancellationToken.None));
  }
  [Fact]
  public async Task CancellationIsTerminal()
  {
    using var cts = new CancellationTokenSource(); var log = new ProgressLog();
    var runner = new CurrentBridgeAnalysisRunner(new FakeProcess((_, _, ct) => { cts.Cancel(); ct.ThrowIfCancellationRequested(); return Task.FromResult(0); }));
    await Assert.ThrowsAnyAsync<OperationCanceledException>(() => runner.RunAsync(Request, log, cts.Token)); Assert.Equal(AnalysisRunState.Cancelled, log.States.Last());
  }
  [Theory]
  [InlineData("[+] Raw report: ")]
  [InlineData("[+] Raw report: relative.json")]
  public void RejectsMalformedPaths(string line) => Assert.Throws<InvalidDataException>(() => ProcessOutputPaths.Read(line, "[+] Raw report: "));
}

