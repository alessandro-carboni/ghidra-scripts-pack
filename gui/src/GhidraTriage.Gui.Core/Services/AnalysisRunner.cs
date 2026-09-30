namespace GhidraTriage.Gui.Core.Services;

public enum AnalysisRunState { Idle, ValidatingConfiguration, RunningGhidra, RunningRustExport, LoadingDataset, Ready, Failed, Cancelled }
public sealed record AnalysisRunRequest(string Sample, string TriageExecutable, string GhidraDirectory, string RuleDirectory, string RustExecutable, string OutputRoot, string WorkingDirectory);
public sealed record AnalysisProgress(AnalysisRunState State, string Message);
public sealed record AnalysisRunResult(string Manifest, string RawReport);
public interface IAnalysisRunner { Task<AnalysisRunResult> RunAsync(AnalysisRunRequest request, IProgress<AnalysisProgress> progress, CancellationToken cancellationToken); }
public sealed record ProcessRequest(string Executable, string[] Arguments, string WorkingDirectory);
public interface IProcessExecutionService { Task<int> ExecuteAsync(ProcessRequest request, Action<string> output, CancellationToken cancellationToken); }

