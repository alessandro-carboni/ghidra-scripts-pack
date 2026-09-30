using System.Diagnostics;
using GhidraTriage.Gui.Core.Services;
namespace GhidraTriage.Gui.Infrastructure.Backend;

public sealed class ProcessExecutionService : IProcessExecutionService
{
  public async Task<int> ExecuteAsync(ProcessRequest request, Action<string> output, CancellationToken cancellationToken)
  {
    cancellationToken.ThrowIfCancellationRequested();
    var start = new ProcessStartInfo(request.Executable) { WorkingDirectory = request.WorkingDirectory, UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
    foreach (var argument in request.Arguments) start.ArgumentList.Add(argument);
    using var process = new Process { StartInfo = start };
    if (!process.Start()) throw new InvalidOperationException("Could not start " + request.Executable);
    using var registration = cancellationToken.Register(() => { try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { } });
    async Task Drain(StreamReader reader) { while (await reader.ReadLineAsync(cancellationToken) is { } line) output(line); }
    var stdout = Drain(process.StandardOutput); var stderr = Drain(process.StandardError);
    try { await Task.WhenAll(stdout, stderr, process.WaitForExitAsync(cancellationToken)); return process.ExitCode; }
    catch { try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { } await process.WaitForExitAsync(CancellationToken.None); throw; }
  }
}

