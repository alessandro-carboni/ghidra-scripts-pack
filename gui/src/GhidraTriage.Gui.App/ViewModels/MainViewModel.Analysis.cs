using System.Diagnostics;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GhidraTriage.Gui.Core.Services;
using GhidraTriage.Gui.Infrastructure.Settings;
namespace GhidraTriage.Gui.App.ViewModels;

public partial class MainViewModel
{
  private IAnalysisRunner runner = null!;
  private GuiSettingsStore settingsStore = null!;
  private CancellationTokenSource? analysisCancellation;
  public GuiSettings Settings { get; private set; } = new();
  [ObservableProperty] private string triageExecutable = "";
  [ObservableProperty] private string ghidraDirectory = "";
  [ObservableProperty] private string ruleDirectory = "";
  [ObservableProperty] private string rustExecutable = "";
  [ObservableProperty] private string outputRoot = "";
  [ObservableProperty] private string workingDirectory = "";
  [ObservableProperty] private string liveLog = "";
  [ObservableProperty] private string runStatus = "Idle";
  [ObservableProperty] private bool isAnalyzing;
  private void ConfigureRunner(IAnalysisRunner runner, GuiSettingsStore store)
  {
    this.runner = runner; settingsStore = store;
    try { Settings = store.Load(); } catch (Exception ex) { Error = "Settings could not be read: " + ex.Message; }
    TriageExecutable = Settings.TriageExecutable; GhidraDirectory = Settings.GhidraDirectory; RuleDirectory = Settings.RuleDirectory; RustExecutable = Settings.RustExecutable; OutputRoot = Settings.OutputRoot; WorkingDirectory = Settings.WorkingDirectory;
  }
  [RelayCommand]
  private void SaveSettings()
  {
    try { Settings = Settings with { TriageExecutable = TriageExecutable, GhidraDirectory = GhidraDirectory, RuleDirectory = RuleDirectory, RustExecutable = RustExecutable, OutputRoot = OutputRoot, WorkingDirectory = WorkingDirectory }; settingsStore.Save(Settings); Status = "Settings saved locally."; } catch (Exception ex) { Error = ex.Message; }
  }
  public void SavePanelWidths(double left, double right)
  {
    try { Settings = Settings with { LeftWidth = left, RightWidth = right }; settingsStore.Save(Settings); } catch (Exception ex) { Error = ex.Message; }
  }
  [RelayCommand]
  private async Task Analyze()
  {
    if (IsAnalyzing) return;
    if (string.IsNullOrWhiteSpace(SamplePath)) { Error = "Select an executable sample first."; return; }
    SaveSettings(); IsAnalyzing = true; LiveLog = ""; Error = ""; analysisCancellation = new(); var sw = Stopwatch.StartNew();
    var progress = new Progress<AnalysisProgress>(p => { RunStatus = $"{p.State} · {sw.Elapsed:mm\\:ss}"; LiveLog += p.Message + Environment.NewLine; if (LiveLog.Length > 60000) LiveLog = LiveLog[^50000..]; });
    try
    {
      var result = await runner.RunAsync(new(SamplePath, TriageExecutable, GhidraDirectory, RuleDirectory, RustExecutable, OutputRoot, WorkingDirectory), progress, analysisCancellation.Token);
      await OpenPathAsync(result.Manifest);
      if (Error.Length > 0) throw new InvalidOperationException(Error);
      RunStatus = $"Ready · {sw.Elapsed:mm\\:ss}"; Status = "Analysis ready · " + result.Manifest;
    }
    catch (OperationCanceledException) { RunStatus = "Cancelled"; }
    catch (Exception ex) { RunStatus = "Failed"; Error = ex.Message; }
    finally { IsAnalyzing = false; analysisCancellation.Dispose(); analysisCancellation = null; }
  }
  [RelayCommand] private void CancelAnalysis() => analysisCancellation?.Cancel();
}

