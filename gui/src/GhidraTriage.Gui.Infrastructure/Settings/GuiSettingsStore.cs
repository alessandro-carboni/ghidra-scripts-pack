using System.Text.Json;
namespace GhidraTriage.Gui.Infrastructure.Settings;

public sealed record GuiSettings
{
  public string TriageExecutable { get; init; } = "";
  public string GhidraDirectory { get; init; } = "";
  public string RuleDirectory { get; init; } = "";
  public string RustExecutable { get; init; } = "";
  public string OutputRoot { get; init; } = "";
  public string WorkingDirectory { get; init; } = "";
  public double LeftWidth { get; init; } = 290;
  public double RightWidth { get; init; } = 310;
  public string Layout { get; init; } = "cose";
}
public sealed class GuiSettingsStore
{
  private readonly string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "GhidraTriage", "settings.json");
  public GuiSettings Load()
  {
    if (File.Exists(path)) return JsonSerializer.Deserialize<GuiSettings>(File.ReadAllText(path)) ?? new();
    var root = new DirectoryInfo(AppContext.BaseDirectory);
    while (root != null && !Directory.Exists(Path.Combine(root.FullName, "ghidra_scripts"))) root = root.Parent;
    if (root == null) return new();
    var repo = root.FullName; var ghidra = "";
    var statePath = Path.Combine(repo, ".runstate.json");
    if (File.Exists(statePath)) { using var doc = JsonDocument.Parse(File.ReadAllText(statePath)); if (doc.RootElement.TryGetProperty("ghidra_dir", out var value)) ghidra = value.GetString() ?? ""; }
    return new() { WorkingDirectory = repo, TriageExecutable = Path.Combine(repo, "triage.exe"), GhidraDirectory = ghidra, RuleDirectory = Path.Combine(repo, "rules"), RustExecutable = Path.Combine(repo, "rust_engine", "target", "debug", "rust_engine.exe"), OutputRoot = Path.Combine(repo, "reports") };
  }
  public void Save(GuiSettings settings) { Directory.CreateDirectory(Path.GetDirectoryName(path)!); var temp = path + ".tmp"; File.WriteAllText(temp, JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true })); File.Move(temp, path, true); }
}

