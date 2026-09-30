using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GhidraTriage.Gui.App.Services;
using GhidraTriage.Gui.Core.Contracts;
using GhidraTriage.Gui.Core.Models;
using GhidraTriage.Gui.Core.Selection;
using GhidraTriage.Gui.Core.Services;
using GhidraTriage.Gui.Infrastructure.Export;
using Microsoft.Win32;
namespace GhidraTriage.Gui.App.ViewModels;

public partial class MainViewModel : ObservableObject
{
  private readonly IAnalysisDatasetLoader loader;
  private readonly GraphViewBridge bridge;
  private readonly SelectionService selection;
  private readonly InspectorRegistry inspectors;
  private readonly IGraphExportService exporter;
  private AnalysisDataset? dataset;
  private GraphDto? graph;
  private VisualGraph? visual;
  private SeedRow[] allSeeds = [];
  private CancellationTokenSource? graphLoad;
  private CancellationTokenSource? searchDelay;
  private int generation;
  private string? pngPath;
  private bool rendererReady;
  internal bool RendererReady => rendererReady;
  internal GraphDto? CurrentGraph => graph;
  internal VisualGraph? CurrentVisual => visual;
  internal AnalysisDataset? CurrentDataset => dataset;
  [ObservableProperty] private string status = "Initializing renderer…";
  [ObservableProperty] private string sample = "Evidence workspace";
  [ObservableProperty] private string versions = "Open a Seeded dataset to begin";
  [ObservableProperty] private string summary = "No dataset loaded";
  [ObservableProperty] private string breadcrumb = "Overview";
  [ObservableProperty] private string graphSummary = "Choose Full Graph or a seed";
  [ObservableProperty] private bool isLocal;
  [ObservableProperty] private string warning = "";
  [ObservableProperty] private string error = "";
  [ObservableProperty] private string seedSearch = "";
  [ObservableProperty] private string nodeSearch = "";
  [ObservableProperty] private string selectedFamily = "All families";
  [ObservableProperty] private bool groupedOnly;
  [ObservableProperty] private bool triggerOnly;
  [ObservableProperty] private bool anchorNeighborhood;
  [ObservableProperty] private string role = "";
  [ObservableProperty] private string inspectorTitle = "Select evidence to inspect";
  [ObservableProperty] private string inspectorId = "";
  [ObservableProperty] private string details = "Click a node or edge to inspect its original fields.";
  [ObservableProperty] private string sourceId = "";
  [ObservableProperty] private string targetId = "";
  [ObservableProperty] private bool isBusy;
  [ObservableProperty] private SeedRow? selectedSeed;
  [ObservableProperty] private string samplePath = "";
  public ObservableCollection<SeedRow> Seeds { get; } = [];
  public ObservableCollection<string> Families { get; } = ["All families"];
  public ObservableCollection<TypeFilter> NodeTypes { get; } = [];
  public ObservableCollection<TypeFilter> EdgeTypes { get; } = [];
  public ObservableCollection<InspectorField> Fields { get; } = [];
  public ObservableCollection<string> SearchResults { get; } = [];
  public string[] Roles { get; } = ["", "caller", "callee"];
  public string SeedCount => $"{Seeds.Count} / {allSeeds.Length} seeds";
  public MainViewModel(IAnalysisDatasetLoader loader, GraphViewBridge bridge, SelectionService selection, InspectorRegistry inspectors, IGraphExportService exporter, IAnalysisRunner runner, GhidraTriage.Gui.Infrastructure.Settings.GuiSettingsStore settingsStore)
  {
    this.loader = loader; this.bridge = bridge; this.selection = selection; this.inspectors = inspectors; this.exporter = exporter;
    bridge.Inbound += OnMessage; ConfigureRunner(runner, settingsStore);
  }
  public async Task OpenPathAsync(string path)
  {
    graphLoad?.Cancel(); var version = ++generation; IsBusy = true; Error = "";
    try
    {
      var loaded = await loader.LoadAsync(path);
      if (version != generation) return;
      dataset = loaded; Sample = loaded.Manifest.SampleName;
      Versions = $"Graph {loaded.Versions.Graph} · Seeds {loaded.Versions.Seed} · Local {loaded.Versions.Local}";
      Summary = $"{loaded.Manifest.SeedDetection.Returned} seeds · {loaded.Manifest.Subgraphs.Length} subgraphs\n{loaded.Manifest.RelatedSeedGroups.Length} related groups";
      Warning = string.Join("\n", loaded.Warnings) + (loaded.Manifest.SeedDetection.Truncated ? " Seed list truncated by backend technical limit: " + loaded.Manifest.SeedDetection.Returned + "/" + loaded.Manifest.SeedDetection.TotalDetected + " returned." : "");
      allSeeds = loaded.Manifest.SeedDetection.Seeds.Select(s => new SeedRow(s, loaded.Subgraphs[s.SeedId], string.Join("\n", loaded.Manifest.RelatedSeedGroups.Where(g => g.SeedIds.Contains(s.SeedId)).Select(g => g.GroupId)))).OrderBy(s => s.Id, StringComparer.Ordinal).ToArray();
      Families.Clear(); Families.Add("All families"); foreach (var f in allSeeds.SelectMany(s => s.Seed.Families).Distinct().Order()) Families.Add(f);
      SelectedFamily = "All families"; SeedSearch = ""; GroupedOnly = false; FilterSeeds();
      graph = null; visual = null; IsLocal = false; GraphSummary = "Choose Full Graph or a seed"; SelectedSeed = null; bridge.Send("clearGraph"); Breadcrumb = "Overview"; Status = "Dataset ready · local graphs load on demand";
      ClearSelection();
    }
    catch (Exception ex) { Error = ex.Message; Status = "Dataset load failed"; }
    finally { if (version == generation) IsBusy = false; }
  }
  [RelayCommand]
  private async Task OpenDataset()
  {
    var dialog = new OpenFileDialog { Title = "Open Seeded manifest", Filter = "Seeded manifest|manifest.json|JSON files|*.json" };
    if (dialog.ShowDialog() == true) await OpenPathAsync(dialog.FileName);
  }
  [RelayCommand] private void SelectSample() { var d = new OpenFileDialog { Title = "Select sample", Filter = "Executable sample|*.exe" }; if (d.ShowDialog() == true) SamplePath = d.FileName; }
  [RelayCommand] private async Task FullGraph() { SelectedSeed = null; await LoadGraphAsync(null); }
  private async Task LoadGraphAsync(SeedRow? seed)
  {
    if (dataset == null) return;
    graphLoad?.Cancel(); graphLoad = new(); var ct = graphLoad.Token; var version = ++generation; IsBusy = true; Error = ""; Status = "Loading graph…";
    try
    {
      var loaded = seed == null ? (GraphDto)await loader.LoadTypedGraphAsync(dataset, ct) : await loader.LoadLocalAsync(dataset, seed.Id, ct);
      if (ct.IsCancellationRequested || version != generation) return;
      graph = loaded; visual = GraphPresentation.Project(loaded, seed?.Seed); IsLocal = loaded is LocalSubgraphDto; GraphSummary = seed == null ? $"{loaded.Nodes.Length} nodes · {loaded.Edges.Length} edges · {loaded.UnresolvedCalls.Length} unresolved" : $"{seed.Entry.FunctionNodes} functions · {seed.Entry.EvidenceNodes} evidence · {seed.Entry.Edges} edges · {seed.Entry.UnresolvedCalls} unresolved · truncated: {seed.Entry.Truncated}";
      Breadcrumb = seed == null ? "Full Graph" : $"Full Graph  ›  {seed.Anchor}";
      Warning = loaded is LocalSubgraphDto l && l.Truncation.GetProperty("truncated").GetBoolean() ? "Local context truncated by technical resource limit.\n" + l.Truncation.ToString() : string.Join("\n", dataset.Warnings);
      Details = loaded is LocalSubgraphDto local ? local.Truncation.ToString() : "Select a node, edge or unresolved record.";
      ClearSelection(); NodeTypes.Clear(); EdgeTypes.Clear();
      foreach (var t in visual.Nodes.Select(n => n.Type).Distinct().Order()) { var filter = new TypeFilter { Name = t }; filter.PropertyChanged += (_, _) => ApplyFilters(); NodeTypes.Add(filter); }
      foreach (var t in visual.Edges.Select(n => n.Type).Distinct().Order()) { var filter = new TypeFilter { Name = t }; filter.PropertyChanged += (_, _) => ApplyFilters(); EdgeTypes.Add(filter); }
      TriggerOnly = false; AnchorNeighborhood = false; Role = "";
      Status = $"{visual.Nodes.Length} nodes · {visual.Edges.Length} edges · {loaded.UnresolvedCalls.Length} unresolved";
      if (loaded is LocalSubgraphDto lg) Status += $" · caller depth {lg.ExtractionConfig.Text("caller_depth")} / callee depth {lg.ExtractionConfig.Text("callee_depth")} · truncated {lg.Truncation.Text("truncated")}";
      if (rendererReady) SendGraph();
    }
    catch (OperationCanceledException) { }
    catch (Exception ex) { if (version == generation) { Error = ex.Message; Status = "Graph load failed"; } }
    finally { if (version == generation) IsBusy = false; }
  }
  partial void OnSelectedSeedChanged(SeedRow? value) { if (value != null) _ = LoadGraphAsync(value); }
  partial void OnSeedSearchChanged(string value) => DebounceSeeds();
  partial void OnSelectedFamilyChanged(string value) => FilterSeeds();
  partial void OnGroupedOnlyChanged(bool value) => FilterSeeds();
  private async void DebounceSeeds() { searchDelay?.Cancel(); searchDelay = new(); try { await Task.Delay(180, searchDelay.Token); FilterSeeds(); } catch (OperationCanceledException) { } }
  private void FilterSeeds()
  {
    var result = allSeeds.Where(s => (!GroupedOnly || s.Group.Length > 0) && (SelectedFamily == "All families" || s.Seed.Families.Contains(SelectedFamily)) && (SeedSearch.Length == 0 || (s.Id + " " + s.Anchor + " " + s.Triggers).Contains(SeedSearch, StringComparison.OrdinalIgnoreCase))).ToArray();
    Seeds.Clear(); foreach (var s in result) Seeds.Add(s); OnPropertyChanged(nameof(SeedCount));
  }
  [RelayCommand]
  private void RelatedGroup()
  {
    if (dataset == null || SelectedSeed == null) return;
    var groups = dataset.Manifest.RelatedSeedGroups.Where(g => g.SeedIds.Contains(SelectedSeed.Id)).ToArray();
    if (groups.Length == 0) { Details = "This seed has no related group."; return; }
    var ids = groups.SelectMany(g => g.SeedIds).ToHashSet();
    Seeds.Clear(); foreach (var s in allSeeds.Where(s => ids.Contains(s.Id))) Seeds.Add(s);
    OnPropertyChanged(nameof(SeedCount)); Details = JsonSerializer.Serialize(groups, new JsonSerializerOptions { WriteIndented = true });
  }
  [RelayCommand] private void ResetSeedFilters() { SeedSearch = ""; SelectedFamily = "All families"; GroupedOnly = false; FilterSeeds(); }
  public FilterState CurrentFilter => new(NodeTypes.Where(t => t.Enabled).Select(t => t.Name).ToArray(), EdgeTypes.Where(t => t.Enabled).Select(t => t.Name).ToArray(), TriggerOnly, Role, AnchorNeighborhood);
  partial void OnTriggerOnlyChanged(bool value) => ApplyFilters();
  partial void OnAnchorNeighborhoodChanged(bool value) => ApplyFilters();
  partial void OnRoleChanged(string value) => ApplyFilters();
  private void ApplyFilters()
  {
    if (visual == null) return;
    var (nodes, edges) = CurrentFilter.Apply(visual);
    bridge.Send("setFilters", new { ids = nodes.Select(n => n.Id).Concat(edges.Select(e => e.Id)) });
    Status = $"Visible {nodes.Length}/{visual.Nodes.Length} nodes · {edges.Length}/{visual.Edges.Length} edges · {graph!.UnresolvedCalls.Length} unresolved in source graph";
  }
  [RelayCommand] private void ResetFilters() { foreach (var t in NodeTypes.Concat(EdgeTypes)) t.Enabled = true; TriggerOnly = false; AnchorNeighborhood = false; Role = ""; ApplyFilters(); }
  [RelayCommand] private void Fit() => bridge.Send("fit");
  private void SendGraph() { if (visual != null) bridge.Send("loadGraph", new { nodes = visual.Nodes, edges = visual.Edges, layout = Settings.Layout }); }
  [RelayCommand] private void Layout(string name) { Settings = Settings with { Layout = name }; settingsStore.Save(Settings); bridge.Send("setLayout", new { name }); }
  [RelayCommand] private void Labels(string mode) => bridge.Send("setLabelMode", new { mode });
  [RelayCommand]
  private void Search()
  {
    SearchResults.Clear(); if (visual == null) return;
    foreach (var n in visual.Nodes.Where(n => (n.Id + " " + n.Label).Contains(NodeSearch, StringComparison.OrdinalIgnoreCase)).Take(100)) SearchResults.Add(n.Id);
    if (SearchResults.Count > 0) Focus(SearchResults[0]); else Status = "No matching node.";
  }
  [RelayCommand]
  private void Focus(string? id)
  {
    if (id == null || visual == null) return;
    ResetFilters(); bridge.Send("focusNode", new { id });
  }
  [RelayCommand] private void ClearSelection() { selection.Select(null); InspectorTitle = "Select evidence to inspect"; InspectorId = ""; Fields.Clear(); SourceId = ""; TargetId = ""; bridge.Send("setSelection"); }
  [RelayCommand] private void CopyId() { if (InspectorId.Length > 0) System.Windows.Clipboard.SetText(InspectorId); }
  [RelayCommand] private void CopyDetails() => System.Windows.Clipboard.SetText(Details);
  [RelayCommand]
  private void Unresolved()
  {
    if (graph == null) return; InspectorTitle = "Unresolved calls · no target"; InspectorId = ""; Fields.Clear(); SourceId = ""; TargetId = "";
    Details = JsonSerializer.Serialize(graph.UnresolvedCalls, new JsonSerializerOptions { WriteIndented = true });
    foreach (var c in graph.UnresolvedCalls) Fields.Add(new(c.Text("caller") + " @ " + c.Text("callsite"), c.Text("reason")));
    if (graph.UnresolvedCalls.Length > 0) SourceId = graph.UnresolvedCalls[0].Text("caller");
  }
  private void Inspect(string kind, string id)
  {
    if (graph == null) return;
    JsonElement data;
    if (kind == "node") { data = graph.Nodes.FirstOrDefault(n => n.Text("id") == id); SourceId = ""; TargetId = ""; }
    else if (id.StartsWith("view-edge:", StringComparison.Ordinal) && int.TryParse(id[10..], out var index) && index >= 0 && index < graph.Edges.Length) { data = graph.Edges[index]; SourceId = data.Text("source"); TargetId = data.Text("target"); }
    else return;
    if (data.ValueKind != JsonValueKind.Object) return;
    selection.Select(new(kind, id)); InspectorId = kind == "node" ? id : "Edge array index " + id[10..]; InspectorTitle = data.Text("type");
    Fields.Clear(); foreach (var field in inspectors.Fields(data)) Fields.Add(field);
    if (kind == "node" && visual != null) { var node = visual.Nodes.First(n => n.Id == id); if (node.Anchor) Fields.Insert(0, new("overlay", "◎ anchor")); if (node.Trigger) Fields.Insert(0, new("overlay", "◆ trigger evidence")); if (node.Role.Length > 0) Fields.Insert(0, new("role", node.Role)); }
    Details = JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true });
  }
  private void OnMessage(BridgeEnvelope message)
  {
    var p = message.Payload;
    switch (message.Type)
    {
      case "ready": rendererReady = true; Status = dataset == null ? "Renderer ready · open a dataset" : "Dataset ready · choose Full Graph or a seed"; if (visual != null) SendGraph(); break;
      case "nodeSelected": case "edgeSelected": if (p is { } v) Inspect(message.Type == "nodeSelected" ? "node" : "edge", v.Text("id")); break;
      case "backgroundSelected": ClearSelection(); break;
      case "layoutCompleted": if (p is { } ready) Status = $"Rendered {ready.Text("nodes")} nodes · {ready.Text("edges")} edges · {ready.Text("renderMs")} ms"; break;
      case "renderError": Error = p?.Text("message") ?? "Renderer error"; break;
      case "pngExported":
        try { if (pngPath != null && p is { } image) { File.WriteAllBytes(pngPath, Convert.FromBase64String(image.Text("data"))); Status = "PNG exported at 2×: " + pngPath; pngPath = null; } }
        catch (Exception ex) { Error = ex.Message; }
        break;
    }
  }
  [RelayCommand] private void ExportPng() { if (visual == null) return; var d = new SaveFileDialog { Filter = "PNG figure|*.png", FileName = "graph.png" }; if (d.ShowDialog() == true) { pngPath = d.FileName; bridge.Send("exportPng"); } }
  [RelayCommand]
  private void ExportDot(string scope)
  {
    if (visual == null) return; var d = new SaveFileDialog { Filter = "Graphviz DOT|*.dot", FileName = scope == "visible" ? "graph-visible.dot" : "graph.dot" };
    if (d.ShowDialog() == true) try { File.WriteAllText(d.FileName, exporter.ToDot(visual, scope == "visible" ? CurrentFilter : null)); Status = "DOT exported: " + d.FileName; } catch (Exception ex) { Error = ex.Message; }
  }
  [RelayCommand] private void OpenFolder() { if (dataset != null) OpenExternal(dataset.Paths.Directory); }
  [RelayCommand] private void OpenJson() { if (dataset != null) OpenExternal(graph is LocalSubgraphDto local ? Path.Combine(dataset.Paths.Directory, dataset.Subgraphs[local.SeedId].File) : dataset.Paths.RawReport ?? dataset.Paths.Manifest); }
  private void OpenExternal(string path) { try { Process.Start(new ProcessStartInfo(path) { UseShellExecute = true }); } catch (Exception ex) { Error = ex.Message; } }
}





