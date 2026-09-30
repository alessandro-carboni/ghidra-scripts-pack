using System.Text.Json;
using System.Text.Json.Nodes;
using GhidraTriage.Gui.Core.Contracts;
using GhidraTriage.Gui.Core.Models;
using GhidraTriage.Gui.Infrastructure.Dataset;
using GhidraTriage.Gui.Infrastructure.Export;
using GhidraTriage.Gui.Infrastructure.Json;
namespace GhidraTriage.Gui.Tests;

public sealed class DatasetTests : IDisposable
{
  private readonly string folder = Path.Combine(Path.GetTempPath(), "seeded-gui-tests-" + Guid.NewGuid().ToString("N"));
  public DatasetTests() { Directory.CreateDirectory(folder); foreach (var f in Directory.GetFiles(Path.Combine(AppContext.BaseDirectory, "Fixtures"))) File.Copy(f, Path.Combine(folder, Path.GetFileName(f))); }
  public void Dispose() => Directory.Delete(folder, true);
  private string Manifest => Path.Combine(folder, "manifest.json");
  private void Mutate(Action<JsonNode> action) { var node = JsonNode.Parse(File.ReadAllText(Manifest))!; action(node); File.WriteAllText(Manifest, node.ToJsonString()); }
  [Fact]
  public async Task LoadsLazilyAndCachesWithoutMutatingSource()
  {
    var loader = new AnalysisDatasetLoader(); var before = File.ReadAllBytes(Manifest); var d = await loader.LoadAsync(Manifest);
    Assert.Equal(0, loader.LocalReads); Assert.Single(d.Warnings);
    var g = await loader.LoadLocalAsync(d, "seed:fn:1400012dc"); var again = await loader.LoadLocalAsync(d, g.SeedId);
    Assert.Same(g, again); Assert.Equal(1, loader.LocalReads); Assert.Equal(before, File.ReadAllBytes(Manifest));
    Assert.Equal(11, g.Nodes.Length); Assert.Equal(15, g.Edges.Length);
  }
  [Theory]
  [InlineData("schema_version")]
  [InlineData("graph_version")]
  [InlineData("seed_rules_version")]
  [InlineData("local_subgraph_schema_version")]
  public async Task RejectsUnsupportedVersion(string key) { Mutate(n => n[key] = "99.0"); await Assert.ThrowsAsync<InvalidDataException>(() => new AnalysisDatasetLoader().LoadAsync(Manifest)); }
  [Fact] public async Task RejectsCorruptManifest() { File.WriteAllText(Manifest, "{broken"); await Assert.ThrowsAsync<InvalidDataException>(() => new AnalysisDatasetLoader().LoadAsync(Manifest)); }
  [Fact] public async Task RejectsMissingSubgraph() { File.Delete(Path.Combine(folder, "seed_fn_1400012dc.json")); await Assert.ThrowsAsync<InvalidDataException>(() => new AnalysisDatasetLoader().LoadAsync(Manifest)); }
  [Fact] public async Task RejectsPathTraversal() { Mutate(n => n["subgraphs"]![0]!["file"] = "../outside.json"); await Assert.ThrowsAsync<InvalidDataException>(() => new AnalysisDatasetLoader().LoadAsync(Manifest)); }
  [Fact] public async Task RejectsMappingMismatch() { Mutate(n => n["subgraphs"]![0]!["anchor_function_id"] = "fn:wrong"); await Assert.ThrowsAsync<InvalidDataException>(() => new AnalysisDatasetLoader().LoadAsync(Manifest)); }
  [Fact] public async Task CorruptLocalIsIsolatedUntilRequested() { File.WriteAllText(Path.Combine(folder, "seed_fn_1400012dc.json"), "{broken"); var loader = new AnalysisDatasetLoader(); var d = await loader.LoadAsync(Manifest); await Assert.ThrowsAsync<InvalidDataException>(() => loader.LoadLocalAsync(d, "seed:fn:1400012dc")); }
  [Fact] public async Task MissingRawDoesNotPreventLocalUse() { var loader = new AnalysisDatasetLoader(); var d = await loader.LoadAsync(Manifest); Assert.Null(d.Paths.RawReport); await Assert.ThrowsAsync<FileNotFoundException>(() => loader.LoadTypedGraphAsync(d)); Assert.NotNull(await loader.LoadLocalAsync(d, "seed:fn:1400012dc")); }
  [Fact] public async Task CancellationIsObserved() { using var ct = new CancellationTokenSource(); ct.Cancel(); await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new AnalysisDatasetLoader().LoadAsync(Manifest, ct.Token)); }
  [Fact]
  public async Task ProjectionFiltersAndDotPreserveTopology()
  {
    var loader = new AnalysisDatasetLoader(); var d = await loader.LoadAsync(Manifest); var graph = await loader.LoadLocalAsync(d, d.Manifest.SeedDetection.Seeds[0].SeedId);
    var before = JsonSerializer.Serialize(graph, DatasetJson.Options); var v = GraphPresentation.Project(graph, d.Manifest.SeedDetection.Seeds[0]);
    Assert.Single(v.Nodes, n => n.Anchor); Assert.Contains(v.Nodes, n => n.Trigger);
    var filter = FilterState.All(v) with { NodeTypes = ["FUNCTION"] };
    var visible = filter.Apply(v); Assert.Equal(6, visible.Nodes.Length); Assert.All(visible.Edges, e => Assert.Contains(visible.Nodes, n => n.Id == e.Target));
    Assert.Equal(v.Nodes.Length, FilterState.All(v).Apply(v).Nodes.Length);
    Assert.Equal(before, JsonSerializer.Serialize(graph, DatasetJson.Options));
    var dot = new GraphExportService().ToDot(v, filter); Assert.Contains("Visible-only", dot); Assert.Contains("fn:1400012dc", dot);
    Assert.DoesNotContain("fake_unknown", dot);
  }
  [Fact]
  public void RejectsUnresolvedFakeTarget()
  {
    var node = JsonDocument.Parse("{\"id\":\"fn:1\",\"type\":\"FUNCTION\"}").RootElement.Clone();
    var call = JsonDocument.Parse("{\"caller\":\"fn:1\",\"callee\":\"fake\",\"unresolved\":true}").RootElement.Clone();
    Assert.Throws<InvalidDataException>(() => AnalysisDatasetLoader.ValidateGraph(new GraphDto { Nodes = [node], Edges = [], UnresolvedCalls = [call] }));
  }
  [Fact]
  public void DotEscapesLabels()
  {
    var graph = new VisualGraph([new("fn:1", "FUNCTION", "quote\"\nslash\\", false, false, "", 0)], []);
    Assert.Contains("quote\\\"\\nslash\\\\", new GraphExportService().ToDot(graph));
  }
  [Fact]
  public async Task DeterministicReloadAndUnknownFieldsPreserved()
  {
    Mutate(n => n["future_metadata"] = "retained");
    var loader = new AnalysisDatasetLoader(); var a = await loader.LoadAsync(Manifest); var b = await loader.LoadAsync(Manifest);
    Assert.Equal(JsonSerializer.Serialize(a.Manifest, DatasetJson.Options), JsonSerializer.Serialize(b.Manifest, DatasetJson.Options));
    Assert.Equal("retained", a.Manifest.Additional!["future_metadata"].GetString());
  }
  [Fact]
  public void CoreHasNoPlatformOrBackendDependencies()
  {
    var references = typeof(AnalysisDataset).Assembly.GetReferencedAssemblies().Select(a => a.Name!).ToArray();
    Assert.DoesNotContain(references, n => n.Contains("Wpf", StringComparison.OrdinalIgnoreCase) || n.Contains("WebView") || n.Contains("rust") || n.Contains("Infrastructure"));
  }
}

