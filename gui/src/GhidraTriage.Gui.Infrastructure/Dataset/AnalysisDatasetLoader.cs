using System.Diagnostics;
using System.Text.Json;
using GhidraTriage.Gui.Core.Contracts;
using GhidraTriage.Gui.Core.Models;
using GhidraTriage.Gui.Infrastructure.Json;
namespace GhidraTriage.Gui.Infrastructure.Dataset;

public sealed class AnalysisDatasetLoader : IAnalysisDatasetLoader
{
  private readonly object gate = new();
  private readonly LinkedList<(string Key, LocalSubgraphDto Value)> cache = new();
  public const int CacheCapacity = 8;
  public int LocalReads { get; private set; }
  public int CachedCount { get { lock (gate) return cache.Count; } }
  public async Task<AnalysisDataset> LoadAsync(string manifestPath, CancellationToken cancellationToken = default)
  {
    var sw = Stopwatch.StartNew();
    var path = Path.GetFullPath(manifestPath);
    var folder = Path.GetDirectoryName(path)!;
    var m = await DatasetJson.ReadAsync<SeededManifestDto>(path, cancellationToken);
    Version(m.SchemaVersion, "0.1.0"); Version(m.LocalSubgraphSchemaVersion, "0.1.0");
    Version(m.GraphVersion, "0.12.0"); Version(m.SeedRulesVersion, "0.4.0"); Version(m.SeedDetection.ModelVersion, "0.4.0");
    Require(m.SeedDetection.Returned == m.SeedDetection.Seeds.Length && m.Subgraphs.Length == m.SeedDetection.Returned, "Seed/subgraph counts do not match.");
    Require(m.SeedDetection.Seeds.Select(s => s.SeedId).Distinct().Count() == m.SeedDetection.Seeds.Length, "Duplicate seed IDs.");
    Require(m.Subgraphs.Select(s => s.SeedId).Distinct().Count() == m.Subgraphs.Length, "Duplicate subgraph IDs.");
    var index = m.Subgraphs.ToDictionary(s => s.SeedId, StringComparer.Ordinal);
    foreach (var seed in m.SeedDetection.Seeds)
    {
      cancellationToken.ThrowIfCancellationRequested();
      Require(index.TryGetValue(seed.SeedId, out var entry) && entry.AnchorFunctionId == seed.AnchorFunctionId, "Seed/file mapping mismatch: " + seed.SeedId);
      Require(entry!.TotalNodes == entry.FunctionNodes + entry.EvidenceNodes, "Invalid manifest node counts.");
      var file = LocalPath(folder, entry.File);
      Require(File.Exists(file), "Missing local subgraph: " + file);
    }
    foreach (var group in m.RelatedSeedGroups)
      Require(group.SeedIds.All(index.ContainsKey), "Related group references an unknown seed.");
    Require(!string.IsNullOrWhiteSpace(m.SourceReport) && !Path.IsPathRooted(m.SourceReport) && Path.GetFileName(m.SourceReport) == m.SourceReport, "Source report must be a filename.");
    var raw = new[] { Path.Combine(folder, m.SourceReport), Path.Combine(Path.GetDirectoryName(folder)!, m.SourceReport) }.FirstOrDefault(File.Exists);
    Trace.WriteLine($"manifest_load_ms={sw.Elapsed.TotalMilliseconds:F1}");
    lock (gate) cache.Clear();
    return new(m, new(path, folder, raw), new(m.SchemaVersion, m.GraphVersion, m.SeedRulesVersion, m.LocalSubgraphSchemaVersion), index,
        raw == null ? ["Source raw report is unavailable. Local seed graphs remain available."] : []);
  }
  public async Task<TypedGraphDto> LoadTypedGraphAsync(AnalysisDataset dataset, CancellationToken cancellationToken = default)
  {
    var sw = Stopwatch.StartNew();
    if (dataset.Paths.RawReport == null) throw new FileNotFoundException("Source raw report is unavailable.");
    using var document = await DatasetJson.ReadAsync<JsonDocument>(dataset.Paths.RawReport, cancellationToken);
    if (!document.RootElement.TryGetProperty("typed_graph", out var value)) throw new InvalidDataException("Raw report has no typed_graph.");
    var graph = value.Deserialize<TypedGraphDto>(DatasetJson.Options) ?? throw new InvalidDataException("Missing typed graph.");
    Version(graph.ModelVersion, "0.12.0"); ValidateGraph(graph);
    Trace.WriteLine($"typed_graph_load_ms={sw.Elapsed.TotalMilliseconds:F1}");
    return graph;
  }
  public async Task<LocalSubgraphDto> LoadLocalAsync(AnalysisDataset dataset, string seedId, CancellationToken cancellationToken = default)
  {
    cancellationToken.ThrowIfCancellationRequested();
    if (!dataset.Subgraphs.TryGetValue(seedId, out var entry)) throw new InvalidDataException("Unknown seed: " + seedId);
    var path = LocalPath(dataset.Paths.Directory, entry.File);
    lock (gate)
    {
      var hit = cache.First;
      while (hit != null) { if (hit.Value.Key == path) { var result = hit.Value.Value; cache.Remove(hit); cache.AddFirst((path, result)); return result; } hit = hit.Next; }
    }
    var sw = Stopwatch.StartNew();
    var graph = await DatasetJson.ReadAsync<LocalSubgraphDto>(path, cancellationToken);
    Version(graph.SchemaVersion, "0.1.0"); Version(graph.GraphVersion, "0.12.0");
    Require(graph.SeedId == seedId && graph.AnchorFunctionId == entry.AnchorFunctionId, "Local subgraph does not match manifest.");
    ValidateGraph(graph);
    Require(graph.Nodes.Length == entry.TotalNodes && graph.Edges.Length == entry.Edges && graph.UnresolvedCalls.Length == entry.UnresolvedCalls, "Local graph counts do not match manifest.");
    Require(graph.Nodes.Count(n => n.Text("type") == "FUNCTION") == entry.FunctionNodes, "Function count mismatch.");
    Require(graph.FunctionSelection.AnchorFunctionId == graph.AnchorFunctionId && graph.Nodes.Any(n => n.Text("id") == graph.AnchorFunctionId && n.Text("type") == "FUNCTION"), "Local anchor is invalid.");
    Require(graph.Truncation.GetProperty("truncated").GetBoolean() == entry.Truncated, "Truncation mismatch.");
    foreach (var distance in graph.FunctionSelection.CallerDistances.Concat(graph.FunctionSelection.CalleeDistances))
      Require(graph.FunctionSelection.FunctionIds.Contains(distance.Key) && graph.Nodes.Any(n => n.Text("id") == distance.Key), "Invalid function selection.");
    cancellationToken.ThrowIfCancellationRequested();
    lock (gate)
    {
      LocalReads++;
      cache.AddFirst((path, graph));
      while (cache.Count > CacheCapacity) cache.RemoveLast();
    }
    Trace.WriteLine($"subgraph_load_ms={sw.Elapsed.TotalMilliseconds:F1}");
    return graph;
  }
  public static void ValidateGraph(GraphDto graph)
  {
    var ids = graph.Nodes.Select(n => n.Text("id")).ToHashSet(StringComparer.Ordinal);
    Require(ids.Count == graph.Nodes.Length && !ids.Contains(""), "Invalid or duplicate node IDs.");
    foreach (var edge in graph.Edges) Require(ids.Contains(edge.Text("source")) && ids.Contains(edge.Text("target")), "Edge endpoint is absent.");
    foreach (var call in graph.UnresolvedCalls)
    {
      Require(call.TryGetProperty("callee", out var callee) && callee.ValueKind == JsonValueKind.Null, "Unresolved call must have null callee.");
      Require(call.TryGetProperty("unresolved", out var unresolved) && unresolved.ValueKind == JsonValueKind.True, "Invalid unresolved call.");
      Require(ids.Contains(call.Text("caller")), "Unresolved caller is absent.");
    }
  }
  private static string LocalPath(string folder, string file)
  {
    Require(!string.IsNullOrWhiteSpace(file) && Path.GetFileName(file) == file && !Path.IsPathRooted(file), "Subgraph must be a local filename.");
    return Path.Combine(folder, file);
  }
  private static void Version(string actual, string expected) => Require(actual == expected, $"Unsupported schema version '{actual}'; expected '{expected}'.");
  private static void Require(bool condition, string message) { if (!condition) throw new InvalidDataException(message); }
}

