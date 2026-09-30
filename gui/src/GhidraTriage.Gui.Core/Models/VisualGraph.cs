using System.Text.Json;
using GhidraTriage.Gui.Core.Contracts;
namespace GhidraTriage.Gui.Core.Models;

public sealed record VisualNode(string Id, string Type, string Label, bool Anchor, bool Trigger, string Role, int Unresolved);
public sealed record VisualEdge(string Id, string Source, string Target, string Type);
public sealed record VisualGraph(VisualNode[] Nodes, VisualEdge[] Edges);
public static class GraphPresentation
{
  public static VisualGraph Project(GraphDto graph, SeedDto? seed)
  {
    var local = graph as LocalSubgraphDto;
    var evidence = seed?.Evidence.Select(e => e.Text("node_id")).ToHashSet() ?? [];
    return new(graph.Nodes.Select(n =>
    {
      var id = n.Text("id");
      var label = n.Text("name"); if (label.Length == 0) label = n.Text("value"); if (label.Length == 0) label = id;
      var caller = local?.FunctionSelection.CallerDistances.GetValueOrDefault(id, -1) > 0;
      var callee = local?.FunctionSelection.CalleeDistances.GetValueOrDefault(id, -1) > 0;
      return new VisualNode(id, n.Text("type"), label, id == seed?.AnchorFunctionId, evidence.Contains(id), caller && callee ? "caller / callee" : caller ? "caller" : callee ? "callee" : "", graph.UnresolvedCalls.Count(c => c.Text("caller") == id));
    }).ToArray(),
    // Backend edges have no ID. These namespaced renderer keys preserve array identity and never enter exported data.
    graph.Edges.Select((e, i) => new VisualEdge("view-edge:" + i, e.Text("source"), e.Text("target"), e.Text("type"))).ToArray());
  }
}
public sealed record FilterState(string[] NodeTypes, string[] EdgeTypes, bool TriggerOnly = false, string Role = "", bool AnchorNeighborhood = false)
{
  public static FilterState All(VisualGraph graph) => new(graph.Nodes.Select(n => n.Type).Distinct().ToArray(), graph.Edges.Select(e => e.Type).Distinct().ToArray());
  public (VisualNode[] Nodes, VisualEdge[] Edges) Apply(VisualGraph graph)
  {
    var anchors = graph.Nodes.Where(n => n.Anchor).Select(n => n.Id).ToHashSet();
    var adjacent = graph.Edges.Where(e => anchors.Contains(e.Source) || anchors.Contains(e.Target)).SelectMany(e => new[] { e.Source, e.Target }).ToHashSet();
    var nodes = graph.Nodes.Where(n => NodeTypes.Contains(n.Type) && (!TriggerOnly || n.Trigger || n.Anchor) && (Role.Length == 0 || n.Anchor || n.Role.Contains(Role, StringComparison.Ordinal)) && (!AnchorNeighborhood || n.Anchor || adjacent.Contains(n.Id))).ToArray();
    var ids = nodes.Select(n => n.Id).ToHashSet();
    return (nodes, graph.Edges.Where(e => EdgeTypes.Contains(e.Type) && ids.Contains(e.Source) && ids.Contains(e.Target)).ToArray());
  }
}

