using System.Text;
using GhidraTriage.Gui.Core.Models;
namespace GhidraTriage.Gui.Infrastructure.Export;

public interface IGraphExportService { string ToDot(VisualGraph graph, FilterState? filter = null); }
public sealed class GraphExportService : IGraphExportService
{
  public string ToDot(VisualGraph graph, FilterState? filter = null)
  {
    var (nodes, edges) = filter?.Apply(graph) ?? (graph.Nodes, graph.Edges);
    var result = new StringBuilder("digraph evidence {\n  // " + (filter == null ? "All current graph" : "Visible-only view") + "\n");
    foreach (var n in nodes) result.AppendLine($"  {Quote(n.Id)} [label={Quote(n.Label)}, type={Quote(n.Type)}];");
    foreach (var e in edges) result.AppendLine($"  {Quote(e.Source)} -> {Quote(e.Target)} [label={Quote(e.Type)}];");
    return result.AppendLine("}").ToString();
  }
  private static string Quote(string value) => "\"" + value.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", "\\r").Replace("\n", "\\n") + "\"";
}

