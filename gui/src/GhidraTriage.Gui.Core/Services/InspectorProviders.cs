using System.Text.Json;
using GhidraTriage.Gui.Core.Contracts;
namespace GhidraTriage.Gui.Core.Services;

public sealed record InspectorField(string Name, string Value);
public interface IInspectorSectionProvider { bool Supports(string type); IReadOnlyList<InspectorField> Fields(JsonElement element); }
public sealed class JsonInspectorSectionProvider(string type) : IInspectorSectionProvider
{
  public bool Supports(string nodeType) => nodeType == type;
  public IReadOnlyList<InspectorField> Fields(JsonElement element) => element.EnumerateObject().Select(p => new InspectorField(p.Name, p.Value.ValueKind == JsonValueKind.Null ? "null" : p.Value.ToString())).ToArray();
}
public sealed class InspectorRegistry
{
  private readonly IInspectorSectionProvider[] providers = new[] { "FUNCTION", "API", "STRING", "STRING_CATEGORY", "CONSTANT", "SECTION", "VISIBILITY_INDICATOR" }.Select(t => (IInspectorSectionProvider)new JsonInspectorSectionProvider(t)).ToArray();
  public IReadOnlyList<InspectorField> Fields(JsonElement element) => (providers.FirstOrDefault(p => p.Supports(element.Text("type"))) ?? new JsonInspectorSectionProvider("fallback")).Fields(element);
}
public interface INavigationSectionProvider { IReadOnlyList<string> Sections { get; } }
public sealed class CurrentNavigationProvider : INavigationSectionProvider { public IReadOnlyList<string> Sections { get; } = ["Overview", "Full Graph", "Seeds"]; }
public interface IArtifactViewProvider { string ArtifactKind { get; } }


