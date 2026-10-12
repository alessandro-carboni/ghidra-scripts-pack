using System.Text.Json;
using GhidraTriage.Gui.Core.Contracts;

namespace GhidraTriage.Gui.Core.Services;

public sealed record InspectorField(string Name, string Value);

public sealed record InspectorContent(
  IReadOnlyList<InspectorField> Fields,
  IReadOnlyList<InspectorField> AdditionalFields);

public interface IInspectorSectionProvider
{
  string NodeType { get; }
  bool Supports(string type);
  InspectorContent Inspect(JsonElement element);
}

public abstract class NodeDetailsProviderBase : IInspectorSectionProvider
{
  private static readonly JsonSerializerOptions PrettyJson = new() { WriteIndented = true };
  private readonly string[] orderedFields;

  protected NodeDetailsProviderBase(string nodeType, params string[] orderedFields)
  {
    NodeType = nodeType;
    this.orderedFields = orderedFields;
  }

  public string NodeType { get; }

  public virtual bool Supports(string type) =>
    string.Equals(type, NodeType, StringComparison.Ordinal);

  public InspectorContent Inspect(JsonElement element)
  {
    if (element.ValueKind != JsonValueKind.Object)
      return new([], []);

    var fields = new List<InspectorField>();
    var consumed = new HashSet<string>(StringComparer.Ordinal)
    {
      "id",
      "type",
    };

    foreach (var key in orderedFields)
    {
      consumed.Add(key);
      if (element.TryGetProperty(key, out var value))
        fields.Add(new InspectorField(key, FormatValue(value)));
    }

    var additional = element
      .EnumerateObject()
      .Where(property => !consumed.Contains(property.Name))
      .OrderBy(property => property.Name, StringComparer.Ordinal)
      .Select(property => new InspectorField(property.Name, FormatValue(property.Value)))
      .ToArray();

    return new(fields, additional);
  }

  protected static string FormatValue(JsonElement value) => value.ValueKind switch
  {
    JsonValueKind.Null => "null",
    JsonValueKind.String => value.GetString() ?? string.Empty,
    JsonValueKind.True => "true",
    JsonValueKind.False => "false",
    JsonValueKind.Array or JsonValueKind.Object => JsonSerializer.Serialize(value, PrettyJson),
    _ => value.GetRawText(),
  };
}

public sealed class FunctionNodeDetailsProvider()
  : NodeDetailsProviderBase(
    "FUNCTION",
    "address",
    "name",
    "symbol_name",
    "external",
    "internal",
    "thunk",
    "section",
    "size");

public sealed class ApiNodeDetailsProvider()
  : NodeDetailsProviderBase(
    "API",
    "name",
    "normalized_name",
    "original_names");

public sealed class StringNodeDetailsProvider()
  : NodeDetailsProviderBase(
    "STRING",
    "address",
    "value",
    "raw_value",
    "category",
    "categories",
    "reference_count");

public sealed class StringCategoryNodeDetailsProvider()
  : NodeDetailsProviderBase(
    "STRING_CATEGORY",
    "name",
    "category");

public sealed class ConstantNodeDetailsProvider()
  : NodeDetailsProviderBase(
    "CONSTANT",
    "category",
    "value",
    "value_hex",
    "symbolic_names",
    "bit_lengths");

public sealed class SectionNodeDetailsProvider()
  : NodeDetailsProviderBase(
    "SECTION",
    "name",
    "start",
    "end",
    "size",
    "permissions",
    "read",
    "write",
    "execute",
    "initialized",
    "entropy",
    "entropy_class",
    "entropy_sampled_bytes",
    "suspicious",
    "reasons");

public sealed class VisibilityIndicatorNodeDetailsProvider()
  : NodeDetailsProviderBase(
    "VISIBILITY_INDICATOR",
    "indicator",
    "function",
    "signals",
    "indirect_callsites",
    "indirect_call_count",
    "resolved_indirect_callsites",
    "resolved_indirect_call_count",
    "unresolved_indirect_callsites",
    "unresolved_indirect_call_count",
    "dynamic_dispatch_callsites",
    "dynamic_dispatch_count",
    "dynamic_dispatch_targets",
    "dynamic_dispatch_recognition");

public sealed class FallbackNodeDetailsProvider : IInspectorSectionProvider
{
  private static readonly JsonSerializerOptions PrettyJson = new() { WriteIndented = true };

  public string NodeType => "*";

  public bool Supports(string type) => true;

  public InspectorContent Inspect(JsonElement element)
  {
    if (element.ValueKind != JsonValueKind.Object)
      return new([], []);

    var fields = element
      .EnumerateObject()
      .Where(property => property.Name is not "id" and not "type")
      .Select(property => new InspectorField(property.Name, FormatValue(property.Value)))
      .ToArray();

    return new(fields, []);
  }

  private static string FormatValue(JsonElement value) => value.ValueKind switch
  {
    JsonValueKind.Null => "null",
    JsonValueKind.String => value.GetString() ?? string.Empty,
    JsonValueKind.True => "true",
    JsonValueKind.False => "false",
    JsonValueKind.Array or JsonValueKind.Object => JsonSerializer.Serialize(value, PrettyJson),
    _ => value.GetRawText(),
  };
}

public sealed class InspectorRegistry
{
  private readonly IInspectorSectionProvider[] providers;
  private readonly IInspectorSectionProvider fallback = new FallbackNodeDetailsProvider();

  public InspectorRegistry(IEnumerable<IInspectorSectionProvider>? providers = null)
  {
    var registered = providers?.ToArray() ?? [];
    this.providers = registered.Length > 0
      ? registered
      :
      [
        new FunctionNodeDetailsProvider(),
        new ApiNodeDetailsProvider(),
        new StringNodeDetailsProvider(),
        new StringCategoryNodeDetailsProvider(),
        new ConstantNodeDetailsProvider(),
        new SectionNodeDetailsProvider(),
        new VisibilityIndicatorNodeDetailsProvider(),
      ];
  }

  public IInspectorSectionProvider Resolve(string type) =>
    providers.FirstOrDefault(provider => provider.Supports(type)) ?? fallback;

  public InspectorContent Inspect(JsonElement element) =>
    Resolve(element.Text("type")).Inspect(element);
}

public interface INavigationSectionProvider
{
  IReadOnlyList<string> Sections { get; }
}

public sealed class CurrentNavigationProvider : INavigationSectionProvider
{
  public IReadOnlyList<string> Sections { get; } = ["Overview", "Full Graph", "Seeds"];
}

public interface IArtifactViewProvider
{
  string ArtifactKind { get; }
}
