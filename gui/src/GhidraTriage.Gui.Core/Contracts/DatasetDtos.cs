using System.Text.Json;
using System.Text.Json.Serialization;
namespace GhidraTriage.Gui.Core.Contracts;

public abstract record ExtensibleDto
{
  [JsonExtensionData] public Dictionary<string, JsonElement>? Additional { get; init; }
}
public sealed record SeededManifestDto : ExtensibleDto
{
  public required string SchemaVersion { get; init; }
  public required string LocalSubgraphSchemaVersion { get; init; }
  public required string SourceReport { get; init; }
  public required string SampleName { get; init; }
  public required string GraphVersion { get; init; }
  public required string SeedRulesVersion { get; init; }
  public required SeedDetectionDto SeedDetection { get; init; }
  public required SubgraphEntryDto[] Subgraphs { get; init; }
  public required RelatedGroupDto[] RelatedSeedGroups { get; init; }
  public required JsonElement ExtractionConfig { get; init; }
}
public sealed record SeedDetectionDto : ExtensibleDto
{
  public required string ModelVersion { get; init; }
  public required SeedDto[] Seeds { get; init; }
  public int Returned { get; init; }
  public int TotalDetected { get; init; }
  public bool Truncated { get; init; }
}
public sealed record SeedDto : ExtensibleDto
{
  public required string SeedId { get; init; }
  public required string AnchorFunctionId { get; init; }
  public required string[] TriggerIds { get; init; }
  public required string[] Families { get; init; }
  public required JsonElement[] Evidence { get; init; }
  public required string[] Reasons { get; init; }
}
public sealed record SubgraphEntryDto : ExtensibleDto
{
  public required string SeedId { get; init; }
  public required string AnchorFunctionId { get; init; }
  public required string File { get; init; }
  public bool Truncated { get; init; }
  public int FunctionNodes { get; init; }
  public int EvidenceNodes { get; init; }
  public int TotalNodes { get; init; }
  public int Edges { get; init; }
  public int UnresolvedCalls { get; init; }
}
public sealed record RelatedGroupDto : ExtensibleDto
{
  public required string GroupId { get; init; }
  public required string[] SeedIds { get; init; }
  public required string[] AnchorFunctionIds { get; init; }
  public required string[] Reasons { get; init; }
}
public record GraphDto : ExtensibleDto
{
  public required JsonElement[] Nodes { get; init; }
  public required JsonElement[] Edges { get; init; }
  public required JsonElement[] UnresolvedCalls { get; init; }
}
public sealed record TypedGraphDto : GraphDto { public required string ModelVersion { get; init; } }
public sealed record LocalSubgraphDto : GraphDto
{
  public required string SchemaVersion { get; init; }
  public required string GraphVersion { get; init; }
  public required string SeedId { get; init; }
  public required string AnchorFunctionId { get; init; }
  public required FunctionSelectionDto FunctionSelection { get; init; }
  public required JsonElement ExtractionConfig { get; init; }
  public required JsonElement Truncation { get; init; }
}
public sealed record FunctionSelectionDto : ExtensibleDto
{
  public required string AnchorFunctionId { get; init; }
  public required string[] FunctionIds { get; init; }
  public required Dictionary<string, int> CallerDistances { get; init; }
  public required Dictionary<string, int> CalleeDistances { get; init; }
}
public static class JsonField
{
  public static string Text(this JsonElement value, string key) => value.TryGetProperty(key, out var field) && field.ValueKind != JsonValueKind.Null ? field.ToString() : "";
}

