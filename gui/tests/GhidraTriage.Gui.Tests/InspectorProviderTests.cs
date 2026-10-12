using System.Text.Json;
using GhidraTriage.Gui.Core.Services;

namespace GhidraTriage.Gui.Tests;

public sealed class InspectorProviderTests
{
  private static JsonElement Json(string value) =>
    JsonDocument.Parse(value).RootElement.Clone();

  [Theory]
  [InlineData("FUNCTION", typeof(FunctionNodeDetailsProvider))]
  [InlineData("API", typeof(ApiNodeDetailsProvider))]
  [InlineData("STRING", typeof(StringNodeDetailsProvider))]
  [InlineData("STRING_CATEGORY", typeof(StringCategoryNodeDetailsProvider))]
  [InlineData("CONSTANT", typeof(ConstantNodeDetailsProvider))]
  [InlineData("SECTION", typeof(SectionNodeDetailsProvider))]
  [InlineData("VISIBILITY_INDICATOR", typeof(VisibilityIndicatorNodeDetailsProvider))]
  public void RegistryResolvesDedicatedProviderForEveryCurrentNodeType(
    string type,
    Type expectedProvider)
  {
    var registry = new InspectorRegistry();

    Assert.IsType(expectedProvider, registry.Resolve(type));
  }

  [Fact]
  public void FunctionProviderUsesTypedOrderAndKeepsFuturePropertiesSeparate()
  {
    var node = Json("""
      {
        "id": "fn:1400012dc",
        "type": "FUNCTION",
        "address": "1400012dc",
        "name": "FUN_1400012dc",
        "symbol_name": "FUN_1400012dc",
        "external": false,
        "internal": true,
        "thunk": false,
        "section": ".text",
        "size": 157,
        "future_backend_field": { "mode": "preserved" }
      }
      """);

    var result = new InspectorRegistry().Inspect(node);

    Assert.Equal(
      new[] { "address", "name", "symbol_name", "external", "internal", "thunk", "section", "size" },
      result.Fields.Select(field => field.Name));
    Assert.DoesNotContain(result.Fields, field => field.Name is "id" or "type");
    var additional = Assert.Single(result.AdditionalFields);
    Assert.Equal("future_backend_field", additional.Name);
    Assert.Contains("preserved", additional.Value);
  }

  [Fact]
  public void MissingOptionalPropertiesDoNotCreateInventedFields()
  {
    var node = Json("""
      {
        "id": "api:eventwritetransfer",
        "type": "API",
        "name": "EventWriteTransfer"
      }
      """);

    var result = new InspectorRegistry().Inspect(node);

    var field = Assert.Single(result.Fields);
    Assert.Equal("name", field.Name);
    Assert.Equal("EventWriteTransfer", field.Value);
    Assert.Empty(result.AdditionalFields);
  }

  [Fact]
  public void ArraysObjectsNullsAndBooleansRemainSourceData()
  {
    var node = Json("""
      {
        "id": "vis:call_visibility:fn:1",
        "type": "VISIBILITY_INDICATOR",
        "indicator": "call_visibility",
        "function": "fn:1",
        "signals": ["indirect_call"],
        "dynamic_dispatch_recognition": null,
        "future_flag": true
      }
      """);

    var result = new InspectorRegistry().Inspect(node);

    Assert.Contains(result.Fields, field =>
      field.Name == "signals" && field.Value.Contains("indirect_call", StringComparison.Ordinal));
    Assert.Contains(result.Fields, field =>
      field.Name == "dynamic_dispatch_recognition" && field.Value == "null");
    Assert.Contains(result.AdditionalFields, field =>
      field.Name == "future_flag" && field.Value == "true");
  }

  [Fact]
  public void UnknownTypeFallsBackWithoutDroppingSourceProperties()
  {
    var node = Json("""
      {
        "id": "future:1",
        "type": "FUTURE_NODE",
        "alpha": "one",
        "beta": 2
      }
      """);

    var registry = new InspectorRegistry();
    var provider = registry.Resolve("FUTURE_NODE");
    var result = registry.Inspect(node);

    Assert.IsType<FallbackNodeDetailsProvider>(provider);
    Assert.Equal(new[] { "alpha", "beta" }, result.Fields.Select(field => field.Name));
    Assert.Empty(result.AdditionalFields);
  }

  [Fact]
  public void RegistryCanBeExtendedWithoutChangingItsImplementation()
  {
    var custom = new CustomProvider();
    var registry = new InspectorRegistry(new[] { custom });
    var node = Json("""
      {
        "id": "future:1",
        "type": "FUTURE_NODE",
        "payload": "backend-owned"
      }
      """);

    Assert.Same(custom, registry.Resolve("FUTURE_NODE"));
    Assert.Equal("backend-owned", Assert.Single(registry.Inspect(node).Fields).Value);
  }

  private sealed class CustomProvider : IInspectorSectionProvider
  {
    public string NodeType => "FUTURE_NODE";

    public bool Supports(string type) => type == NodeType;

    public InspectorContent Inspect(JsonElement element) =>
      new([new InspectorField("payload", element.GetProperty("payload").GetString()!)], []);
  }
}
