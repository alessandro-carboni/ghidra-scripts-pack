using System.Text.Json;
namespace GhidraTriage.Gui.Core.Contracts;

public sealed record BridgeEnvelope(string Version, string Type, JsonElement? Payload = null)
{
  public const string CurrentVersion = "0.1.0";
  public static BridgeEnvelope Parse(string json)
  {
    var message = JsonSerializer.Deserialize<BridgeEnvelope>(json, new JsonSerializerOptions(JsonSerializerDefaults.Web)) ?? throw new JsonException("Empty bridge message");
    if (message.Version != CurrentVersion || string.IsNullOrWhiteSpace(message.Type)) throw new JsonException("Unsupported bridge envelope");
    return message;
  }
}
