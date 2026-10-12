using System.Text.Json;
using GhidraTriage.Gui.Core.Contracts;
namespace GhidraTriage.Gui.App.Services;

public sealed class GraphViewBridge
{
  public event Action<string>? Outbound;
  public event Action<BridgeEnvelope>? Inbound;
  public void Send(string type, object? payload = null) => Outbound?.Invoke(JsonSerializer.Serialize(new { version = BridgeEnvelope.CurrentVersion, type, payload }, new JsonSerializerOptions(JsonSerializerDefaults.Web)));
  public void Receive(string message) => Inbound?.Invoke(BridgeEnvelope.Parse(message));
}

