using GhidraTriage.Gui.Core.Contracts;
using System.Text.Json;
namespace GhidraTriage.Gui.Tests;

public class BridgeTests
{
  [Fact] public void AcceptsVersionedReady() => Assert.Equal("ready", BridgeEnvelope.Parse("{\"version\":\"0.1.0\",\"type\":\"ready\"}").Type);
  [Theory]
  [InlineData("{}")]
  [InlineData("{\"version\":\"9.0\",\"type\":\"ready\"}")]
  [InlineData("null")]
  public void RejectsInvalidEnvelope(string json) => Assert.Throws<JsonException>(() => BridgeEnvelope.Parse(json));
}
