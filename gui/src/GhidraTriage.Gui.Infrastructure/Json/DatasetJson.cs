using System.Text.Json;
namespace GhidraTriage.Gui.Infrastructure.Json;

public static class DatasetJson
{
  public static JsonSerializerOptions Options { get; } = new() { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower, WriteIndented = true };
  public static async Task<T> ReadAsync<T>(string path, CancellationToken ct = default)
  {
    try
    {
      await using var stream = File.OpenRead(path);
      return await JsonSerializer.DeserializeAsync<T>(stream, Options, ct) ?? throw new InvalidDataException("Empty JSON document: " + path);
    }
    catch (JsonException e) { throw new InvalidDataException("Invalid JSON in " + path + ": " + e.Message, e); }
  }
}

