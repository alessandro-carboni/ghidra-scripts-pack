using GhidraTriage.Gui.Infrastructure.Dataset;
using GhidraTriage.Gui.Core.Models;
namespace GhidraTriage.Gui.Tests;

public class RealNotepadTests
{
  [Fact]
  public async Task RealExportValidatesAllLocalGraphsAndCacheBound()
  {
    var path = Environment.GetEnvironmentVariable("SEEDED_GUI_REAL_MANIFEST");
    if (string.IsNullOrEmpty(path)) return; // Optional integration dataset; mandatory in the documented real-data validation command.
    var loader = new AnalysisDatasetLoader(); var d = await loader.LoadAsync(path); Assert.Equal(0, loader.LocalReads);
    var full = await loader.LoadTypedGraphAsync(d); Assert.NotEmpty(full.Nodes); Assert.NotEmpty(full.Edges);
    foreach (var seed in d.Manifest.SeedDetection.Seeds)
    {
      var g = await loader.LoadLocalAsync(d, seed.SeedId); var v = GraphPresentation.Project(g, seed);
      Assert.Equal(g.Nodes.Length, v.Nodes.Length); Assert.Equal(g.Edges.Length, v.Edges.Length);
      Assert.True(loader.CachedCount <= AnalysisDatasetLoader.CacheCapacity);
    }
  }
}

