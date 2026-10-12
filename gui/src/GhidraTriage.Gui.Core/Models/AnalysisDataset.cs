using GhidraTriage.Gui.Core.Contracts;
namespace GhidraTriage.Gui.Core.Models;

public sealed record DatasetPaths(string Manifest, string Directory, string? RawReport);
public sealed record DatasetVersionInfo(string Manifest, string Graph, string Seed, string Local);
public sealed record AnalysisDataset(SeededManifestDto Manifest, DatasetPaths Paths, DatasetVersionInfo Versions, IReadOnlyDictionary<string, SubgraphEntryDto> Subgraphs, IReadOnlyList<string> Warnings);
public interface IAnalysisDatasetLoader
{
  Task<AnalysisDataset> LoadAsync(string manifestPath, CancellationToken cancellationToken = default);
  Task<TypedGraphDto> LoadTypedGraphAsync(AnalysisDataset dataset, CancellationToken cancellationToken = default);
  Task<LocalSubgraphDto> LoadLocalAsync(AnalysisDataset dataset, string seedId, CancellationToken cancellationToken = default);
}

