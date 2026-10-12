using CommunityToolkit.Mvvm.ComponentModel;
using GhidraTriage.Gui.Core.Contracts;
namespace GhidraTriage.Gui.App.ViewModels;

public sealed record SeedRow(SeedDto Seed, SubgraphEntryDto Entry, string Group)
{
  public string Anchor => Seed.AnchorFunctionId;
  public string Id => Seed.SeedId;
  public string Triggers => string.Join(", ", Seed.TriggerIds);
  public string Families => string.Join(" · ", Seed.Families);
  public string Summary => $"{Seed.Evidence.Length} evidence" + (Group.Length > 0 ? " · grouped" : "") + (Entry.Truncated ? " · ⚠ truncated" : "");
}
public sealed partial class TypeFilter : ObservableObject
{
  public required string Name { get; init; }
  [ObservableProperty] private bool enabled = true;
}

