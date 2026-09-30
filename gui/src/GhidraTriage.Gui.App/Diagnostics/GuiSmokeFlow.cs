using System.IO;
using System.Text.Json;
using GhidraTriage.Gui.App.Services;
using GhidraTriage.Gui.App.ViewModels;
using GhidraTriage.Gui.Core.Contracts;
using GhidraTriage.Gui.Infrastructure.Export;
namespace GhidraTriage.Gui.App.Diagnostics;
// Explicit developer entry point. Exercises the running WPF + WebView2 bridge on real backend artifacts.
internal static class GuiSmokeFlow
{
  public static async Task RunAsync(MainViewModel vm, GraphViewBridge bridge, string directory)
  {
    Directory.CreateDirectory(directory);
    var checks = new List<string>();
    try
    {
      await Until(() => vm.RendererReady, "WebView2 ready");
      Check(vm.CurrentDataset != null, "dataset loaded", checks);
      var original = vm.CurrentDataset!;
      var rendered = Next(bridge, "layoutCompleted");
      await vm.FullGraphCommand.ExecuteAsync(null); await rendered;
      Check(vm.CurrentVisual!.Nodes.Length == vm.CurrentGraph!.Nodes.Length, "full topology counts preserved", checks);
      await Export(vm, bridge, directory, "full");
      foreach (var type in vm.CurrentVisual.Nodes.Select(n => n.Type).Distinct().ToArray())
      {
        var node = vm.CurrentVisual.Nodes.First(n => n.Type == type);
        var selected = Next(bridge, "nodeSelected");
        vm.FocusCommand.Execute(node.Id); await selected;
        Check(vm.InspectorId == node.Id && vm.Fields.Count > 0, "node inspector " + type, checks);
      }
      var edge = vm.CurrentVisual.Edges[0]; var edgeSelected = Next(bridge, "edgeSelected");
      bridge.Send("setSelection", new { id = edge.Id, notify = true }); await edgeSelected;
      Check(vm.SourceId == edge.Source && vm.TargetId == edge.Target, "edge inspector source/target preserved", checks);
      var fullSnapshot = JsonSerializer.Serialize(vm.CurrentGraph);
      vm.NodeTypes[0].Enabled = false; await Task.Delay(100); vm.ResetFiltersCommand.Execute(null);
      Check(fullSnapshot == JsonSerializer.Serialize(vm.CurrentGraph), "filter/reset source immutability", checks);
      vm.NodeSearch = vm.CurrentVisual.Nodes[0].Id; vm.SearchCommand.Execute(null); await Task.Delay(250);
      Check(vm.SearchResults.Count > 0, "node search results", checks);
      vm.UnresolvedCommand.Execute(null);
      Check(vm.TargetId == "", "unresolved has no focus target", checks);
      vm.SelectedSeed = vm.Seeds[0]; await Until(() => !vm.IsBusy && vm.CurrentGraph is LocalSubgraphDto, "local graph load");
      await Task.Delay(400);
      Check(vm.CurrentVisual!.Nodes.Count(n => n.Anchor) == 1, "one real anchor", checks);
      Check(vm.CurrentVisual.Nodes.Where(n => n.Trigger).All(n => vm.SelectedSeed.Seed.Evidence.Any(e => e.Text("node_id") == n.Id)), "trigger uses backend evidence IDs", checks);
      await Export(vm, bridge, directory, "local");
      vm.TriggerOnly = true; await Task.Delay(100); vm.ResetFiltersCommand.Execute(null);
      if (vm.Seeds.Count > 2) { vm.SelectedSeed = vm.Seeds[1]; vm.SelectedSeed = vm.Seeds[2]; await Until(() => !vm.IsBusy, "rapid seed switching"); Check(((LocalSubgraphDto)vm.CurrentGraph!).SeedId == vm.SelectedSeed.Id, "stale load protection", checks); }
      var grouped = vm.Seeds.FirstOrDefault(s => s.Group.Length > 0);
      if (grouped != null) { vm.SelectedSeed = grouped; await Until(() => !vm.IsBusy, "group seed"); vm.RelatedGroupCommand.Execute(null); Check(vm.Seeds.All(s => original.Manifest.RelatedSeedGroups.Where(g => g.SeedIds.Contains(grouped.Id)).Any(g => g.SeedIds.Contains(s.Id))), "related group uses manifest membership", checks); vm.ResetSeedFiltersCommand.Execute(null); }
      rendered = Next(bridge, "layoutCompleted"); await vm.FullGraphCommand.ExecuteAsync(null); await rendered; checks.Add("return to full graph");
      vm.SelectedSeed = vm.Seeds[0]; await Until(() => !vm.IsBusy, "final local view"); await Task.Delay(300); vm.FitCommand.Execute(null);
      if (vm.CurrentGraph is LocalSubgraphDto local && local.Truncation.GetProperty("truncated").GetBoolean()) Check(vm.Warning.Contains("technical resource limit"), "truncation banner", checks);
      Check(vm.Error.Length == 0, "no UI error", checks);
      File.WriteAllText(Path.Combine(directory, "result.json"), JsonSerializer.Serialize(new { status = "PASS", manifest = original.Paths.Manifest, sample = vm.Sample, seedCount = original.Manifest.SeedDetection.Returned, checks }, new JsonSerializerOptions { WriteIndented = true }));
      vm.Status = "Real WPF/WebView2 smoke flow passed · " + checks.Count + " checks";
    }
    catch (Exception ex) { File.WriteAllText(Path.Combine(directory, "result.json"), JsonSerializer.Serialize(new { status = "FAIL", error = ex.ToString(), checks }, new JsonSerializerOptions { WriteIndented = true })); vm.Error = "Smoke flow failed: " + ex.Message; }
  }
  private static async Task Export(MainViewModel vm, GraphViewBridge bridge, string directory, string name)
  {
    var png = Next(bridge, "pngExported"); bridge.Send("exportPng");
    var payload = (await png).Payload!.Value;
    await File.WriteAllBytesAsync(Path.Combine(directory, name + ".png"), Convert.FromBase64String(payload.Text("data")));
    await File.WriteAllTextAsync(Path.Combine(directory, name + ".dot"), new GraphExportService().ToDot(vm.CurrentVisual!));
  }
  private static async Task Until(Func<bool> predicate, string label) { var deadline = DateTime.UtcNow.AddSeconds(30); while (!predicate()) { if (DateTime.UtcNow > deadline) throw new TimeoutException(label); await Task.Delay(30); } }
  private static Task<BridgeEnvelope> Next(GraphViewBridge bridge, string type)
  {
    var source = new TaskCompletionSource<BridgeEnvelope>(TaskCreationOptions.RunContinuationsAsynchronously);
    void Handler(BridgeEnvelope e) { if (e.Type == type) { bridge.Inbound -= Handler; source.TrySetResult(e); } else if (e.Type == "renderError") { bridge.Inbound -= Handler; source.TrySetException(new InvalidOperationException(e.Payload?.ToString())); } }
    bridge.Inbound += Handler;
    return Wait();
    async Task<BridgeEnvelope> Wait() { try { return await source.Task.WaitAsync(TimeSpan.FromSeconds(30)); } finally { bridge.Inbound -= Handler; } }
  }
  private static void Check(bool condition, string label, List<string> checks) { if (!condition) throw new InvalidOperationException(label); checks.Add(label); }
}

