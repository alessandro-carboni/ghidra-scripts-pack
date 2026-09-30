using System.IO;
using System.Windows;
using System.Windows.Input;
using System.Windows.Controls;
using GhidraTriage.Gui.App.Services;
using GhidraTriage.Gui.App.ViewModels;
using Microsoft.Web.WebView2.Core;
namespace GhidraTriage.Gui.App;

public partial class MainWindow : Window
{
  private readonly MainViewModel vm;
  private readonly GraphViewBridge bridge;
  public MainWindow(MainViewModel viewModel, GraphViewBridge bridge)
  {
    InitializeComponent(); vm = viewModel; this.bridge = bridge; DataContext = vm; Loaded += InitializeGraph; Closed += (_, _) => { vm.CancelAnalysisCommand.Execute(null); vm.SavePanelWidths(LeftColumn.ActualWidth, RightColumn.ActualWidth); GraphHost.Dispose(); }; LeftColumn.Width = new GridLength(Math.Clamp(vm.Settings.LeftWidth, 230, 450)); RightColumn.Width = new GridLength(Math.Clamp(vm.Settings.RightWidth, 230, 450));
    bridge.Outbound += json => GraphHost.CoreWebView2?.PostWebMessageAsJson(json);
  }
  private async void InitializeGraph(object sender, RoutedEventArgs e)
  {
    try
    {
      var cache = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "GhidraTriage", "WebView2");
      var environment = await CoreWebView2Environment.CreateAsync(userDataFolder: cache);
      await GraphHost.EnsureCoreWebView2Async(environment);
      GraphHost.CoreWebView2.SetVirtualHostNameToFolderMapping("graph.local", Path.Combine(AppContext.BaseDirectory, "web"), CoreWebView2HostResourceAccessKind.DenyCors);
      GraphHost.CoreWebView2.NavigationStarting += (_, args) => { if (!args.Uri.StartsWith("https://graph.local/", StringComparison.Ordinal)) args.Cancel = true; };
      GraphHost.CoreWebView2.NewWindowRequested += (_, args) => args.Handled = true;
      GraphHost.CoreWebView2.WebMessageReceived += (_, args) => { try { if (args.Source.StartsWith("https://graph.local/", StringComparison.Ordinal)) bridge.Receive(args.WebMessageAsJson); } catch (Exception ex) { vm.Error = ex.Message; } };
      GraphHost.Source = new Uri("https://graph.local/index.html");
      var args = Environment.GetCommandLineArgs();
      if (args.Length > 2 && args[1] == "--sample") { vm.SamplePath = args[2]; if (args.Contains("--analyze")) await vm.AnalyzeCommand.ExecuteAsync(null); } else if (args.Length > 1 && File.Exists(args[1])) await vm.OpenPathAsync(args[1]);
      var verifyIndex = Array.IndexOf(args, "--verify"); if (verifyIndex >= 0 && verifyIndex + 1 < args.Length) await Diagnostics.GuiSmokeFlow.RunAsync(vm, bridge, args[verifyIndex + 1]);
    }
    catch (Exception ex) { vm.Error = "Renderer unavailable: " + ex.Message; }
  }
  private async void OnDrop(object sender, DragEventArgs e) { if (e.Data.GetData(DataFormats.FileDrop) is string[] paths && paths.Length == 1) await vm.OpenPathAsync(paths[0]); }
  private void OnKey(object sender, KeyEventArgs e)
  {
    if (e.Key == Key.F && Keyboard.Modifiers == ModifierKeys.Control) { NodeSearchBox.Focus(); e.Handled = true; }
    else if (e.Key == Key.F && Keyboard.Modifiers == ModifierKeys.None && Keyboard.FocusedElement is not TextBox) { vm.FitCommand.Execute(null); e.Handled = true; }
  }
}



