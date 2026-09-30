using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using GhidraTriage.Gui.App.ViewModels;
using GhidraTriage.Gui.App.Services;
using GhidraTriage.Gui.Core.Models;
using GhidraTriage.Gui.Core.Selection;
using GhidraTriage.Gui.Core.Services;
using GhidraTriage.Gui.Infrastructure.Dataset;
using GhidraTriage.Gui.Infrastructure.Export;
namespace GhidraTriage.Gui.App;

public partial class App : Application
{
  private ServiceProvider? services;
  protected override void OnStartup(StartupEventArgs e)
  {
    base.OnStartup(e);
    DispatcherUnhandledException += (_, args) => { var folder = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "GhidraTriage"); System.IO.Directory.CreateDirectory(folder); System.IO.File.AppendAllText(System.IO.Path.Combine(folder, "errors.log"), args.Exception.ToString() + Environment.NewLine); };
    services = new ServiceCollection().AddSingleton<IAnalysisDatasetLoader, AnalysisDatasetLoader>().AddSingleton<GraphViewBridge>().AddSingleton<SelectionService>().AddSingleton<InspectorRegistry>().AddSingleton<IGraphExportService, GraphExportService>().AddSingleton<IProcessExecutionService, GhidraTriage.Gui.Infrastructure.Backend.ProcessExecutionService>().AddSingleton<IAnalysisRunner, GhidraTriage.Gui.Infrastructure.Backend.CurrentBridgeAnalysisRunner>().AddSingleton<GhidraTriage.Gui.Infrastructure.Settings.GuiSettingsStore>().AddSingleton<MainViewModel>().AddSingleton<MainWindow>().BuildServiceProvider();
    services.GetRequiredService<MainWindow>().Show();
  }
  protected override void OnExit(ExitEventArgs e) { services?.Dispose(); base.OnExit(e); }
}


