using System.Windows;
using GhidraTriage.Gui.App.Services;
using GhidraTriage.Gui.App.ViewModels;
using GhidraTriage.Gui.Core.Models;
using GhidraTriage.Gui.Core.Selection;
using GhidraTriage.Gui.Core.Services;
using GhidraTriage.Gui.Infrastructure.Dataset;
using GhidraTriage.Gui.Infrastructure.Export;
using Microsoft.Extensions.DependencyInjection;

namespace GhidraTriage.Gui.App;

public partial class App : Application
{
  private ServiceProvider? services;

  protected override void OnStartup(StartupEventArgs e)
  {
    base.OnStartup(e);

    DispatcherUnhandledException += (_, args) =>
    {
      var folder = System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "GhidraTriage");
      System.IO.Directory.CreateDirectory(folder);
      System.IO.File.AppendAllText(
        System.IO.Path.Combine(folder, "errors.log"),
        args.Exception + Environment.NewLine);
    };

    services = new ServiceCollection()
      .AddSingleton<IAnalysisDatasetLoader, AnalysisDatasetLoader>()
      .AddSingleton<GraphViewBridge>()
      .AddSingleton<SelectionService>()
      .AddSingleton<IInspectorSectionProvider, FunctionNodeDetailsProvider>()
      .AddSingleton<IInspectorSectionProvider, ApiNodeDetailsProvider>()
      .AddSingleton<IInspectorSectionProvider, StringNodeDetailsProvider>()
      .AddSingleton<IInspectorSectionProvider, StringCategoryNodeDetailsProvider>()
      .AddSingleton<IInspectorSectionProvider, ConstantNodeDetailsProvider>()
      .AddSingleton<IInspectorSectionProvider, SectionNodeDetailsProvider>()
      .AddSingleton<IInspectorSectionProvider, VisibilityIndicatorNodeDetailsProvider>()
      .AddSingleton<InspectorRegistry>()
      .AddSingleton<IGraphExportService, GraphExportService>()
      .AddSingleton<IProcessExecutionService, GhidraTriage.Gui.Infrastructure.Backend.ProcessExecutionService>()
      .AddSingleton<IAnalysisRunner, GhidraTriage.Gui.Infrastructure.Backend.CurrentBridgeAnalysisRunner>()
      .AddSingleton<GhidraTriage.Gui.Infrastructure.Settings.GuiSettingsStore>()
      .AddSingleton<MainViewModel>()
      .AddSingleton<MainWindow>()
      .BuildServiceProvider();

    services.GetRequiredService<MainWindow>().Show();
  }

  protected override void OnExit(ExitEventArgs e)
  {
    services?.Dispose();
    base.OnExit(e);
  }
}
