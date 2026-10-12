using System.Globalization;
using System.Windows;
using System.Windows.Data;
namespace GhidraTriage.Gui.App.Converters;

public sealed class NonEmptyVisibilityConverter : IValueConverter
{
  public object Convert(object value, Type targetType, object parameter, CultureInfo culture) => string.IsNullOrWhiteSpace(value?.ToString()) ? Visibility.Collapsed : Visibility.Visible;
  public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

