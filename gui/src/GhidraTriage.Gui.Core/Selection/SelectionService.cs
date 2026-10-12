namespace GhidraTriage.Gui.Core.Selection;

public sealed record GraphSelection(string Kind, string Id);
public sealed class SelectionService
{
  public GraphSelection? Current { get; private set; }
  public event Action<GraphSelection?>? Changed;
  public void Select(GraphSelection? selection) { Current = selection; Changed?.Invoke(selection); }
}

