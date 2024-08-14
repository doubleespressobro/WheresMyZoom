using ExileCore.Shared.Interfaces;
using ExileCore.Shared.Nodes;

namespace WheresMyZoom;

public class WheresMyZoomSettings : ISettings
{
    public ToggleNode Enable { get; set; } = new ToggleNode(false);

    public ButtonNode EnableZoom { get; set; } = new ButtonNode();
    public ButtonNode EnableNoFog { get; set; } = new ButtonNode();
    public ButtonNode EnableNoBlackBox { get; set; } = new ButtonNode();
}