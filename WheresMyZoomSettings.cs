using ExileCore2.Shared.Interfaces;
using ExileCore2.Shared.Nodes;

namespace WheresMyZoom;

public class WheresMyZoomSettings : ISettings
{
    public ToggleNode Enable { get; set; } = new ToggleNode(false);

    public ButtonNode EnableZoom { get; set; } = new ButtonNode();
    //public ButtonNode EnableFastZoom { get; set; } = new ButtonNode();
    //public ButtonNode EnableNoFog { get; set; } = new ButtonNode();
    //public ButtonNode EnableNoBlackBox { get; set; } = new ButtonNode();
    public ButtonNode EnableBrightness { get; set; } = new ButtonNode();
}