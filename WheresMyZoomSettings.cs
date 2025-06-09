using ExileCore.Shared.Attributes;
using ExileCore.Shared.Interfaces;
using ExileCore.Shared.Nodes;

namespace WheresMyZoom;

public class WheresMyZoomSettings : ISettings
{
    public ToggleNode Enable { get; set; } = new ToggleNode(false);

    [Menu("Zoom Menu")]
    public ZoomMenu ZoomMenu { get; set; } = new ZoomMenu();

    [Menu("QOL Menu")]
    public QOLMenu QOLMenu { get; set; } = new QOLMenu();
}

[Submenu(CollapsedByDefault = false)]
public class ZoomMenu
{
    [Menu("Enable Unzoom", "Scroll Mouse Wheel to unzoom further.")]
    public ButtonNode EnableZoom { get; set; } = new ButtonNode();
    [Menu("Enable Unzoom at Launch", "Scroll Mouse Wheel to unzoom further.")]
    public ToggleNode EnableZoomAtLaunch { get; set; } = new ToggleNode(false);

    [Menu("Enable Fast Zoom", "Scroll Mouse Wheel unzoom faster.")]
    public ButtonNode EnableFastZoom { get; set; } = new ButtonNode();
    [Menu("Enable Fast Zoom at Launch", "Scroll Mouse Wheel unzoom faster.")]
    public ToggleNode EnableFastZoomAtLaunch { get; set; } = new ToggleNode(false);
}

[Submenu(CollapsedByDefault = false)]
public class QOLMenu
{
    public ButtonNode EnableNoFog { get; set; } = new ButtonNode();
    public ToggleNode EnableNoFogAtLaunch { get; set; } = new ToggleNode(false);

    public ButtonNode EnableNoBlackBox { get; set; } = new ButtonNode();
    public ToggleNode EnableNoBlackBoxAtLaunch { get; set; } = new ToggleNode(false);

    public ButtonNode EnableBrightness { get; set; } = new ButtonNode();
    public ToggleNode EnableBrightnessAtLaunch { get; set; } = new ToggleNode(false);
}