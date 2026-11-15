"""GUI-focused multi-line HTML templates.

Keep HTML blobs used for Qt/Rich-text rendering here so non-GUI modules don't depend on GUI styling.
"""

import html
from typing import TYPE_CHECKING

from session_sniffer.constants.local import VERSION
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.theming import themed_qss
from session_sniffer.i18n import tr

if TYPE_CHECKING:
    from session_sniffer.capture.packet_capture import PacketCapture


_CAPTURE_STOPPED_HTML_TEMPLATE: str = """
<div style="background: linear-gradient(90deg, #bf616a, #d08770); padding: 10px;
            margin-top: 10px; border: 2px solid #bf616a; border-radius: 6px;
            box-shadow: 0px 3px 8px rgba(191, 97, 106, 0.4); text-align: center;">
    <span style="font-size: 14pt; font-weight: bold; color: #ffeb3b;">{label}</span>
</div>
"""


_GUI_HEADER_HTML_TEMPLATE: str = """
<div style="background: linear-gradient(90deg, #2e3440, #4c566a); color: white; padding: 15px;
            border: 2px solid #88c0d0; border-radius: 8px; box-shadow: 0px 4px 10px rgba(0, 0, 0, 0.3);">
    <div style="text-align: center;">
        <span style="font-size: 18pt; color: #88c0d0; font-weight: bold;">{title}</span>&nbsp;&nbsp;<span style="font-size: 10pt; color: #aaa">{version}</span>
    </div>
    <p style="font-size: 10pt; margin: 8px 0 0 0; text-align: center; color: #d8dee9;">
        {tagline}
    </p>
    {stop_status}
</div>
"""


def generate_gui_header_html(*, capture: PacketCapture) -> str:
    """Generate the GUI header HTML based on capture state."""
    stop_status = '' if capture.is_running() else _CAPTURE_STOPPED_HTML_TEMPLATE.format(label=html.escape(tr('CAPTURE STOPPED')))

    return themed_qss(
        _GUI_HEADER_HTML_TEMPLATE.format(
            title=html.escape(TITLE),
            version=html.escape(VERSION),
            tagline=html.escape(tr('The FREE and Open-Source IP Puller')),
            stop_status=stop_status,
        ),
    )
