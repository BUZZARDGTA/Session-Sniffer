"""GUI-focused multi-line HTML templates.

Keep HTML blobs used for Qt/Rich-text rendering here so non-GUI modules don't depend on GUI styling.
"""


CAPTURE_STOPPED_HTML = """
<div style="background: linear-gradient(90deg, #bf616a, #d08770); padding: 10px;
            margin-top: 10px; border: 2px solid #bf616a; border-radius: 6px;
            box-shadow: 0px 3px 8px rgba(191, 97, 106, 0.4); text-align: center;">
    <span style="font-size: 18px; font-weight: bold; color: #ffeb3b;">⏸️ CAPTURE STOPPED</span>
</div>
"""


GUI_HEADER_HTML_TEMPLATE = """
<div style="background: linear-gradient(90deg, #2e3440, #4c566a); color: white; padding: 15px;
            border: 2px solid #88c0d0; border-radius: 8px; box-shadow: 0px 4px 10px rgba(0, 0, 0, 0.3);">
    <div style="text-align: center;">
        <span style="font-size: 24px; color: #88c0d0; font-weight: bold;">{title}</span>&nbsp;&nbsp;<span style="font-size: 14px; color: #aaa">{version}</span>
    </div>
    <p style="font-size: 14px; margin: 8px 0 0 0; text-align: center; color: #d8dee9;">
        The best FREE and Open-Source packet sniffer, aka IP puller
    </p>
    {stop_status}
</div>
"""
