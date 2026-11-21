"""Web Server settings tab QSS: access card, status badges, address boxes, inline notices, and QR card."""

from session_sniffer.guis.theming import themed_qss


def _webserver_badge_stylesheet(token: str, fg_color: str, rgb: str) -> str:
    """Build a compact status/security pill badge QSS for the Web Server settings panel."""
    return themed_qss(
        f'QLabel {{ color: @{token}[{fg_color}]; background: @{token}[rgba({rgb}, 0.14)]; '
        f'border: 1px solid @{token}[rgba({rgb}, 0.38)]; border-radius: 5px; '
        'padding: 2px 8px; font-size: 8pt; font-weight: 700; }',
    )


WEBSERVER_STATUS_BADGE_RUNNING_STYLESHEET = _webserver_badge_stylesheet('success', '#3dd68c', '61, 214, 140')

WEBSERVER_STATUS_BADGE_STOPPED_STYLESHEET = themed_qss(
    'QLabel { color: @text_muted[#94a3b8]; background: @control[rgba(148, 163, 184, 0.12)]; '
    'border: 1px solid @border[rgba(148, 163, 184, 0.30)]; border-radius: 5px; '
    'padding: 2px 8px; font-size: 8pt; font-weight: 700; }',
)

WEBSERVER_STATUS_BADGE_PENDING_STYLESHEET = _webserver_badge_stylesheet('warning', '#f59e0b', '245, 158, 11')

WEBSERVER_STATUS_BADGE_ERROR_STYLESHEET = _webserver_badge_stylesheet('danger', '#f87171', '239, 68, 68')

WEBSERVER_ADDRESS_BOX_STYLESHEET = themed_qss(
    'QLabel {'
    'background-color: @input[#141922];'
    'border: 1px solid @border[#334155];'
    'border-radius: 6px;'
    'padding: 6px 10px;'
    'color: @accent[#61afef];'
    'font-family: Menlo, Consolas, "Courier New", monospace;'
    'font-size: 10pt;'
    'font-weight: 700;'
    '}',
)

WEBSERVER_SECTION_TITLE_STYLESHEET = themed_qss(
    'QLabel { color: @text_strong[#e8edf4]; font-size: 9pt; font-weight: 700; background: transparent; }',
)

WEBSERVER_HINT_LABEL_STYLESHEET = themed_qss(
    'QLabel { color: @text_muted[#94a3b8]; font-size: 8.5pt; background: transparent; }',
)

WEBSERVER_INLINE_WARNING_STYLESHEET = themed_qss(
    'QFrame#webserverInlineWarning {'
    'background: @warning[rgba(245, 158, 11, 0.12)];'
    'border: 1px solid @warning[rgba(245, 158, 11, 0.35)];'
    'border-radius: 6px;'
    '}',
)

WEBSERVER_INLINE_ERROR_STYLESHEET = themed_qss(
    'QFrame#webserverInlineError {'
    'background: @danger[rgba(239, 68, 68, 0.12)];'
    'border: 1px solid @danger[rgba(248, 113, 113, 0.40)];'
    'border-radius: 6px;'
    '}',
)

WEBSERVER_QR_CARD_STYLESHEET = themed_qss(
    'QFrame#webserverQrCard {'
    'background-color: @lock[#ffffff];'
    'border: 1px solid @border[#3b4455];'
    'border-radius: 10px;'
    '}',
)

WEBSERVER_QR_CAPTION_STYLESHEET = themed_qss(
    'QLabel { color: @lock[#1e293b]; background: transparent; font-size: 8pt; font-weight: 700; }',
)

WEBSERVER_DIVIDER_STYLESHEET = themed_qss(
    'background: @border[rgba(61, 142, 201, 0.22)]; border: none; max-height: 1px;',
)
