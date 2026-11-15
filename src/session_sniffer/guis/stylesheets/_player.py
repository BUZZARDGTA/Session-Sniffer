"""Player identifier, player info dialog, and detection warning QSS."""

from session_sniffer.guis.theming import themed_qss

# =============================================================================
# PLAYER IDENTIFIER STYLES
# =============================================================================

_PROGRESS_BAR_BASE = (
    'QProgressBar {'
    ' background-color: @input;'
    ' border: 1px solid @border;'
    ' border-radius: 12px;'
    ' text-align: center;'
    ' color: @text_strong;'
    ' font-weight: 700;'
    ' font-size: 9pt;'
    ' min-height: 24px;'
    ' max-height: 24px;'
    '}'
)

PROGRESS_BAR_IDLE_STYLESHEET = themed_qss(_PROGRESS_BAR_BASE + 'QProgressBar::chunk { background-color: transparent; }')

PROGRESS_BAR_CHUNK_BLUE_STYLESHEET = themed_qss(
    _PROGRESS_BAR_BASE + 'QProgressBar::chunk {'
    ' background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 @accent:pressed, stop:0.5 @accent, stop:1 @accent:hover);'
    ' border-radius: 10px;'
    ' margin: 2px;'
    '}',
)

PROGRESS_BAR_CHUNK_GREEN_STYLESHEET = themed_qss(
    _PROGRESS_BAR_BASE + 'QProgressBar::chunk {'
    ' background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 @success:pressed, stop:0.5 @success, stop:1 @success:hover);'
    ' border-radius: 10px;'
    ' margin: 2px;'
    '}',
)

PROGRESS_BAR_CHUNK_ORANGE_STYLESHEET = themed_qss(
    _PROGRESS_BAR_BASE + 'QProgressBar::chunk {'
    ' background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 @warning:pressed, stop:0.5 @warning, stop:1 @warning:hover);'
    ' border-radius: 10px;'
    ' margin: 2px;'
    '}',
)

PROGRESS_BAR_CHUNK_RED_STYLESHEET = themed_qss(
    _PROGRESS_BAR_BASE + 'QProgressBar::chunk {'
    ' background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 @danger:pressed, stop:0.5 @danger, stop:1 @danger:hover);'
    ' border-radius: 10px;'
    ' margin: 2px;'
    '}',
)


# =============================================================================
# PLAYER INFO DIALOG STYLES
# =============================================================================

PLAYER_INFO_FORM_LABEL_STYLESHEET = themed_qss('color: @text; font-weight: 600; background: transparent;')

PLAYER_INFO_VALUE_LABEL_STYLESHEET = themed_qss('color: @text_strong; font-weight: bold; padding: 3px 6px; border-radius: 3px; background: @input;')

DETECTION_WARN_LABEL_STYLESHEET = themed_qss(
    'color: @warning; font-weight: bold; padding: 4px 8px; background: @surface~warning/18; border: 1px solid @warning/55; border-radius: 4px;',
)


def player_info_group_stylesheet(accent: str) -> str:
    """Return the QSS for a player info group box with the given `accent` color."""
    return themed_qss(
        'QGroupBox {'
        f' border: 1px solid {accent};'
        ' border-radius: 6px;'
        ' margin-top: 14px;'
        ' padding-top: 10px;'
        ' background: @surface;'
        ' font-weight: bold;'
        '}'
        'QGroupBox::title {'
        ' subcontrol-origin: margin;'
        ' subcontrol-position: top left;'
        ' left: 10px; padding: 2px 8px;'
        f' background: {accent};'
        ' color: @text_strong;'
        ' border-radius: 4px;'
        '}',
    )


def player_info_header_stylesheet(grad_stop0: str, grad_stop1: str) -> str:
    """Return the QSS for a player info dialog header label with the given gradient stops."""
    return themed_qss(
        'font-size: 14pt; font-weight: bold; padding: 8px 6px;'
        'color: @text_strong; background: qlineargradient(x1:0, y1:0, x2:1, y2:0,'
        f' stop:0 {grad_stop0}, stop:1 {grad_stop1}); border-radius: 6px;',
    )
