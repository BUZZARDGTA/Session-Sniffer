"""Player identifier, player info dialog, and detection warning QSS."""

# =============================================================================
# PLAYER IDENTIFIER STYLES
# =============================================================================

PROGRESS_BAR_IDLE_STYLESHEET = ''

PROGRESS_BAR_CHUNK_GREEN_STYLESHEET = 'QProgressBar::chunk { background-color: #27ae60; }'

PROGRESS_BAR_CHUNK_RED_STYLESHEET = 'QProgressBar::chunk { background-color: #e74c3c; }'


# =============================================================================
# PLAYER INFO DIALOG STYLES
# =============================================================================

PLAYER_INFO_FORM_LABEL_STYLESHEET = 'color: #cbd5e0; font-weight: 600; background: transparent;'

PLAYER_INFO_VALUE_LABEL_STYLESHEET = 'color: #ffffff; font-weight: bold; padding: 3px 6px; border-radius: 3px; background: rgba(255, 255, 255, 12);'

DETECTION_WARN_LABEL_STYLESHEET = (
    'color: #f6e05e; font-weight: bold; padding: 4px 8px;background: rgba(214, 158, 46, 20); border: 1px solid rgba(214, 158, 46, 80);border-radius: 4px;'
)


def player_info_group_stylesheet(accent: str) -> str:
    """Return the QSS for a player info group box with the given `accent` color."""
    return (
        'QGroupBox {'
        f' border: 1px solid {accent};'
        ' border-radius: 6px;'
        ' margin-top: 14px;'
        ' padding-top: 10px;'
        ' background: rgba(255, 255, 255, 8);'
        ' font-weight: bold;'
        '}'
        'QGroupBox::title {'
        ' subcontrol-origin: margin;'
        ' subcontrol-position: top left;'
        ' left: 10px; padding: 2px 8px;'
        f' background: {accent};'
        ' color: #ffffff;'
        ' border-radius: 4px;'
        '}'
    )


def player_info_header_stylesheet(grad_stop0: str, grad_stop1: str) -> str:
    """Return the QSS for a player info dialog header label with the given gradient stops."""
    return (
        'font-size: 14pt; font-weight: bold; padding: 8px 6px;'
        'color: #ffffff; background: qlineargradient(x1:0, y1:0, x2:1, y2:0,'
        f' stop:0 {grad_stop0}, stop:1 {grad_stop1}); border-radius: 6px;'
    )
