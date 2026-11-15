"""Session Host diagnostics window QSS."""

from session_sniffer.guis.theming import themed_qss

HOST_DIAGNOSTICS_HERO_SUCCESS_STYLESHEET = themed_qss(
    """
QFrame#hostHeroSuccess {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 @surface~success/18, stop:1 @surface~success/10);
    border: 1px solid @success/45;
    border-left: 5px solid @success;
    border-radius: 8px;
    padding: 10px 14px;
}
""".strip(),
)

HOST_DIAGNOSTICS_HERO_FAILURE_STYLESHEET = themed_qss(
    """
QFrame#hostHeroFailure {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 @surface~warning/18, stop:1 @surface~warning/10);
    border: 1px solid @warning/45;
    border-left: 5px solid @warning;
    border-radius: 8px;
    padding: 10px 14px;
}
""".strip(),
)

HOST_DIAGNOSTICS_SECTION_CARD_STYLESHEET = themed_qss(
    """
QFrame#hostSectionCard {
    background-color: @surface;
    border: 1px solid @border;
    border-radius: 8px;
    padding: 10px 12px;
}
""".strip(),
)

HOST_DIAGNOSTICS_CHECKLIST_ROW_STYLESHEET = themed_qss(
    """
QFrame#hostChecklistRow {
    background-color: @table;
    border: 1px solid @border;
    border-radius: 6px;
    padding: 6px 10px;
}
""".strip(),
)

HOST_DIAGNOSTICS_STAT_BOX_STYLESHEET = themed_qss(
    """
QFrame#hostStatBox {
    background-color: @table;
    border: 1px solid @border;
    border-radius: 6px;
    padding: 8px 10px;
}
""".strip(),
)

HOST_DIAGNOSTICS_CANDIDATE_CARD_STYLESHEET = themed_qss(
    """
QFrame#hostCandidateCard {
    background-color: @surface;
    border: 1px solid @border;
    border-radius: 8px;
    padding: 10px 12px;
}
""".strip(),
)

HOST_DIAGNOSTICS_CANDIDATE_HOST_STYLESHEET = themed_qss(
    """
QFrame#hostCandidateCard {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 @surface~warning/16, stop:1 @surface);
    border: 1px solid @warning/50;
    border-radius: 8px;
    padding: 10px 12px;
}
""".strip(),
)

HOST_BADGE_SUCCESS_STYLESHEET = themed_qss(
    'background-color: @surface~success/18; color: @success; '
    'border: 1px solid @success/45; border-radius: 4px; '
    'padding: 2px 7px; font-weight: bold; font-size: 8.5pt;',
)

HOST_BADGE_WARNING_STYLESHEET = themed_qss(
    'background-color: @surface~warning/18; color: @warning; '
    'border: 1px solid @warning/45; border-radius: 4px; '
    'padding: 2px 7px; font-weight: bold; font-size: 8.5pt;',
)

HOST_BADGE_DANGER_STYLESHEET = themed_qss(
    'background-color: @surface~danger/18; color: @danger; '
    'border: 1px solid @danger/45; border-radius: 4px; '
    'padding: 2px 7px; font-weight: bold; font-size: 8.5pt;',
)

HOST_BADGE_INFO_STYLESHEET = themed_qss(
    'background-color: @surface~accent/18; color: @accent; '
    'border: 1px solid @accent/45; border-radius: 4px; '
    'padding: 2px 7px; font-weight: bold; font-size: 8.5pt;',
)

HOST_BADGE_MUTED_STYLESHEET = themed_qss(
    'background-color: @surface; color: @text_muted; border: 1px solid @border; border-radius: 4px; padding: 2px 7px; font-size: 8.5pt;',
)
