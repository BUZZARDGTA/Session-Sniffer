"""Session Host diagnostics window QSS."""

from session_sniffer.guis.theming import themed_qss

HOST_DIAGNOSTICS_HERO_SUCCESS_STYLESHEET = themed_qss(
    """
QFrame#hostHeroSuccess {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 @success[rgba(16, 185, 129, 0.16)], stop:1 @success[rgba(6, 78, 59, 0.22)]);
    border: 1px solid @success[rgba(16, 185, 129, 0.45)];
    border-left: 5px solid @success[#10b981];
    border-radius: 8px;
    padding: 10px 14px;
}
""".strip(),
)

HOST_DIAGNOSTICS_HERO_FAILURE_STYLESHEET = themed_qss(
    """
QFrame#hostHeroFailure {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 @warning[rgba(245, 158, 11, 0.16)], stop:1 @warning[rgba(180, 83, 9, 0.22)]);
    border: 1px solid @warning[rgba(245, 158, 11, 0.45)];
    border-left: 5px solid @warning[#f59e0b];
    border-radius: 8px;
    padding: 10px 14px;
}
""".strip(),
)

HOST_DIAGNOSTICS_SECTION_CARD_STYLESHEET = themed_qss(
    """
QFrame#hostSectionCard {
    background-color: @surface[#1a1e24];
    border: 1px solid @border[#28313e];
    border-radius: 8px;
    padding: 10px 12px;
}
""".strip(),
)

HOST_DIAGNOSTICS_CHECKLIST_ROW_STYLESHEET = themed_qss(
    """
QFrame#hostChecklistRow {
    background-color: @surface[rgba(255, 255, 255, 0.025)];
    border: 1px solid @border[rgba(255, 255, 255, 0.05)];
    border-radius: 6px;
    padding: 6px 10px;
}
""".strip(),
)

HOST_DIAGNOSTICS_STAT_BOX_STYLESHEET = themed_qss(
    """
QFrame#hostStatBox {
    background-color: @surface[rgba(255, 255, 255, 0.035)];
    border: 1px solid @border[rgba(255, 255, 255, 0.08)];
    border-radius: 6px;
    padding: 8px 10px;
}
""".strip(),
)

HOST_DIAGNOSTICS_CANDIDATE_CARD_STYLESHEET = themed_qss(
    """
QFrame#hostCandidateCard {
    background-color: @surface[#171c23];
    border: 1px solid @border[#283344];
    border-radius: 8px;
    padding: 10px 12px;
}
""".strip(),
)

HOST_DIAGNOSTICS_CANDIDATE_HOST_STYLESHEET = themed_qss(
    """
QFrame#hostCandidateCard {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 @warning[rgba(245, 158, 11, 0.10)], stop:1 @surface[rgba(24, 20, 14, 0.65)]);
    border: 1px solid @warning[rgba(245, 158, 11, 0.45)];
    border-radius: 8px;
    padding: 10px 12px;
}
""".strip(),
)

HOST_BADGE_SUCCESS_STYLESHEET = themed_qss(
    'background-color: @success[rgba(16, 185, 129, 0.18)]; color: @success[#34d399]; '
    'border: 1px solid @success[rgba(16, 185, 129, 0.45)]; border-radius: 4px; '
    'padding: 2px 7px; font-weight: bold; font-size: 8.5pt;',
)

HOST_BADGE_WARNING_STYLESHEET = themed_qss(
    'background-color: @warning[rgba(245, 158, 11, 0.18)]; color: @warning[#fbbf24]; '
    'border: 1px solid @warning[rgba(245, 158, 11, 0.45)]; border-radius: 4px; '
    'padding: 2px 7px; font-weight: bold; font-size: 8.5pt;',
)

HOST_BADGE_DANGER_STYLESHEET = themed_qss(
    'background-color: @danger[rgba(239, 68, 68, 0.18)]; color: @danger[#f87171]; '
    'border: 1px solid @danger[rgba(239, 68, 68, 0.45)]; border-radius: 4px; '
    'padding: 2px 7px; font-weight: bold; font-size: 8.5pt;',
)

HOST_BADGE_INFO_STYLESHEET = themed_qss(
    'background-color: @accent[rgba(56, 189, 248, 0.18)]; color: @accent[#38bdf8]; '
    'border: 1px solid @accent[rgba(56, 189, 248, 0.45)]; border-radius: 4px; '
    'padding: 2px 7px; font-weight: bold; font-size: 8.5pt;',
)

HOST_BADGE_MUTED_STYLESHEET = themed_qss(
    'background-color: @surface[rgba(148, 163, 184, 0.14)]; color: @text[#cbd5e1];'
    ' border: 1px solid @border[rgba(148, 163, 184, 0.3)]; border-radius: 4px; padding: 2px 7px; font-size: 8.5pt;',
)
