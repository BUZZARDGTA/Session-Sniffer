"""Session Host diagnostics window QSS."""

HOST_DIAGNOSTICS_HERO_SUCCESS_STYLESHEET = """
QFrame#hostHeroSuccess {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(16, 185, 129, 0.16), stop:1 rgba(6, 78, 59, 0.22));
    border: 1px solid rgba(16, 185, 129, 0.45);
    border-left: 5px solid #10b981;
    border-radius: 8px;
    padding: 10px 14px;
}
""".strip()

HOST_DIAGNOSTICS_HERO_FAILURE_STYLESHEET = """
QFrame#hostHeroFailure {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(245, 158, 11, 0.16), stop:1 rgba(180, 83, 9, 0.22));
    border: 1px solid rgba(245, 158, 11, 0.45);
    border-left: 5px solid #f59e0b;
    border-radius: 8px;
    padding: 10px 14px;
}
""".strip()

HOST_DIAGNOSTICS_SECTION_CARD_STYLESHEET = """
QFrame#hostSectionCard {
    background-color: #1a1e24;
    border: 1px solid #28313e;
    border-radius: 8px;
    padding: 10px 12px;
}
""".strip()

HOST_DIAGNOSTICS_CHECKLIST_ROW_STYLESHEET = """
QFrame#hostChecklistRow {
    background-color: rgba(255, 255, 255, 0.025);
    border: 1px solid rgba(255, 255, 255, 0.05);
    border-radius: 6px;
    padding: 6px 10px;
}
""".strip()

HOST_DIAGNOSTICS_STAT_BOX_STYLESHEET = """
QFrame#hostStatBox {
    background-color: rgba(255, 255, 255, 0.035);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 6px;
    padding: 8px 10px;
}
""".strip()

HOST_DIAGNOSTICS_CANDIDATE_CARD_STYLESHEET = """
QFrame#hostCandidateCard {
    background-color: #171c23;
    border: 1px solid #283344;
    border-radius: 8px;
    padding: 10px 12px;
}
""".strip()

HOST_DIAGNOSTICS_CANDIDATE_HOST_STYLESHEET = """
QFrame#hostCandidateCard {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(245, 158, 11, 0.10), stop:1 rgba(24, 20, 14, 0.65));
    border: 1px solid rgba(245, 158, 11, 0.45);
    border-radius: 8px;
    padding: 10px 12px;
}
""".strip()

HOST_BADGE_SUCCESS_STYLESHEET = (
    'background-color: rgba(16, 185, 129, 0.18); color: #34d399; '
    'border: 1px solid rgba(16, 185, 129, 0.45); border-radius: 4px; '
    'padding: 2px 7px; font-weight: bold; font-size: 8.5pt;'
)

HOST_BADGE_WARNING_STYLESHEET = (
    'background-color: rgba(245, 158, 11, 0.18); color: #fbbf24; '
    'border: 1px solid rgba(245, 158, 11, 0.45); border-radius: 4px; '
    'padding: 2px 7px; font-weight: bold; font-size: 8.5pt;'
)

HOST_BADGE_DANGER_STYLESHEET = (
    'background-color: rgba(239, 68, 68, 0.18); color: #f87171; '
    'border: 1px solid rgba(239, 68, 68, 0.45); border-radius: 4px; '
    'padding: 2px 7px; font-weight: bold; font-size: 8.5pt;'
)

HOST_BADGE_INFO_STYLESHEET = (
    'background-color: rgba(56, 189, 248, 0.18); color: #38bdf8; '
    'border: 1px solid rgba(56, 189, 248, 0.45); border-radius: 4px; '
    'padding: 2px 7px; font-weight: bold; font-size: 8.5pt;'
)

HOST_BADGE_MUTED_STYLESHEET = (
    'background-color: rgba(148, 163, 184, 0.14); color: #cbd5e1; '
    'border: 1px solid rgba(148, 163, 184, 0.3); border-radius: 4px; '
    'padding: 2px 7px; font-size: 8.5pt;'
)
