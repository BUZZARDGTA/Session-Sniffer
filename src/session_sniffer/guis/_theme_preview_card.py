"""Clickable miniature UI preview card widget and live preview builder for browsing and editing themes."""

from typing import TYPE_CHECKING, Final, NamedTuple, override

from PySide6.QtCore import QEvent, QPointF, QRect, QRectF, QSize, Qt, Signal
from PySide6.QtGui import (
    QColor,
    QEnterEvent,
    QFont,
    QFontMetrics,
    QIcon,
    QKeyEvent,
    QMouseEvent,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
)
from PySide6.QtWidgets import QFrame, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QPushButton, QSizePolicy, QVBoxLayout, QWidget

from session_sniffer.guis.live_language import register_language_refresh
from session_sniffer.guis.theming import Theme, ThemeColors, get_active_theme, themed_qcolor, themed_text_qcolor
from session_sniffer.guis.theming._engine import ThemeTransform
from session_sniffer.guis.utils import scale_by_ui
from session_sniffer.i18n import tr

if TYPE_CHECKING:
    from PySide6.QtGui import QPaintEvent

_CARD_HEIGHT: Final = 196
_CARD_MIN_WIDTH: Final = 248
_CAPTION_HEIGHT: Final = 34
_CARD_RADIUS: Final = 8.0
_SCENE_RADIUS: Final = 5.0
_LUMINANCE_LIGHT_THRESHOLD: Final = 140.0

PREVIEW_BASE_QSS: Final = (
    'QFrame#themePreviewRoot { background-color: @background; border: 1px solid @border; border-radius: 8px; }\n'
    'QFrame#themePreviewMenuBar { background-color: @menubar; border-bottom: 1px solid @border;'
    ' border-top-left-radius: 7px; border-top-right-radius: 7px; }\n'
    'QLabel#themePreviewMenuActive { background-color: @selection; color: @text_strong; border-radius: 4px;'
    ' padding: 2px 8px; font-size: 8.5pt; font-weight: 600; }\n'
    'QLabel#themePreviewMenuItem { background: transparent; color: @text; padding: 2px 6px; font-size: 8.5pt; }\n'
    'QLabel#themePreviewPopupChip { background-color: @popup; color: @text; border: 1px solid @border;'
    ' border-radius: 4px; padding: 2px 8px; font-size: 8pt; }\n'
    'QFrame#themePreviewCard { background-color: @surface; border: 1px solid @border; border-radius: 6px; }\n'
    'QLabel#themePreviewTitle { color: @text_strong; background: transparent; font-size: 9.5pt; font-weight: 700; }\n'
    'QLabel#themePreviewBody { color: @text; background: transparent; font-size: 8.5pt; }\n'
    'QLabel#themePreviewMuted { color: @text_muted; background: transparent; font-size: 8pt; }\n'
    'QLineEdit#themePreviewInput { background-color: @input; color: @text; border: 1px solid @border;'
    ' border-radius: 4px; padding: 3px 8px; font-size: 8.5pt; selection-background-color: @selection; selection-color: @text_strong; }\n'
    'QLineEdit#themePreviewInput:focus { border: 1px solid @accent; }\n'
    'QPushButton#themePreviewPrimaryButton { background-color: @accent; color: @text_strong; border: 1px solid @accent;'
    ' border-radius: 5px; padding: 3px 10px; font-size: 8pt; font-weight: 700; }\n'
    'QPushButton#themePreviewStandardButton { background-color: @control; color: @text; border: 1px solid @border;'
    ' border-radius: 5px; padding: 3px 10px; font-size: 8pt; font-weight: 600; }\n'
    'QPushButton#themePreviewDangerButton { background-color: @control~danger/22; color: @danger;'
    ' border: 1px solid @danger/55; border-radius: 5px; padding: 3px 10px; font-size: 8pt; font-weight: 700; }\n'
    'QLabel#themePreviewBadgeAccent { background-color: @accent/18; color: @accent;'
    ' border: 1px solid @accent/50; border-radius: 4px; padding: 1px 7px; font-size: 7.5pt; font-weight: 700; }\n'
    'QLabel#themePreviewBadgeSuccess { background-color: @success/18; color: @success;'
    ' border: 1px solid @success/50; border-radius: 4px; padding: 1px 7px; font-size: 7.5pt; font-weight: 700; }\n'
    'QLabel#themePreviewBadgeWarning { background-color: @warning/18; color: @warning;'
    ' border: 1px solid @warning/50; border-radius: 4px; padding: 1px 7px; font-size: 7.5pt; font-weight: 700; }\n'
    'QLabel#themePreviewBadgeDanger { background-color: @danger/18; color: @danger;'
    ' border: 1px solid @danger/50; border-radius: 4px; padding: 1px 7px; font-size: 7.5pt; font-weight: 700; }\n'
    'QFrame#themePreviewTable { background-color: @table; border: 1px solid @border; border-radius: 6px; }\n'
    'QFrame#themePreviewTableHeader { background-color: @table_header; border-bottom: 1px solid @accent;'
    ' border-top-left-radius: 5px; border-top-right-radius: 5px; }\n'
    'QFrame#themePreviewTableRowEven { background-color: @table; border-bottom: 1px solid @border/45; }\n'
    'QFrame#themePreviewTableRowAlt { background-color: @table_alt; border-bottom: 1px solid @border/45; }\n'
    'QFrame#themePreviewTableRowSelected { background-color: @selection; border-bottom-left-radius: 5px; }\n'
    'QLabel#themePreviewTableHeaderCell { background: transparent; color: @text_muted; font-size: 7.5pt; font-weight: 700; }\n'
    'QLabel#themePreviewCellStrong { background: transparent; color: @text_strong; font-size: 8pt; font-weight: 700; }\n'
    'QLabel#themePreviewCellNormal { background: transparent; color: @text; font-size: 8pt; }\n'
    'QLabel#themePreviewCellMuted { background: transparent; color: @text_muted; font-size: 8pt; }\n'
    'QLabel#themePreviewCellSuccess { background: transparent; color: @success; font-size: 8pt; font-weight: 700; }\n'
    'QLabel#themePreviewCellWarning { background: transparent; color: @warning; font-size: 8pt; font-weight: 700; }\n'
    'QLabel#themePreviewCellDanger { background: transparent; color: @danger; font-size: 8pt; font-weight: 700; }\n'
    'QFrame#themePreviewScrollTrack { background-color: @table; border-left: 1px solid @border/45;'
    ' border-bottom-right-radius: 5px; }\n'
    'QFrame#themePreviewScrollThumb { background-color: @scrollbar; border-radius: 3px; }\n'
    'QFrame#themePreviewStatusBar { background-color: @statusbar; border-top: 1px solid @accent;'
    ' border-bottom-left-radius: 7px; border-bottom-right-radius: 7px; }\n'
    'QLabel#themePreviewStatusAccent { background: transparent; color: @accent; font-size: 8pt; font-weight: 600; }\n'
    'QLabel#themePreviewStatusSuccess { background: transparent; color: @success; font-size: 8pt; font-weight: 600; }\n'
    'QLabel#themePreviewStatusWarning { background: transparent; color: @warning; font-size: 8pt; font-weight: 600; }\n'
    'QLabel#themePreviewStatusMuted { background: transparent; color: @text_muted; font-size: 8pt; }'
)


def token_swatch_stylesheet(hex_color: str) -> str:
    """Build an untransformed QSS string showing the literal *hex_color* token swatch."""
    parsed = QColor(hex_color)
    luminance = 0.299 * parsed.red() + 0.587 * parsed.green() + 0.114 * parsed.blue()
    border_hex = '#333333' if luminance > _LUMINANCE_LIGHT_THRESHOLD else '#d0d7de'
    return (
        f'QPushButton {{ background-color: {hex_color}; border: 1px solid {border_hex}; border-radius: 4px; }}'
        f' QPushButton:hover {{ border: 2px solid {border_hex}; }}'
        f' QPushButton:disabled {{ background-color: {hex_color}; border: 1px solid #6e7681; }}'
    )


def create_theme_list_icon(colors: ThemeColors) -> QIcon:
    """Render a small two-tone swatch icon representing *colors* (`background` + `accent`)."""
    size = scale_by_ui(16)
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, on=True)
    painter.setPen(QPen(QColor(colors.border), 1))
    painter.setBrush(QColor(colors.background))
    painter.drawRoundedRect(1, 1, size - 2, size - 2, 3, 3)

    dot_radius = max(2, (size - 6) // 2)
    center = size // 2
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QColor(colors.accent))
    painter.drawEllipse(center - dot_radius, center - dot_radius, dot_radius * 2, dot_radius * 2)
    painter.end()
    return QIcon(pixmap)


def _make_preview_label(text: str, object_name: str) -> QLabel:
    label = QLabel(text)
    label.setObjectName(object_name)
    return label


def _build_preview_menubar() -> QFrame:
    menu_bar = QFrame()
    menu_bar.setObjectName('themePreviewMenuBar')
    layout = QHBoxLayout(menu_bar)
    layout.setContentsMargins(8, 4, 8, 4)
    layout.setSpacing(6)
    layout.addWidget(_make_preview_label(tr('Capture'), 'themePreviewMenuActive'))
    for title in ('GTA V', 'Tools', 'Settings'):
        layout.addWidget(_make_preview_label(tr(title), 'themePreviewMenuItem'))
    layout.addStretch()
    popup_chip = _make_preview_label(tr('Popup / Tooltip'), 'themePreviewPopupChip')
    popup_chip.setToolTip(tr('Previews the Popup & Tooltip surface token'))
    layout.addWidget(popup_chip)
    return menu_bar


def _build_preview_surface_card() -> tuple[QFrame, QLineEdit]:
    card = QFrame()
    card.setObjectName('themePreviewCard')
    card_layout = QVBoxLayout(card)
    card_layout.setContentsMargins(10, 7, 10, 7)
    card_layout.setSpacing(6)

    header_row = QHBoxLayout()
    header_row.addWidget(_make_preview_label(tr('Session Sniffer Preview'), 'themePreviewTitle'))
    header_row.addStretch()
    header_row.addWidget(_make_preview_label(tr('Interface: Ethernet  •  Filtering active'), 'themePreviewMuted'))
    header_row.addSpacing(8)
    header_row.addWidget(_make_preview_label(tr('Uptime: 01:14:22'), 'themePreviewBody'))
    card_layout.addLayout(header_row)

    controls_row = QHBoxLayout()
    controls_row.setSpacing(6)
    sample_input = QLineEdit(tr('Search players or IPs…'))
    sample_input.setObjectName('themePreviewInput')
    sample_input.setReadOnly(True)
    sample_input.setCursorPosition(0)
    sample_input.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
    controls_row.addWidget(sample_input, 1)

    for button_text, object_name in (
        ('Primary', 'themePreviewPrimaryButton'),
        ('Control', 'themePreviewStandardButton'),
        ('Danger', 'themePreviewDangerButton'),
    ):
        sample_button = QPushButton(tr(button_text))
        sample_button.setObjectName(object_name)
        sample_button.setAutoDefault(False)
        sample_button.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        controls_row.addWidget(sample_button)
    card_layout.addLayout(controls_row)

    badges_row = QHBoxLayout()
    badges_row.setSpacing(5)
    for badge_text, object_name in (
        ('Host', 'themePreviewBadgeAccent'),
        ('Connected • 24 ms', 'themePreviewBadgeSuccess'),
        ('High Rate', 'themePreviewBadgeWarning'),
        ('Disconnected', 'themePreviewBadgeDanger'),
    ):
        badge = _make_preview_label(tr(badge_text), object_name)
        badge.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
        badges_row.addWidget(badge)
    badges_row.addStretch()
    card_layout.addLayout(badges_row)
    return card, sample_input


def _build_preview_table_row(row_object_name: str, cells: tuple[tuple[str, str, int], ...]) -> QFrame:
    row = QFrame()
    row.setObjectName(row_object_name)
    layout = QHBoxLayout(row)
    layout.setContentsMargins(8, 3, 8, 3)
    layout.setSpacing(8)
    for text, cell_object_name, stretch in cells:
        layout.addWidget(_make_preview_label(text, cell_object_name), stretch)
    return row


def _build_preview_mini_table() -> QFrame:
    table = QFrame()
    table.setObjectName('themePreviewTable')
    outer = QVBoxLayout(table)
    outer.setContentsMargins(0, 0, 0, 0)
    outer.setSpacing(0)

    header = _build_preview_table_row(
        'themePreviewTableHeader',
        (
            (tr('Username'), 'themePreviewTableHeaderCell', 3),
            (tr('IP Address'), 'themePreviewTableHeaderCell', 3),
            (tr('Ping'), 'themePreviewTableHeaderCell', 2),
            (tr('Status'), 'themePreviewTableHeaderCell', 2),
        ),
    )
    outer.addWidget(header)

    body_row = QHBoxLayout()
    body_row.setContentsMargins(0, 0, 0, 0)
    body_row.setSpacing(0)

    rows_col = QVBoxLayout()
    rows_col.setContentsMargins(0, 0, 0, 0)
    rows_col.setSpacing(0)
    rows_col.addWidget(
        _build_preview_table_row(
            'themePreviewTableRowEven',
            (
                ('★ HostPlayer', 'themePreviewCellStrong', 3),
                ('198.51.100.14', 'themePreviewCellNormal', 3),
                (tr('{ms} ms', ms=22), 'themePreviewCellSuccess', 2),
                (tr('Table Row'), 'themePreviewCellMuted', 2),
            ),
        ),
    )
    rows_col.addWidget(
        _build_preview_table_row(
            'themePreviewTableRowAlt',
            (
                ('NightRider99', 'themePreviewCellSuccess', 3),
                ('203.0.113.42', 'themePreviewCellNormal', 3),
                (tr('{ms} ms', ms=148), 'themePreviewCellWarning', 2),
                (tr('Alternate Row'), 'themePreviewCellMuted', 2),
            ),
        ),
    )
    rows_col.addWidget(
        _build_preview_table_row(
            'themePreviewTableRowSelected',
            (
                ('KnownModder', 'themePreviewCellStrong', 3),
                ('198.51.100.99', 'themePreviewCellMuted', 3),
                (tr('{ms} ms', ms=265), 'themePreviewCellDanger', 2),
                (tr('Selected Row'), 'themePreviewCellStrong', 2),
            ),
        ),
    )
    body_row.addLayout(rows_col, 1)

    scroll_track = QFrame()
    scroll_track.setObjectName('themePreviewScrollTrack')
    scroll_track.setFixedWidth(scale_by_ui(11))
    track_layout = QVBoxLayout(scroll_track)
    track_layout.setContentsMargins(2, 4, 2, 4)
    track_layout.setSpacing(0)
    scroll_thumb = QFrame()
    scroll_thumb.setObjectName('themePreviewScrollThumb')
    scroll_thumb.setMinimumHeight(scale_by_ui(26))
    track_layout.addWidget(scroll_thumb)
    track_layout.addStretch()
    body_row.addWidget(scroll_track)

    outer.addLayout(body_row)
    return table


def _build_preview_statusbar() -> QFrame:
    status = QFrame()
    status.setObjectName('themePreviewStatusBar')
    layout = QHBoxLayout(status)
    layout.setContentsMargins(8, 3, 8, 3)
    layout.setSpacing(6)
    layout.addWidget(_make_preview_label(tr('Capture: Active'), 'themePreviewStatusSuccess'))
    layout.addWidget(_make_preview_label('|', 'themePreviewStatusMuted'))
    layout.addWidget(_make_preview_label(tr('Connected Players: 12'), 'themePreviewStatusAccent'))
    layout.addStretch()
    layout.addWidget(_make_preview_label(tr('Bandwidth: 48.2 KB/s'), 'themePreviewStatusWarning'))
    return status


def build_theme_preview_group(preview_root: QFrame) -> QGroupBox:
    """Build the 20-token miniature Session Sniffer Live Preview group box for `ThemeManagerDialog`."""
    preview_group = QGroupBox(tr('Live Preview'))
    outer_layout = QVBoxLayout(preview_group)
    outer_layout.setContentsMargins(8, 8, 8, 8)

    preview_root.setObjectName('themePreviewRoot')
    root_layout = QVBoxLayout(preview_root)
    root_layout.setContentsMargins(0, 0, 0, 0)
    root_layout.setSpacing(6)

    root_layout.addWidget(_build_preview_menubar())

    content_layout = QVBoxLayout()
    content_layout.setContentsMargins(8, 2, 8, 2)
    content_layout.setSpacing(6)
    surface_card, sample_input = _build_preview_surface_card()
    content_layout.addWidget(surface_card)
    content_layout.addWidget(_build_preview_mini_table())
    root_layout.addLayout(content_layout)

    root_layout.addStretch()
    root_layout.addWidget(_build_preview_statusbar())
    outer_layout.addWidget(preview_root)

    register_language_refresh(
        preview_group,
        lambda: sample_input.setText(tr('Search players or IPs…')),
    )
    return preview_group


class _PreviewRow(NamedTuple):
    username: str
    ip_text: str
    ping_text: str
    tag_text: str
    role: str
    user_style: str  # 'strong' | 'role' | 'normal'
    bold_user: bool
    bold_ping: bool
    green_ping: bool
    muted_ip: bool
    row_bg_kind: str  # 'selected' | 'even' | 'alt'


_PREVIEW_ROWS: Final[tuple[_PreviewRow, ...]] = (
    _PreviewRow('★ HostPlayer', '198.51.100.14', '22 ms', 'Host', 'accent', 'strong', bold_user=True, bold_ping=True, green_ping=True, muted_ip=False, row_bg_kind='selected'),
    _PreviewRow('NightRider99', '203.0.113.42', '41 ms', 'Active', 'success', 'role', bold_user=False, bold_ping=False, green_ping=True, muted_ip=False, row_bg_kind='alt'),
    _PreviewRow('PacketStorm', '192.0.2.188', '148 ms', 'High', 'warning', 'normal', bold_user=False, bold_ping=True, green_ping=False, muted_ip=False, row_bg_kind='even'),
    _PreviewRow('KnownModder', '198.51.100.99', '265 ms', 'Alert', 'danger', 'role', bold_user=True, bold_ping=False, green_ping=False, muted_ip=True, row_bg_kind='alt'),
)
_SPARKLINE_POINTS: Final[tuple[float, ...]] = (0.30, 0.48, 0.38, 0.72, 0.56, 0.85, 0.62, 0.76, 0.50, 0.90)


def _with_alpha(color: QColor, alpha: int) -> QColor:
    result = QColor(color)
    result.setAlpha(alpha)
    return result


def _draw_pill(painter: QPainter, rect: QRectF, text: str, base_color: QColor, text_color: QColor) -> None:
    radius = min(rect.height() / 2.0, float(scale_by_ui(4)))
    path = QPainterPath()
    path.addRoundedRect(rect, radius, radius)
    painter.fillPath(path, _with_alpha(base_color, 44))
    painter.setPen(QPen(_with_alpha(base_color, 138), 1.0))
    painter.setBrush(Qt.BrushStyle.NoBrush)
    painter.drawPath(path)
    painter.setPen(text_color)
    painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, text)


def _draw_preview_toolbar(painter: QPainter, rect: QRectF, transform: ThemeTransform, base_font: QFont) -> None:
    colors = transform.colors
    c_menubar = QColor(colors.menubar)
    c_input = QColor(colors.input)
    c_control = QColor(colors.control)
    c_border = QColor(colors.border)
    c_accent = QColor(colors.accent)
    c_success = QColor(colors.success)

    painter.fillRect(rect, c_menubar)
    painter.setPen(QPen(c_border, 1.0))
    painter.drawLine(QPointF(rect.left(), rect.bottom()), QPointF(rect.right(), rect.bottom()))

    pill_font = QFont(base_font)
    pill_font.setPointSizeF(6.2)
    pill_font.setBold(True)
    painter.setFont(pill_font)

    pad = float(scale_by_ui(5))
    pill_h = rect.height() - pad * 1.5
    pill_y = rect.top() + (rect.height() - pill_h) / 2.0

    cap_rect = QRectF(rect.left() + pad, pill_y, float(scale_by_ui(58)), pill_h)
    _draw_pill(painter, cap_rect, f"● {tr('Capturing')}", c_success, transform.text_on('@success', c_menubar))

    game_rect = QRectF(cap_rect.right() + float(scale_by_ui(4)), pill_y, float(scale_by_ui(34)), pill_h)
    _draw_pill(painter, game_rect, tr('GTA V'), c_accent, transform.text_on('@accent', c_menubar))

    btn_w = float(scale_by_ui(32))
    btn_rect = QRectF(rect.right() - pad - btn_w, pill_y, btn_w, pill_h)
    btn_path = QPainterPath()
    btn_path.addRoundedRect(btn_rect, 3.0, 3.0)
    painter.fillPath(btn_path, c_accent)
    painter.setPen(transform.text_on('@text_strong', c_accent))
    painter.drawText(btn_rect, Qt.AlignmentFlag.AlignCenter, tr('Filter'))

    ctrl_w = float(scale_by_ui(28))
    ctrl_rect = QRectF(btn_rect.left() - float(scale_by_ui(3)) - ctrl_w, pill_y, ctrl_w, pill_h)
    ctrl_path = QPainterPath()
    ctrl_path.addRoundedRect(ctrl_rect, 3.0, 3.0)
    painter.fillPath(ctrl_path, c_control)
    painter.setPen(QPen(c_border, 1.0))
    painter.drawPath(ctrl_path)
    painter.setPen(transform.text_on('@text', c_control))
    painter.drawText(ctrl_rect, Qt.AlignmentFlag.AlignCenter, tr('Clear'))

    search_left = game_rect.right() + float(scale_by_ui(5))
    search_right = ctrl_rect.left() - float(scale_by_ui(4))
    if search_right - search_left >= float(scale_by_ui(30)):
        search_rect = QRectF(search_left, pill_y, search_right - search_left, pill_h)
        search_path = QPainterPath()
        search_path.addRoundedRect(search_rect, 3.0, 3.0)
        painter.fillPath(search_path, c_input)
        painter.setPen(QPen(c_border, 1.0))
        painter.drawPath(search_path)
        search_font = QFont(base_font)
        search_font.setPointSizeF(6.0)
        painter.setFont(search_font)
        painter.setPen(transform.text_on('@text_muted', c_input))
        text_rect = search_rect.adjusted(float(scale_by_ui(5)), 0.0, -float(scale_by_ui(3)), 0.0)
        painter.drawText(text_rect, Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, tr('Search…'))


def _draw_preview_table(painter: QPainter, rect: QRectF, transform: ThemeTransform, base_font: QFont) -> None:
    colors = transform.colors
    c_table = QColor(colors.table)
    c_table_alt = QColor(colors.table_alt)
    c_table_header = QColor(colors.table_header)
    c_selection = QColor(colors.selection)
    c_scrollbar = QColor(colors.scrollbar)
    c_border = QColor(colors.border)
    c_accent = QColor(colors.accent)

    table_path = QPainterPath()
    table_path.addRoundedRect(rect, 4.0, 4.0)
    painter.save()
    painter.setClipPath(table_path)
    painter.fillRect(rect, c_table)

    header_h = float(scale_by_ui(15))
    header_rect = QRectF(rect.left(), rect.top(), rect.width(), header_h)
    painter.fillRect(header_rect, c_table_header)
    painter.setPen(QPen(c_accent, 1.0))
    painter.drawLine(QPointF(rect.left(), header_rect.bottom()), QPointF(rect.right(), header_rect.bottom()))

    sb_w = float(scale_by_ui(5))
    w = rect.width() - sb_w
    col_x = (rect.left() + float(scale_by_ui(6)), rect.left() + w * 0.39, rect.left() + w * 0.67, rect.left() + w * 0.82)
    hdr_font = QFont(base_font)
    hdr_font.setPointSizeF(5.8)
    hdr_font.setBold(True)
    painter.setFont(hdr_font)
    painter.setPen(transform.text_on('@text_muted', c_table_header))
    for idx, title in enumerate(('Username', 'IP Address', 'Ping', 'Tag')):
        right_edge = col_x[idx + 1] if idx + 1 < len(col_x) else rect.left() + w - float(scale_by_ui(4))
        col_rect = QRectF(col_x[idx], header_rect.top(), right_edge - col_x[idx], header_h)
        painter.drawText(col_rect, Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, tr(title))

    rows_top = header_rect.bottom()
    row_h = (rect.bottom() - rows_top) / len(_PREVIEW_ROWS)
    token_colors = {
        'accent': (c_accent, '@accent'),
        'success': (QColor(colors.success), '@success'),
        'warning': (QColor(colors.warning), '@warning'),
        'danger': (QColor(colors.danger), '@danger'),
    }
    row_font = QFont(base_font)
    row_font.setPointSizeF(6.1)
    bold_font = QFont(row_font)
    bold_font.setBold(True)

    for row_idx, row in enumerate(_PREVIEW_ROWS):
        row_rect = QRectF(rect.left(), rows_top + row_idx * row_h, w, row_h)
        role_qcolor, role_token = token_colors[row.role]
        if row.row_bg_kind == 'selected':
            row_bg = c_selection
            painter.fillRect(row_rect, row_bg)
        elif row.row_bg_kind == 'alt':
            row_bg = c_table_alt
            painter.fillRect(row_rect, row_bg)
        else:
            row_bg = c_table

        painter.setFont(bold_font if row.bold_user else row_font)
        if row.user_style == 'strong':
            user_fg = transform.text_on('@text_strong', row_bg)
        elif row.user_style == 'role':
            user_fg = transform.text_on(role_token, row_bg)
        else:
            user_fg = transform.text_on('@text', row_bg)
        painter.setPen(user_fg)
        user_rect = QRectF(col_x[0], row_rect.top(), col_x[1] - col_x[0] - 2.0, row_h)
        painter.drawText(user_rect, Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, row.username)

        painter.setFont(row_font)
        painter.setPen(transform.text_on('@text_muted' if row.muted_ip else '@text', row_bg))
        ip_rect = QRectF(col_x[1], row_rect.top(), col_x[2] - col_x[1] - 2.0, row_h)
        painter.drawText(ip_rect, Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, row.ip_text)

        ping_token = '@success' if row.green_ping else role_token
        painter.setFont(bold_font if row.bold_ping else row_font)
        painter.setPen(transform.text_on(ping_token, row_bg))
        ping_rect = QRectF(col_x[2], row_rect.top(), col_x[3] - col_x[2] - 2.0, row_h)
        painter.drawText(ping_rect, Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, row.ping_text)

        pill_pad_y = max(1.5, (row_h - float(scale_by_ui(12))) / 2.0)
        tag_rect = QRectF(col_x[3], row_rect.top() + pill_pad_y, rect.left() + w - col_x[3] - float(scale_by_ui(4)), row_h - pill_pad_y * 2.0)
        painter.setFont(hdr_font)
        _draw_pill(painter, tag_rect, tr(row.tag_text), role_qcolor, transform.text_on(role_token, row_bg))

    thumb_rect = QRectF(rect.right() - sb_w + 1.0, rows_top + 3.0, max(2.0, sb_w - 2.0), max(10.0, (rect.bottom() - rows_top) * 0.48))
    thumb_path = QPainterPath()
    thumb_path.addRoundedRect(thumb_rect, 1.5, 1.5)
    painter.fillPath(thumb_path, c_scrollbar)

    painter.restore()
    painter.setPen(QPen(c_border, 1.0))
    painter.setBrush(Qt.BrushStyle.NoBrush)
    painter.drawPath(table_path)


def _draw_preview_status_sparkline(painter: QPainter, rect: QRectF, transform: ThemeTransform, base_font: QFont) -> None:
    colors = transform.colors
    c_statusbar = QColor(colors.statusbar)
    c_accent = QColor(colors.accent)
    painter.fillRect(rect, c_statusbar)
    painter.setPen(QPen(c_accent, 1.0))
    painter.drawLine(QPointF(rect.left(), rect.top()), QPointF(rect.right(), rect.top()))

    inner_rect = rect.adjusted(float(scale_by_ui(6)), 1.0, -float(scale_by_ui(6)), -1.0)
    status_font = QFont(base_font)
    status_font.setPointSizeF(5.9)
    painter.setFont(status_font)
    painter.setPen(transform.text_on('@text_muted', c_statusbar))
    painter.drawText(inner_rect, Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, tr('01:14:22 • 48.2 KB/s'))

    spark_w = min(float(scale_by_ui(74)), inner_rect.width() * 0.36)
    spark_rect = QRectF(inner_rect.right() - spark_w, inner_rect.top() + 2.0, spark_w, max(5.0, inner_rect.height() - 4.0))
    step_x = spark_rect.width() / (len(_SPARKLINE_POINTS) - 1)
    line_path = QPainterPath()
    for idx, sample in enumerate(_SPARKLINE_POINTS):
        pt = QPointF(spark_rect.left() + idx * step_x, spark_rect.bottom() - sample * spark_rect.height())
        if not idx:
            line_path.moveTo(pt)
        else:
            line_path.lineTo(pt)

    fill_path = QPainterPath(line_path)
    fill_path.lineTo(QPointF(spark_rect.right(), spark_rect.bottom()))
    fill_path.lineTo(QPointF(spark_rect.left(), spark_rect.bottom()))
    fill_path.closeSubpath()
    painter.fillPath(fill_path, _with_alpha(c_accent, 48))
    painter.setPen(QPen(c_accent, 1.3))
    painter.setBrush(Qt.BrushStyle.NoBrush)
    painter.drawPath(line_path)


def _render_scene_pixmap(theme: Theme, size: QSize, dpr: float, base_font: QFont) -> QPixmap:
    pixel_w = max(1, round(size.width() * dpr))
    pixel_h = max(1, round(size.height() * dpr))
    pixmap = QPixmap(pixel_w, pixel_h)
    pixmap.setDevicePixelRatio(dpr)
    pixmap.fill(Qt.GlobalColor.transparent)

    transform = ThemeTransform(theme.colors)
    colors = theme.colors
    scene_rect = QRectF(0.5, 0.5, size.width() - 1.0, size.height() - 1.0)

    painter = QPainter(pixmap)
    painter.setRenderHints(QPainter.RenderHint.Antialiasing | QPainter.RenderHint.TextAntialiasing)

    clip_path = QPainterPath()
    clip_path.addRoundedRect(scene_rect, _SCENE_RADIUS, _SCENE_RADIUS)
    painter.save()
    painter.setClipPath(clip_path)
    painter.fillRect(scene_rect, QColor(colors.background))

    toolbar_h = float(scale_by_ui(23))
    _draw_preview_toolbar(painter, QRectF(scene_rect.left(), scene_rect.top(), scene_rect.width(), toolbar_h), transform, base_font)

    pad_x = float(scale_by_ui(6))
    sec_top = scene_rect.top() + toolbar_h + float(scale_by_ui(3))
    sec_h = float(scale_by_ui(13))
    sec_rect = QRectF(scene_rect.left() + pad_x, sec_top, scene_rect.width() - pad_x * 2.0, sec_h)
    sec_path = QPainterPath()
    sec_path.addRoundedRect(sec_rect, 2.5, 2.5)
    c_surface = QColor(colors.surface)
    painter.fillPath(sec_path, c_surface)
    painter.fillRect(QRectF(sec_rect.left() + 2.0, sec_top + 2.0, 2.5, sec_h - 4.0), QColor(colors.success))
    sec_font = QFont(base_font)
    sec_font.setPointSizeF(6.1)
    sec_font.setBold(True)
    painter.setFont(sec_font)
    painter.setPen(transform.text_on('@text_strong', c_surface))
    sec_text_rect = QRectF(sec_rect.left() + float(scale_by_ui(7)), sec_top, sec_rect.width() - float(scale_by_ui(11)), sec_h)
    painter.drawText(sec_text_rect, Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, tr('Connected Players ({count})', count=4))
    sec_font.setBold(False)
    sec_font.setPointSizeF(5.7)
    painter.setFont(sec_font)
    painter.setPen(transform.text_on('@text_muted', c_surface))
    painter.drawText(sec_text_rect, Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight, tr('{rate} PPS', rate=148))

    status_h = float(scale_by_ui(15))
    table_top = sec_top + sec_h + float(scale_by_ui(2))
    table_bottom = scene_rect.bottom() - status_h - float(scale_by_ui(3))
    table_rect = QRectF(scene_rect.left() + pad_x, table_top, scene_rect.width() - pad_x * 2.0, max(float(scale_by_ui(40)), table_bottom - table_top))
    _draw_preview_table(painter, table_rect, transform, base_font)

    status_rect = QRectF(scene_rect.left(), scene_rect.bottom() - status_h, scene_rect.width(), status_h)
    _draw_preview_status_sparkline(painter, status_rect, transform, base_font)

    painter.restore()
    painter.setPen(QPen(QColor(colors.border), 1.0))
    painter.setBrush(Qt.BrushStyle.NoBrush)
    painter.drawPath(clip_path)
    painter.end()
    return pixmap


class ThemePreviewCard(QFrame):
    """Clickable miniature Session Sniffer window preview card for a single `Theme`."""

    clicked = Signal(str)

    def __init__(self, theme: Theme, *, selected: bool = False, parent: QWidget | None = None) -> None:
        """Initialize the preview card for *theme*."""
        super().__init__(parent)
        self._theme = theme
        self._selected = selected
        self._hovered = False
        self._cached_scene: QPixmap | None = None
        self._cached_key: tuple[int, int, float] | None = None

        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setMinimumWidth(scale_by_ui(_CARD_MIN_WIDTH))
        self.setFixedHeight(scale_by_ui(_CARD_HEIGHT))
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        self._update_tooltip()
        register_language_refresh(self, self._on_language_refreshed)

    def _on_language_refreshed(self) -> None:
        """Invalidate cached preview pixmap and refresh localized labels/tooltips."""
        self._cached_scene = None
        self._cached_key = None
        self._update_tooltip()
        self.update()

    def _update_tooltip(self) -> None:
        kind = tr('Built-in preset') if self._theme.builtin else tr('Custom theme')
        if self.is_active_theme:
            self.setToolTip(tr('{name} — {kind} (currently active)\nClick to apply this theme live.', name=self._theme.name, kind=kind))
        else:
            self.setToolTip(tr('{name} — {kind}\nClick to apply this theme live.', name=self._theme.name, kind=kind))

    @property
    def theme_name(self) -> str:
        """Return the name of the theme represented by this card."""
        return self._theme.name

    @property
    def is_active_theme(self) -> bool:
        """Return `True` if this card represents the currently active runtime theme."""
        return self._theme.name.casefold() == get_active_theme().name.casefold()

    def set_selected(self, *, selected: bool) -> None:
        """Update the selected visual state and active tooltip of this card."""
        self._selected = selected
        self._update_tooltip()
        self.update()

    @override
    def sizeHint(self) -> QSize:
        return QSize(scale_by_ui(290), scale_by_ui(_CARD_HEIGHT))

    @override
    def enterEvent(self, event: QEnterEvent) -> None:
        self._hovered = True
        self.update()
        super().enterEvent(event)

    @override
    def leaveEvent(self, event: QEvent) -> None:
        self._hovered = False
        self.update()
        super().leaveEvent(event)

    @override
    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton and self.rect().contains(event.position().toPoint()):
            self.clicked.emit(self._theme.name)
            event.accept()
            return
        super().mouseReleaseEvent(event)

    @override
    def keyPressEvent(self, event: QKeyEvent) -> None:
        if event.key() in (Qt.Key.Key_Space, Qt.Key.Key_Return, Qt.Key.Key_Enter):
            self.clicked.emit(self._theme.name)
            event.accept()
            return
        super().keyPressEvent(event)

    def _draw_caption_bar(self, painter: QPainter, caption_rect: QRectF) -> None:
        active_accent = themed_qcolor('@accent')
        caption_bg_token = '@selection' if self._selected else '@table_header'
        caption_bg = themed_qcolor(caption_bg_token)
        painter.fillRect(caption_rect, caption_bg)
        painter.setPen(QPen(themed_qcolor('@border'), 1.0))
        painter.drawLine(QPointF(caption_rect.left(), caption_rect.top()), QPointF(caption_rect.right(), caption_rect.top()))

        pad_x = float(scale_by_ui(9))
        dot_size = float(scale_by_ui(13))
        radio_rect = QRectF(caption_rect.left() + pad_x, caption_rect.center().y() - dot_size / 2.0, dot_size, dot_size)
        if self._selected:
            painter.setBrush(active_accent)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawEllipse(radio_rect)
            inner = radio_rect.adjusted(dot_size * 0.28, dot_size * 0.28, -dot_size * 0.28, -dot_size * 0.28)
            painter.setBrush(themed_text_qcolor('@text_strong', '@accent'))
            painter.drawEllipse(inner)
        else:
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.setPen(QPen(themed_qcolor('@text_muted'), 1.4))
            painter.drawEllipse(radio_rect)

        swatch_hexes = (
            self._theme.colors.background,
            self._theme.colors.surface,
            self._theme.colors.control,
            self._theme.colors.accent,
            self._theme.colors.success,
            self._theme.colors.warning,
            self._theme.colors.danger,
        )
        swatch_d = float(scale_by_ui(8))
        swatch_gap = float(scale_by_ui(3))
        swatches_total_w = len(swatch_hexes) * swatch_d + (len(swatch_hexes) - 1) * swatch_gap
        swatches_left = caption_rect.right() - pad_x - swatches_total_w
        swatch_y = caption_rect.center().y() - swatch_d / 2.0
        swatch_border = QPen(themed_qcolor('@border'), 0.8)
        for idx, color_hex in enumerate(swatch_hexes):
            sx = swatches_left + idx * (swatch_d + swatch_gap)
            painter.setBrush(QColor(color_hex))
            painter.setPen(swatch_border)
            painter.drawEllipse(QRectF(sx, swatch_y, swatch_d, swatch_d))

        right_limit = swatches_left - float(scale_by_ui(7))
        if self.is_active_theme:
            active_label = tr('Active')
            badge_font = QFont(self.font())
            badge_font.setPointSizeF(6.8)
            badge_font.setBold(True)
            painter.setFont(badge_font)
            badge_w = float(QFontMetrics(badge_font).horizontalAdvance(active_label) + scale_by_ui(12))
            badge_h = float(scale_by_ui(16))
            badge_rect = QRectF(right_limit - badge_w, caption_rect.center().y() - badge_h / 2.0, badge_w, badge_h)
            _draw_pill(painter, badge_rect, active_label, themed_qcolor('@success'), themed_text_qcolor('@success', caption_bg_token))
            right_limit = badge_rect.left() - float(scale_by_ui(6))

        name_left = radio_rect.right() + float(scale_by_ui(7))
        name_w = max(0, int(right_limit - name_left))
        if name_w > 0:
            name_font = QFont(self.font())
            name_font.setPointSizeF(8.8)
            name_font.setBold(self._selected)
            painter.setFont(name_font)
            painter.setPen(themed_text_qcolor('@text_strong' if self._selected else '@text', caption_bg_token))
            elided = QFontMetrics(name_font).elidedText(self._theme.name, Qt.TextElideMode.ElideRight, name_w)
            text_rect = QRect(int(name_left), int(caption_rect.top()), name_w, int(caption_rect.height()))
            painter.drawText(text_rect, Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, elided)

    @override
    def paintEvent(self, event: QPaintEvent) -> None:
        del event
        painter = QPainter(self)
        painter.setRenderHints(QPainter.RenderHint.Antialiasing | QPainter.RenderHint.TextAntialiasing)

        outer = QRectF(self.rect()).adjusted(1.5, 1.5, -1.5, -1.5)
        card_path = QPainterPath()
        card_path.addRoundedRect(outer, _CARD_RADIUS, _CARD_RADIUS)

        painter.save()
        painter.setClipPath(card_path)
        painter.fillRect(outer, QColor(self._theme.colors.background))

        caption_h = float(scale_by_ui(_CAPTION_HEIGHT))
        pad = float(scale_by_ui(6))
        scene_size = QSize(max(1, round(outer.width() - pad * 2.0)), max(1, round(outer.height() - caption_h - pad * 2.0)))
        dpr = self.devicePixelRatioF()
        cache_key = (scene_size.width(), scene_size.height(), dpr)
        if self._cached_scene is None or self._cached_key != cache_key:
            self._cached_scene = _render_scene_pixmap(self._theme, scene_size, dpr, self.font())
            self._cached_key = cache_key
        painter.drawPixmap(QPointF(outer.left() + pad, outer.top() + pad), self._cached_scene)

        caption_rect = QRectF(outer.left(), outer.bottom() - caption_h, outer.width(), caption_h)
        self._draw_caption_bar(painter, caption_rect)
        painter.restore()

        if self._selected:
            border_pen = QPen(themed_qcolor('@accent'), 2.2)
        elif self._hovered or self.hasFocus():
            border_pen = QPen(themed_qcolor('@text_muted'), 1.5)
        else:
            border_pen = QPen(themed_qcolor('@border'), 1.0)
        painter.setPen(border_pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPath(card_path)
        painter.end()
