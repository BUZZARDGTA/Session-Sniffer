"""Clickable miniature UI preview card widget for browsing built-in and custom themes."""

from typing import TYPE_CHECKING, Final, NamedTuple, override

from PySide6.QtCore import QEvent, QPointF, QRect, QRectF, QSize, Qt, Signal
from PySide6.QtGui import (
    QColor,
    QEnterEvent,
    QFont,
    QFontMetrics,
    QKeyEvent,
    QMouseEvent,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
)
from PySide6.QtWidgets import QFrame, QSizePolicy, QWidget

from session_sniffer.guis.theming import Theme, get_active_theme, themed_qcolor, themed_text_qcolor
from session_sniffer.guis.theming._engine import ThemeTransform
from session_sniffer.guis.utils import scale_by_ui

if TYPE_CHECKING:
    from PySide6.QtGui import QPaintEvent

_CARD_HEIGHT: Final = 196
_CARD_MIN_WIDTH: Final = 248
_CAPTION_HEIGHT: Final = 34
_CARD_RADIUS: Final = 8.0
_SCENE_RADIUS: Final = 5.0


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
    tint_kind: str  # 'accent' | 'control' | 'role' | 'none'


_PREVIEW_ROWS: Final[tuple[_PreviewRow, ...]] = (
    _PreviewRow('★ HostPlayer', '198.51.100.14', '22 ms', 'Host', 'accent', 'strong', bold_user=True, bold_ping=True, green_ping=True, muted_ip=False, tint_kind='accent'),
    _PreviewRow('NightRider99', '203.0.113.42', '41 ms', 'Looky', 'secondary', 'role', bold_user=False, bold_ping=False, green_ping=True, muted_ip=False, tint_kind='none'),
    _PreviewRow('PacketStorm', '192.0.2.188', '148 ms', 'High', 'warning', 'normal', bold_user=False, bold_ping=True, green_ping=False, muted_ip=False, tint_kind='control'),
    _PreviewRow('KnownModder', '198.51.100.99', '265 ms', 'Alert', 'danger', 'role', bold_user=True, bold_ping=False, green_ping=False, muted_ip=True, tint_kind='role'),
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
    c_surface = QColor(colors.surface)
    c_control = QColor(colors.control)
    c_border = QColor(colors.border)
    c_accent = QColor(colors.accent)
    c_secondary = QColor(colors.secondary)
    c_success = QColor(colors.success)

    painter.fillRect(rect, c_surface)
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
    _draw_pill(painter, cap_rect, '● Capturing', c_success, transform.text_on(QColor('#22c55e'), c_surface))

    game_rect = QRectF(cap_rect.right() + float(scale_by_ui(4)), pill_y, float(scale_by_ui(34)), pill_h)
    _draw_pill(painter, game_rect, 'GTA V', c_secondary, transform.text_on(QColor('#a78bfa'), c_surface))

    btn_w = float(scale_by_ui(34))
    btn_rect = QRectF(rect.right() - pad - btn_w, pill_y, btn_w, pill_h)
    btn_path = QPainterPath()
    btn_path.addRoundedRect(btn_rect, 3.0, 3.0)
    painter.fillPath(btn_path, c_accent)
    painter.setPen(transform.text_on(QColor('#ffffff'), QColor('#3d8ec9')))
    painter.drawText(btn_rect, Qt.AlignmentFlag.AlignCenter, 'Filter')

    search_left = game_rect.right() + float(scale_by_ui(6))
    search_right = btn_rect.left() - float(scale_by_ui(5))
    if search_right - search_left >= float(scale_by_ui(36)):
        search_rect = QRectF(search_left, pill_y, search_right - search_left, pill_h)
        search_path = QPainterPath()
        search_path.addRoundedRect(search_rect, 3.0, 3.0)
        painter.fillPath(search_path, c_control)
        painter.setPen(QPen(c_border, 1.0))
        painter.drawPath(search_path)
        search_font = QFont(base_font)
        search_font.setPointSizeF(6.0)
        painter.setFont(search_font)
        painter.setPen(QColor(colors.text_muted))
        text_rect = search_rect.adjusted(float(scale_by_ui(5)), 0.0, -float(scale_by_ui(3)), 0.0)
        painter.drawText(text_rect, Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, 'Search…')


def _draw_preview_table(painter: QPainter, rect: QRectF, transform: ThemeTransform, base_font: QFont) -> None:
    colors = transform.colors
    c_surface = QColor(colors.surface)
    c_control = QColor(colors.control)
    c_border = QColor(colors.border)
    c_accent = QColor(colors.accent)

    table_path = QPainterPath()
    table_path.addRoundedRect(rect, 4.0, 4.0)
    painter.save()
    painter.setClipPath(table_path)
    painter.fillRect(rect, c_surface)

    header_h = float(scale_by_ui(15))
    header_rect = QRectF(rect.left(), rect.top(), rect.width(), header_h)
    painter.fillRect(header_rect, c_control)
    painter.setPen(QPen(c_border, 1.0))
    painter.drawLine(QPointF(rect.left(), header_rect.bottom()), QPointF(rect.right(), header_rect.bottom()))

    w = rect.width()
    col_x = (rect.left() + float(scale_by_ui(6)), rect.left() + w * 0.39, rect.left() + w * 0.67, rect.left() + w * 0.82)
    hdr_font = QFont(base_font)
    hdr_font.setPointSizeF(5.8)
    hdr_font.setBold(True)
    painter.setFont(hdr_font)
    painter.setPen(QColor(colors.text_muted))
    for idx, title in enumerate(('Username', 'IP Address', 'Ping', 'Tag')):
        right_edge = col_x[idx + 1] if idx + 1 < len(col_x) else rect.right() - float(scale_by_ui(4))
        col_rect = QRectF(col_x[idx], header_rect.top(), right_edge - col_x[idx], header_h)
        painter.drawText(col_rect, Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, title)

    rows_top = header_rect.bottom()
    row_h = (rect.bottom() - rows_top) / len(_PREVIEW_ROWS)
    token_colors = {
        'accent': (c_accent, '#38bdf8'),
        'secondary': (QColor(colors.secondary), '#a78bfa'),
        'warning': (QColor(colors.warning), '#f59e0b'),
        'danger': (QColor(colors.danger), '#f87171'),
    }
    row_font = QFont(base_font)
    row_font.setPointSizeF(6.1)
    bold_font = QFont(row_font)
    bold_font.setBold(True)

    for row_idx, row in enumerate(_PREVIEW_ROWS):
        row_rect = QRectF(rect.left(), rows_top + row_idx * row_h, w, row_h)
        role_qcolor, canonical_fg = token_colors[row.role]
        if row.tint_kind == 'accent':
            painter.fillRect(row_rect, _with_alpha(c_accent, 42))
        elif row.tint_kind == 'control':
            painter.fillRect(row_rect, _with_alpha(c_control, 95))
        elif row.tint_kind == 'role':
            painter.fillRect(row_rect, _with_alpha(role_qcolor, 22))

        painter.setFont(bold_font if row.bold_user else row_font)
        if row.user_style == 'strong':
            user_fg = QColor(colors.text_strong)
        elif row.user_style == 'role':
            user_fg = transform.text_on(QColor(canonical_fg), c_surface)
        else:
            user_fg = QColor(colors.text)
        painter.setPen(user_fg)
        user_rect = QRectF(col_x[0], row_rect.top(), col_x[1] - col_x[0] - 2.0, row_h)
        painter.drawText(user_rect, Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, row.username)

        painter.setFont(row_font)
        painter.setPen(QColor(colors.text_muted if row.muted_ip else colors.text))
        ip_rect = QRectF(col_x[1], row_rect.top(), col_x[2] - col_x[1] - 2.0, row_h)
        painter.drawText(ip_rect, Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, row.ip_text)

        ping_canonical = '#22c55e' if row.green_ping else canonical_fg
        painter.setFont(bold_font if row.bold_ping else row_font)
        painter.setPen(transform.text_on(QColor(ping_canonical), c_surface))
        ping_rect = QRectF(col_x[2], row_rect.top(), col_x[3] - col_x[2] - 2.0, row_h)
        painter.drawText(ping_rect, Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, row.ping_text)

        pill_pad_y = max(1.5, (row_h - float(scale_by_ui(12))) / 2.0)
        tag_rect = QRectF(col_x[3], row_rect.top() + pill_pad_y, rect.right() - col_x[3] - float(scale_by_ui(5)), row_h - pill_pad_y * 2.0)
        painter.setFont(hdr_font)
        _draw_pill(painter, tag_rect, row.tag_text, role_qcolor, transform.text_on(QColor(canonical_fg), c_surface))

    painter.restore()
    painter.setPen(QPen(c_border, 1.0))
    painter.setBrush(Qt.BrushStyle.NoBrush)
    painter.drawPath(table_path)


def _draw_preview_status_sparkline(painter: QPainter, rect: QRectF, transform: ThemeTransform, base_font: QFont) -> None:
    colors = transform.colors
    status_font = QFont(base_font)
    status_font.setPointSizeF(5.9)
    painter.setFont(status_font)
    painter.setPen(QColor(colors.text_muted))
    painter.drawText(rect, Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, '01:14:22 • 48.2 KB/s')

    spark_w = min(float(scale_by_ui(74)), rect.width() * 0.36)
    spark_rect = QRectF(rect.right() - spark_w, rect.top() + 2.0, spark_w, max(6.0, rect.height() - 4.0))
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
    c_accent = QColor(colors.accent)
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
    sec_top = scene_rect.top() + toolbar_h + float(scale_by_ui(4))
    sec_h = float(scale_by_ui(13))
    painter.fillRect(QRectF(scene_rect.left() + pad_x, sec_top + 2.0, 2.5, sec_h - 4.0), QColor(colors.accent))
    sec_font = QFont(base_font)
    sec_font.setPointSizeF(6.2)
    sec_font.setBold(True)
    painter.setFont(sec_font)
    painter.setPen(QColor(colors.text_strong))
    sec_text_rect = QRectF(scene_rect.left() + pad_x + float(scale_by_ui(6)), sec_top, scene_rect.width() - pad_x * 2.0 - float(scale_by_ui(6)), sec_h)
    painter.drawText(sec_text_rect, Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, 'Connected Players (4)')
    sec_font.setBold(False)
    sec_font.setPointSizeF(5.8)
    painter.setFont(sec_font)
    painter.setPen(QColor(colors.text_muted))
    painter.drawText(sec_text_rect, Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight, '148 PPS')

    status_h = float(scale_by_ui(15))
    table_top = sec_top + sec_h + float(scale_by_ui(3))
    table_bottom = scene_rect.bottom() - status_h - float(scale_by_ui(4))
    table_rect = QRectF(scene_rect.left() + pad_x, table_top, scene_rect.width() - pad_x * 2.0, max(float(scale_by_ui(40)), table_bottom - table_top))
    _draw_preview_table(painter, table_rect, transform, base_font)

    status_rect = QRectF(scene_rect.left() + pad_x, table_rect.bottom() + float(scale_by_ui(2)), scene_rect.width() - pad_x * 2.0, status_h)
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

    def _update_tooltip(self) -> None:
        kind = 'Built-in preset' if self._theme.builtin else 'Custom theme'
        active_suffix = ' (currently active)' if self.is_active_theme else ''
        self.setToolTip(f'{self._theme.name} — {kind}{active_suffix}\nClick to apply this theme live.')

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
        active_accent = themed_qcolor('#3d8ec9')
        caption_bg_hex = '#243447' if self._selected else '#252526'
        caption_bg = themed_qcolor(caption_bg_hex)
        painter.fillRect(caption_rect, caption_bg)
        painter.setPen(QPen(themed_qcolor('#3e3e42'), 1.0))
        painter.drawLine(QPointF(caption_rect.left(), caption_rect.top()), QPointF(caption_rect.right(), caption_rect.top()))

        pad_x = float(scale_by_ui(9))
        dot_size = float(scale_by_ui(13))
        radio_rect = QRectF(caption_rect.left() + pad_x, caption_rect.center().y() - dot_size / 2.0, dot_size, dot_size)
        if self._selected:
            painter.setBrush(active_accent)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawEllipse(radio_rect)
            inner = radio_rect.adjusted(dot_size * 0.28, dot_size * 0.28, -dot_size * 0.28, -dot_size * 0.28)
            painter.setBrush(themed_text_qcolor('#ffffff', '#3d8ec9'))
            painter.drawEllipse(inner)
        else:
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.setPen(QPen(themed_qcolor('#6b7280'), 1.4))
            painter.drawEllipse(radio_rect)

        swatch_hexes = (
            self._theme.colors.background,
            self._theme.colors.accent,
            self._theme.colors.secondary,
            self._theme.colors.success,
            self._theme.colors.warning,
            self._theme.colors.danger,
        )
        swatch_d = float(scale_by_ui(9))
        swatch_gap = float(scale_by_ui(3))
        swatches_total_w = len(swatch_hexes) * swatch_d + (len(swatch_hexes) - 1) * swatch_gap
        swatches_left = caption_rect.right() - pad_x - swatches_total_w
        swatch_y = caption_rect.center().y() - swatch_d / 2.0
        swatch_border = QPen(themed_qcolor('#6b7280'), 0.8)
        for idx, color_hex in enumerate(swatch_hexes):
            sx = swatches_left + idx * (swatch_d + swatch_gap)
            painter.setBrush(QColor(color_hex))
            painter.setPen(swatch_border)
            painter.drawEllipse(QRectF(sx, swatch_y, swatch_d, swatch_d))

        right_limit = swatches_left - float(scale_by_ui(7))
        if self.is_active_theme:
            badge_font = QFont(self.font())
            badge_font.setPointSizeF(6.8)
            badge_font.setBold(True)
            painter.setFont(badge_font)
            badge_w = float(QFontMetrics(badge_font).horizontalAdvance('Active') + scale_by_ui(12))
            badge_h = float(scale_by_ui(16))
            badge_rect = QRectF(right_limit - badge_w, caption_rect.center().y() - badge_h / 2.0, badge_w, badge_h)
            _draw_pill(painter, badge_rect, 'Active', themed_qcolor('#22c55e'), themed_text_qcolor('#4ade80', caption_bg_hex))
            right_limit = badge_rect.left() - float(scale_by_ui(6))

        name_left = radio_rect.right() + float(scale_by_ui(7))
        name_w = max(0, int(right_limit - name_left))
        if name_w > 0:
            name_font = QFont(self.font())
            name_font.setPointSizeF(8.8)
            name_font.setBold(self._selected)
            painter.setFont(name_font)
            painter.setPen(themed_text_qcolor('#ffffff' if self._selected else '#e0e0e0', caption_bg_hex))
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
            border_pen = QPen(themed_qcolor('#3d8ec9'), 2.2)
        elif self._hovered or self.hasFocus():
            border_pen = QPen(themed_qcolor('#8b949e'), 1.5)
        else:
            border_pen = QPen(themed_qcolor('#3e3e42'), 1.0)
        painter.setPen(border_pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPath(card_path)
        painter.end()
