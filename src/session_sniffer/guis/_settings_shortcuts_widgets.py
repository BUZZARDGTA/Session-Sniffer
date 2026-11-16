"""Custom pill switches, tactile keycap shortcut recorders, and row cards for the Shortcuts settings tab."""

import sys
from typing import TYPE_CHECKING, Final, override

from PySide6.QtCore import QEvent, QKeyCombination, QPoint, QRectF, QSize, Qt, Signal
from PySide6.QtGui import QColor, QFont, QFontMetricsF, QIcon, QKeyEvent, QKeySequence, QLinearGradient, QPainter, QPen, QPixmap
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import (
    QCheckBox,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QSizePolicy,
    QToolButton,
    QToolTip,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.guis.live_language import register_language_refresh
from session_sniffer.guis.stylesheets import (
    SHORTCUT_DESC_LABEL_STYLESHEET,
    SHORTCUT_GLOBAL_BADGE_STYLESHEET,
    SHORTCUT_RESET_ICON_BUTTON_STYLESHEET,
    SHORTCUT_ROW_CARD_STYLESHEET,
    SHORTCUT_TITLE_LABEL_STYLESHEET,
)
from session_sniffer.guis.theming import ICONS_DIR_PATH, themed_qcolor, themed_text_qcolor
from session_sniffer.guis.utils import scale_by_ui
from session_sniffer.i18n import tr
from session_sniffer.settings import SETTING_DEFAULTS, SETTING_METADATA, SettingType
from session_sniffer.text_utils import is_bare_typing_hotkey

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from PySide6.QtGui import QMouseEvent, QPaintEvent, QResizeEvent

    from session_sniffer.settings import SettingMeta

_MODIFIER_ONLY_QT_KEYS: Final[frozenset[Qt.Key]] = frozenset({
    Qt.Key.Key_Control,
    Qt.Key.Key_Shift,
    Qt.Key.Key_Alt,
    Qt.Key.Key_AltGr,
    Qt.Key.Key_Meta,
    Qt.Key.Key_Super_L,
    Qt.Key.Key_Super_R,
    Qt.Key.Key_Hyper_L,
    Qt.Key.Key_Hyper_R,
    Qt.Key.Key_Mode_switch,
    Qt.Key.Key_unknown,
})
_RECORDED_CHORD_MODIFIERS: Final[Qt.KeyboardModifier] = (
    Qt.KeyboardModifier.ControlModifier
    | Qt.KeyboardModifier.ShiftModifier
    | Qt.KeyboardModifier.AltModifier
    | Qt.KeyboardModifier.MetaModifier
    | Qt.KeyboardModifier.KeypadModifier
)
_WIN32_VK_NUMPAD0: Final[int] = 0x60
_WIN32_VK_DIVIDE: Final[int] = 0x6F
_MAX_MODIFIER_PREFIX_PASSES: Final[int] = 5
_TWO_TOKEN_CHORD: Final[int] = 2

SHORTCUT_ROW_DESCRIPTIONS: Final[dict[str, str]] = {
    'shortcut_focus_search': 'Jump to the global search bar',
    'shortcut_merge_tables': 'Switch between merged and split player tables',
    'shortcut_open_settings': 'Open this settings dialog',
    'shortcut_clear_connected': 'Clear all connected players from the table',
    'shortcut_clear_disconnected': 'Clear all disconnected players from the table',
    'toggle_capture_hotkey': 'Start or stop packet capture',
    'toggle_visual_notifications_hotkey': 'Mute or enable visual popup notifications',
    'toggle_voice_notifications_hotkey': 'Mute or enable voice notifications',
    'toggle_all_notifications_hotkey': 'Mute or enable all notifications',
    'solo_session_hotkey': 'Suspend the game briefly for a solo session',
    'suspend_process_hotkey': 'Manually suspend or resume the game process',
    'player_resolver_hotkey': 'Open or focus the Player Resolver window',
    'redetect_host_hotkey': 'Re-evaluate session host detection',
    'looky_crawler_hotkey': 'Request the Looky crawler bot in your session',
    'looky_rescan_hotkey': 'Refresh Looky data for all eligible players',
}


def _parse_chord_tokens(portable: str) -> list[str]:
    """Split a portable `QKeySequence` chord string into displayable keycap labels."""
    remaining = portable.strip()
    if not remaining:
        return []

    modifiers: list[str] = []
    is_numpad = False
    meta_label = 'Win' if sys.platform == 'win32' else 'Meta'
    num_prefix = 'num+'
    mod_prefixes = (
        ('ctrl+', 'Ctrl'),
        ('alt+', 'Alt'),
        ('shift+', 'Shift'),
        ('meta+', meta_label),
    )

    for _ in range(_MAX_MODIFIER_PREFIX_PASSES):
        lowered = remaining.lower()
        if lowered.startswith(num_prefix) and len(remaining) > len(num_prefix):
            is_numpad = True
            remaining = remaining[len(num_prefix) :]
            continue
        matched = False
        for prefix, label in mod_prefixes:
            if lowered.startswith(prefix) and len(remaining) > len(prefix):
                modifiers.append(label)
                remaining = remaining[len(prefix) :]
                matched = True
                break
        if not matched:
            break

    key_token = f'Num {remaining}' if is_numpad else remaining
    return [*modifiers, key_token]


class PillToggleSwitch(QCheckBox):
    """Compact pill-shaped toggle switch compatible with `QCheckBox` settings bindings."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the fixed-size pill toggle switch."""
        super().__init__(parent)
        self._hovered: bool = False
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedSize(scale_by_ui(38), scale_by_ui(20))
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.toggled.connect(lambda _checked=False: self.update())

    @override
    def sizeHint(self) -> QSize:
        return QSize(scale_by_ui(38), scale_by_ui(20))

    @override
    def event(self, e: QEvent) -> bool:
        ev_type = e.type()
        if ev_type == QEvent.Type.Enter:
            self._hovered = True
            self.update()
        elif ev_type == QEvent.Type.Leave:
            self._hovered = False
            self.update()
        elif ev_type in (QEvent.Type.EnabledChange, QEvent.Type.PaletteChange, QEvent.Type.StyleChange):
            self.update()
        return super().event(e)

    @override
    def mousePressEvent(self, e: QMouseEvent) -> None:
        if e.button() == Qt.MouseButton.LeftButton and self.isEnabled() and self.rect().contains(e.position().toPoint()):
            self.setDown(True)
            self.update()
            e.accept()
            return
        super().mousePressEvent(e)

    @override
    def mouseReleaseEvent(self, e: QMouseEvent) -> None:
        if e.button() == Qt.MouseButton.LeftButton and self.isDown():
            self.setDown(False)
            if self.isEnabled() and self.rect().contains(e.position().toPoint()):
                self.click()
            self.update()
            e.accept()
            return
        super().mouseReleaseEvent(e)

    @override
    def paintEvent(self, arg__1: QPaintEvent) -> None:
        del arg__1
        painter = QPainter(self)
        painter.setRenderHints(QPainter.RenderHint.Antialiasing)

        rect = QRectF(self.rect()).adjusted(1.0, 1.0, -1.0, -1.0)
        radius = rect.height() / 2.0
        enabled = self.isEnabled()
        checked = self.isChecked()

        if not enabled:
            track_color = themed_qcolor('@accent[rgba(59, 130, 246, 0.28)]') if checked else themed_qcolor('@control[#181c23]')
            border_color = themed_qcolor('@border[rgba(59, 130, 246, 0.32)]') if checked else themed_qcolor('@border[#252b36]')
            thumb_color = themed_qcolor('@text_muted[#8a96a8]') if checked else themed_qcolor('@text_muted[#505866]')
        elif checked:
            track_color = themed_qcolor('@accent[#4b8df8]') if self._hovered else themed_qcolor('@accent[#3b82f6]')
            border_color = themed_qcolor('@accent[#60a5fa]') if self._hovered else themed_qcolor('@accent[#3b82f6]')
            thumb_color = themed_text_qcolor('@text_strong[#ffffff]', '@accent[#3b82f6]')
        else:
            track_color = themed_qcolor('@control[#2c3340]') if self._hovered else themed_qcolor('@control[#232934]')
            border_color = themed_qcolor('@border[#4d586b]') if self._hovered else themed_qcolor('@border[#3a4354]')
            thumb_color = themed_qcolor('@text[#d5dde8]') if self._hovered else themed_qcolor('@text[#aab4c3]')

        painter.setPen(QPen(border_color, 1.0))
        painter.setBrush(track_color)
        painter.drawRoundedRect(rect, radius, radius)

        margin = float(scale_by_ui(3))
        thumb_d = max(4.0, rect.height() - margin * 2.0)
        is_rtl = self.layoutDirection() == Qt.LayoutDirection.RightToLeft
        on_right = (not checked) if is_rtl else checked
        thumb_x = (rect.right() - margin - thumb_d) if on_right else (rect.left() + margin)
        thumb_y = rect.top() + (rect.height() - thumb_d) / 2.0

        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(thumb_color)
        painter.drawEllipse(QRectF(thumb_x, thumb_y, thumb_d, thumb_d))
        painter.end()


class _ElidedDescriptionLabel(QLabel):
    """Single-line description label that smoothly elides trailing text on narrow layouts."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._full_text: str = ''
        self.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.setStyleSheet(SHORTCUT_DESC_LABEL_STYLESHEET)

    def set_full_text(self, text: str) -> None:
        """Store un-truncated *text* and update the visible elided label."""
        self._full_text = text
        self._sync_elided()

    def _sync_elided(self) -> None:
        avail = max(0, self.width())
        if avail <= 0 or not self._full_text:
            super().setText(self._full_text)
            return
        mode = Qt.TextElideMode.ElideLeft if self.layoutDirection() == Qt.LayoutDirection.RightToLeft else Qt.TextElideMode.ElideRight
        super().setText(self.fontMetrics().elidedText(self._full_text, mode, avail))

    @override
    def resizeEvent(self, event: QResizeEvent) -> None:
        super().resizeEvent(event)
        self._sync_elided()


class _ClearShortcutButton(QToolButton):
    """Frameless inline `circle-x.svg` unbind button with crisp vector hover tinting and no background box."""

    def __init__(self, parent: QWidget | None = None, *, on_hover_changed: Callable[[], None] | None = None) -> None:
        super().__init__(parent)
        self._hovered: bool = False
        self._on_hover_changed = on_hover_changed
        self._svg_renderer = QSvgRenderer(str(ICONS_DIR_PATH / 'circle-x.svg'), self)
        btn_px = scale_by_ui(22)
        self.setFixedSize(btn_px, btn_px)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    @property
    def is_hovered(self) -> bool:
        """Return `True` while the pointer is hovering over the clear button."""
        return self._hovered

    @override
    def event(self, e: QEvent) -> bool:
        ev_type = e.type()
        if ev_type == QEvent.Type.Enter:
            self._hovered = True
            self.update()
            if self._on_hover_changed is not None:
                self._on_hover_changed()
        elif ev_type in (QEvent.Type.Leave, QEvent.Type.Hide):
            if self._hovered:
                self._hovered = False
                self.update()
                if self._on_hover_changed is not None:
                    self._on_hover_changed()
        elif ev_type in (QEvent.Type.PaletteChange, QEvent.Type.StyleChange):
            self._svg_renderer.load(str(ICONS_DIR_PATH / 'circle-x.svg'))
            self.update()
        return super().event(e)

    @override
    def paintEvent(self, arg__1: QPaintEvent) -> None:
        del arg__1
        if not self._svg_renderer.isValid():
            return
        dpr = max(1.0, self.devicePixelRatioF())
        icon_logical = scale_by_ui(16)
        icon_phys = max(1, round(icon_logical * dpr))

        pixmap = QPixmap(icon_phys, icon_phys)
        pixmap.setDevicePixelRatio(dpr)
        pixmap.fill(Qt.GlobalColor.transparent)

        if self.isDown():
            tint = themed_qcolor('@danger[#ef4444]')
        elif self._hovered:
            tint = themed_qcolor('@danger[#f87171]')
        else:
            tint = themed_qcolor('@text_muted[#7d899b]')

        icon_painter = QPainter(pixmap)
        icon_painter.setRenderHints(QPainter.RenderHint.Antialiasing | QPainter.RenderHint.SmoothPixmapTransform)
        self._svg_renderer.render(icon_painter, QRectF(0.0, 0.0, float(icon_logical), float(icon_logical)))
        icon_painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceIn)
        icon_painter.fillRect(QRectF(0.0, 0.0, float(icon_logical), float(icon_logical)), tint)
        icon_painter.end()

        painter = QPainter(self)
        painter.setRenderHints(QPainter.RenderHint.Antialiasing | QPainter.RenderHint.SmoothPixmapTransform)
        x_pos = (self.width() - icon_logical) / 2.0
        y_pos = (self.height() - icon_logical) / 2.0
        painter.drawPixmap(QPoint(round(x_pos), round(y_pos)), pixmap)
        painter.end()


class _KeycapRecorderSlot(QFrame):
    """Interactive single-chord recorder rendering tactile keycaps, unbound slots, and live listening states."""

    sequence_changed = Signal()

    def __init__(self, parent: QWidget | None = None, *, is_global: bool = False) -> None:
        super().__init__(parent)
        self._is_global: bool = is_global
        self._portable_value: str | None = None
        self._recording: bool = False
        self._hovered: bool = False

        self.setObjectName('keycapRecorderSlot')
        self.setStyleSheet('QFrame#keycapRecorderSlot { background: transparent; border: none; }')
        self.setFocusPolicy(Qt.FocusPolicy.ClickFocus)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(scale_by_ui(32))
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        slot_layout = QHBoxLayout(self)
        slot_layout.setContentsMargins(scale_by_ui(6), 0, scale_by_ui(5), 0)
        slot_layout.setSpacing(0)
        slot_layout.addStretch(1)

        self._clear_button = _ClearShortcutButton(self, on_hover_changed=self.update)
        self._clear_button.clicked.connect(self.clear_value)
        slot_layout.addWidget(self._clear_button, 0, Qt.AlignmentFlag.AlignVCenter)

        self.refresh_localized_texts()
        self._sync_clear_button()

    def refresh_localized_texts(self) -> None:
        """Update localized button tooltips and repaint slot prompt strings."""
        self._clear_button.setToolTip(tr('Unbind shortcut'))
        self.update()

    def value(self) -> str | None:
        """Return the current portable key sequence string, or `None` if unbound."""
        return self._portable_value

    def set_value(self, portable: str | None) -> None:
        """Set the slot's shortcut from a portable string or `None` without emitting `sequence_changed`."""
        normalized: str | None = None
        if portable is not None and portable.strip():
            seq = QKeySequence.fromString(portable.strip(), QKeySequence.SequenceFormat.PortableText)
            text = seq.toString(QKeySequence.SequenceFormat.PortableText).strip()
            if text and '\ufffd' not in text:
                normalized = text
        self._portable_value = normalized
        self._recording = False
        self._sync_clear_button()
        self.update()

    def clear_value(self) -> None:
        """Unbind the current shortcut and emit `sequence_changed` if it was bound."""
        was_bound = self._portable_value is not None
        self._portable_value = None
        self._recording = False
        self._sync_clear_button()
        self.update()
        if was_bound:
            self.sequence_changed.emit()

    def cancel_recording(self) -> None:
        """Exit interactive listening mode without altering the bound shortcut."""
        if self._recording:
            self._set_recording(recording=False)

    def _set_recording(self, *, recording: bool) -> None:
        if self._recording == recording:
            return
        self._recording = recording
        self._sync_clear_button()
        self.update()

    def _sync_clear_button(self) -> None:
        self._clear_button.setVisible(self.isEnabled() and not self._recording and self._portable_value is not None)

    @override
    def event(self, e: QEvent) -> bool:
        ev_type = e.type()
        if ev_type == QEvent.Type.Enter:
            self._hovered = True
            self.update()
        elif ev_type == QEvent.Type.Leave:
            self._hovered = False
            self.update()
        elif ev_type == QEvent.Type.EnabledChange:
            if not self.isEnabled():
                self._recording = False
            self.setCursor(Qt.CursorShape.PointingHandCursor if self.isEnabled() else Qt.CursorShape.ArrowCursor)
            self._sync_clear_button()
            self.update()
        elif ev_type in (QEvent.Type.PaletteChange, QEvent.Type.StyleChange):
            self.update()
        elif ev_type == QEvent.Type.FocusOut and self._recording:
            self._set_recording(recording=False)
        elif self._recording and ev_type == QEvent.Type.ShortcutOverride:
            e.accept()
            return True
        elif self._recording and ev_type == QEvent.Type.KeyPress and isinstance(e, QKeyEvent):
            self._handle_recorded_key(e)
            return True
        return super().event(e)

    @override
    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton and self.isEnabled():
            self._set_recording(recording=True)
            self.setFocus(Qt.FocusReason.MouseFocusReason)
            event.accept()
            return
        if self._recording:
            self._set_recording(recording=False)
            event.accept()
            return
        super().mousePressEvent(event)

    @override
    def keyPressEvent(self, event: QKeyEvent) -> None:
        if self._recording:
            self._handle_recorded_key(event)
            return
        super().keyPressEvent(event)

    def _handle_recorded_key(self, event: QKeyEvent) -> None:
        if event.isAutoRepeat():
            event.accept()
            return
        key = Qt.Key(event.key())
        if key in _MODIFIER_ONLY_QT_KEYS:
            event.accept()
            return

        modifiers = event.modifiers() & _RECORDED_CHORD_MODIFIERS
        if key == Qt.Key.Key_Escape and not modifiers:
            self._set_recording(recording=False)
            event.accept()
            return

        native_vk = event.nativeVirtualKey()
        is_numpad_event = (
            bool(modifiers & Qt.KeyboardModifier.KeypadModifier)
            or key == Qt.Key.Key_Enter
            or (sys.platform == 'win32' and _WIN32_VK_NUMPAD0 <= native_vk <= _WIN32_VK_DIVIDE)
        )
        if is_numpad_event:
            modifiers |= Qt.KeyboardModifier.KeypadModifier

        seq = QKeySequence(QKeyCombination(modifiers, key))
        portable = seq.toString(QKeySequence.SequenceFormat.PortableText).strip()
        if not portable or '\ufffd' in portable:
            self._set_recording(recording=False)
            event.accept()
            return

        if self._is_global and is_bare_typing_hotkey(portable):
            self._set_recording(recording=False)
            QToolTip.showText(
                self.mapToGlobal(QPoint(0, self.height())),
                tr('Global hotkeys with typing keys require Ctrl or Alt (or use Numpad, F1-F24, or Pause).'),
                self,
            )
            event.accept()
            return

        changed = portable != self._portable_value
        self._portable_value = portable
        self._set_recording(recording=False)
        if changed:
            self.sequence_changed.emit()
        event.accept()

    @override
    def paintEvent(self, arg__1: QPaintEvent) -> None:
        del arg__1
        painter = QPainter(self)
        painter.setRenderHints(QPainter.RenderHint.Antialiasing | QPainter.RenderHint.TextAntialiasing)

        rect = QRectF(self.rect()).adjusted(0.75, 0.75, -0.75, -0.75)
        radius = float(scale_by_ui(6))
        enabled = self.isEnabled()

        if self._recording and enabled:
            self._paint_recording_state(painter, rect, radius)
        elif self._portable_value is None:
            self._paint_unbound_state(painter, rect, radius, enabled=enabled)
        else:
            self._paint_bound_state(painter, rect, radius, self._portable_value, enabled=enabled)

        painter.end()

    def _paint_recording_state(self, painter: QPainter, rect: QRectF, radius: float) -> None:
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(themed_qcolor('@accent[rgba(59, 130, 246, 0.14)]'))
        painter.drawRoundedRect(rect, radius, radius)

        inner_glow = rect.adjusted(1.25, 1.25, -1.25, -1.25)
        painter.setPen(QPen(themed_qcolor('@accent[rgba(96, 165, 250, 0.30)]'), 1.0))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawRoundedRect(inner_glow, max(1.0, radius - 1.0), max(1.0, radius - 1.0))

        painter.setPen(QPen(themed_qcolor('@accent[#3b82f6]'), 1.5))
        painter.drawRoundedRect(rect, radius, radius)

        font = QFont(self.font())
        font.setPointSizeF(max(7.5, font.pointSizeF() - 0.5))
        painter.setFont(font)
        fm = QFontMetricsF(font)

        dot_r = scale_by_ui(7) / 2.0
        halo_r = float(scale_by_ui(6))
        gap = float(scale_by_ui(7))
        side_pad = float(scale_by_ui(10))
        max_text_w = max(20.0, rect.width() - side_pad * 2.0 - halo_r * 2.0 - gap)
        prompt = fm.elidedText(tr('Listening\u2026 press keys (Esc to cancel)'), Qt.TextElideMode.ElideRight, int(max_text_w))
        text_w = fm.horizontalAdvance(prompt)
        group_w = dot_r * 2.0 + gap + text_w
        start_x = rect.center().x() - group_w / 2.0
        center_y = rect.center().y()

        is_rtl = self.layoutDirection() == Qt.LayoutDirection.RightToLeft
        dot_cx = (start_x + group_w - dot_r) if is_rtl else (start_x + dot_r)
        text_x = start_x if is_rtl else (start_x + dot_r * 2.0 + gap)

        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(themed_qcolor('@accent[rgba(59, 130, 246, 0.28)]'))
        painter.drawEllipse(QRectF(dot_cx - halo_r, center_y - halo_r, halo_r * 2.0, halo_r * 2.0))
        painter.setBrush(themed_qcolor('@accent[#60a5fa]'))
        painter.drawEllipse(QRectF(dot_cx - dot_r, center_y - dot_r, dot_r * 2.0, dot_r * 2.0))

        painter.setPen(themed_qcolor('@text_strong[#e2eeff]'))
        painter.drawText(QRectF(text_x, rect.top(), text_w + 2.0, rect.height()), Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, prompt)

    def _paint_unbound_state(self, painter: QPainter, rect: QRectF, radius: float, *, enabled: bool) -> None:
        fill = themed_qcolor('@input[#14171f]') if enabled else themed_qcolor('@input[#12151b]')
        if enabled and self._hovered:
            border_col = themed_qcolor('@accent[#4d8ef7]')
            text_col = themed_qcolor('@text[#c4d0e0]')
        elif enabled:
            border_col = themed_qcolor('@border[#353e4f]')
            text_col = themed_qcolor('@text_muted[#8590a2]')
        else:
            border_col = themed_qcolor('@border[#232833]')
            text_col = themed_qcolor('@text_muted[#505866]')

        pen = QPen(border_col, 1.0, Qt.PenStyle.DashLine)
        pen.setDashPattern([4.0, 3.0])
        painter.setPen(pen)
        painter.setBrush(fill)
        painter.drawRoundedRect(rect, radius, radius)

        font = QFont(self.font())
        font.setPointSizeF(max(7.5, font.pointSizeF() - 0.3))
        painter.setFont(font)
        painter.setPen(text_col)
        prompt = f"+ {tr('Click to bind')}"
        painter.drawText(rect.adjusted(6.0, 0.0, -6.0, 0.0), Qt.AlignmentFlag.AlignCenter, prompt)

    def _paint_bound_state(self, painter: QPainter, rect: QRectF, radius: float, portable: str, *, enabled: bool) -> None:
        slot_hovered = self._hovered and not self._clear_button.is_hovered
        fill = themed_qcolor('@input[#141820]') if enabled else themed_qcolor('@input[#12151b]')
        if enabled and slot_hovered:
            border_col = themed_qcolor('@accent[#3d8ec9]')
        elif enabled:
            border_col = themed_qcolor('@border[#2c3545]')
        else:
            border_col = themed_qcolor('@border[#202530]')

        painter.setPen(QPen(border_col, 1.0))
        painter.setBrush(fill)
        painter.drawRoundedRect(rect, radius, radius)

        tokens = _parse_chord_tokens(portable)
        if not tokens:
            return

        cap_font = QFont(self.font())
        cap_font.setWeight(QFont.Weight.DemiBold)
        cap_font.setPointSizeF(max(7.5, cap_font.pointSizeF() - 0.3))
        painter.setFont(cap_font)
        fm = QFontMetricsF(cap_font)

        min_chip_w = float(scale_by_ui(52 if len(tokens) == 1 else (40 if len(tokens) == _TWO_TOKEN_CHORD else 30)))
        h_pad = float(scale_by_ui(14))
        plus_w = float(scale_by_ui(14))

        is_rtl = self.layoutDirection() == Qt.LayoutDirection.RightToLeft
        clear_reserve = float(scale_by_ui(27)) if self._clear_button.isVisible() else float(scale_by_ui(7))
        edge_pad = float(scale_by_ui(7))
        safe_left = rect.left() + (clear_reserve if is_rtl else edge_pad)
        safe_right = rect.right() - (edge_pad if is_rtl else clear_reserve)
        avail_w = max(24.0, safe_right - safe_left)

        chip_widths = [max(min_chip_w, fm.horizontalAdvance(tok) + h_pad) for tok in tokens]
        total_w = sum(chip_widths) + plus_w * max(0, len(tokens) - 1)
        if total_w > avail_w:
            compact_pad = float(scale_by_ui(8))
            plus_w = float(scale_by_ui(10))
            chip_widths = [max(float(scale_by_ui(22)), fm.horizontalAdvance(tok) + compact_pad) for tok in tokens]
            total_w = sum(chip_widths) + plus_w * max(0, len(tokens) - 1)
            if total_w > avail_w and total_w > 0:
                scale_ratio = avail_w / total_w
                chip_widths = [w * scale_ratio for w in chip_widths]
                plus_w *= scale_ratio
                total_w = avail_w

        ideal_start = rect.center().x() - total_w / 2.0
        start_x = min(max(ideal_start, safe_left), max(safe_left, safe_right - total_w))

        cap_h = float(scale_by_ui(21))
        cap_y = rect.center().y() - cap_h / 2.0
        cap_radius = float(scale_by_ui(4))

        bevel_col: QColor = themed_qcolor('@border[#0e1218]') if enabled else themed_qcolor('@border[#0f1217]')
        top_col: QColor = (
            (themed_qcolor('@control[#333b4b]') if slot_hovered else themed_qcolor('@control[#2c3342]'))
            if enabled
            else themed_qcolor('@control[#1d212a]')
        )
        bot_col: QColor = (
            (themed_qcolor('@control[#272e3b]') if slot_hovered else themed_qcolor('@control[#222834]'))
            if enabled
            else themed_qcolor('@control[#181b23]')
        )
        cap_border: QColor = themed_qcolor('@border[#465168]') if enabled else themed_qcolor('@border[#292f3b]')
        cap_text: QColor = (
            themed_text_qcolor('@text_strong[#f2f6fc]', '@control[#282f3d]')
            if enabled
            else themed_qcolor('@text_muted[#5c6574]')
        )
        plus_col: QColor = themed_qcolor('@text_muted[#7e8899]') if enabled else themed_qcolor('@text_muted[#4d5563]')

        cur_x = start_x
        for idx, (tok, chip_w) in enumerate(zip(tokens, chip_widths, strict=True)):
            chip_rect = QRectF(cur_x, cap_y, chip_w, cap_h)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(bevel_col)
            painter.drawRoundedRect(chip_rect.adjusted(0.0, 1.2, 0.0, 1.2), cap_radius, cap_radius)

            face_rect = chip_rect.adjusted(0.0, 0.0, 0.0, -1.0)
            grad = QLinearGradient(face_rect.topLeft(), face_rect.bottomLeft())
            grad.setColorAt(0.0, top_col)
            grad.setColorAt(1.0, bot_col)
            painter.setBrush(grad)
            painter.setPen(QPen(cap_border, 1.0))
            painter.drawRoundedRect(face_rect, cap_radius, cap_radius)

            painter.setPen(cap_text)
            elided_tok = fm.elidedText(tok, Qt.TextElideMode.ElideRight, max(8, int(chip_w - 4.0)))
            painter.drawText(face_rect, Qt.AlignmentFlag.AlignCenter, elided_tok)
            cur_x += chip_w

            if idx + 1 < len(tokens):
                painter.setPen(plus_col)
                painter.drawText(QRectF(cur_x, cap_y, plus_w, cap_h - 1.0), Qt.AlignmentFlag.AlignCenter, '+')
                cur_x += plus_w


class HotkeyEditWidget(QWidget):
    """Single-chord keyboard shortcut control combining a pill toggle, keycap slot, and reset button."""

    hotkey_changed = Signal()

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        is_global: bool = False,
        default_value: str | None = None,
    ) -> None:
        """Initialize the pill switch, fixed-width keycap recorder slot, and default-reset button."""
        super().__init__(parent)
        self._default_value: str | None = default_value.strip() if isinstance(default_value, str) and default_value.strip() else None

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(scale_by_ui(10))

        self.enabled_checkbox = PillToggleSwitch(self)
        self.enabled_checkbox.setChecked(True)

        recorder_container = QWidget(self)
        recorder_container.setObjectName('shortcutRecorderContainer')
        recorder_container.setStyleSheet('QWidget#shortcutRecorderContainer { background: transparent; }')
        recorder_container.setFixedSize(scale_by_ui(256), scale_by_ui(32))
        recorder_layout = QHBoxLayout(recorder_container)
        recorder_layout.setContentsMargins(0, 0, 0, 0)
        recorder_layout.setSpacing(scale_by_ui(4))

        self._slot = _KeycapRecorderSlot(recorder_container, is_global=is_global)

        self._reset_button = QToolButton(recorder_container)
        self._reset_button.setIcon(QIcon(str(ICONS_DIR_PATH / 'rotate-ccw.svg')))
        self._reset_button.setIconSize(QSize(scale_by_ui(14), scale_by_ui(14)))
        self._reset_button.setFixedSize(scale_by_ui(28), scale_by_ui(32))
        self._reset_button.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._reset_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._reset_button.setStyleSheet(SHORTCUT_RESET_ICON_BUTTON_STYLESHEET)
        self._reset_button.clicked.connect(self._reset_to_default)

        recorder_layout.addWidget(self._slot, 1)
        recorder_layout.addWidget(self._reset_button)

        layout.addWidget(self.enabled_checkbox, 0, Qt.AlignmentFlag.AlignVCenter)
        layout.addWidget(recorder_container, 0, Qt.AlignmentFlag.AlignVCenter)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)

        def _apply_language() -> None:
            self._slot.refresh_localized_texts()
            if self._default_value is not None:
                self._reset_button.setToolTip(tr('Reset shortcut to default ({default})', default=self._default_value))

        _apply_language()
        register_language_refresh(self, _apply_language)

        self.enabled_checkbox.toggled.connect(self._sync_controls_enabled)
        self._slot.sequence_changed.connect(self._on_slot_sequence_changed)
        self._sync_controls_enabled()

    def _sync_controls_enabled(self) -> None:
        shortcut_enabled = self.enabled_checkbox.isChecked()
        if not shortcut_enabled:
            self._slot.cancel_recording()
        self._slot.setEnabled(shortcut_enabled)
        show_reset = shortcut_enabled and self._default_value is not None and self._slot.value() != self._default_value
        self._reset_button.setVisible(show_reset)

    def _on_slot_sequence_changed(self) -> None:
        self._sync_controls_enabled()
        self.hotkey_changed.emit()

    def _reset_to_default(self) -> None:
        if self._default_value is None or self._slot.value() == self._default_value:
            return
        self._slot.set_value(self._default_value)
        self._sync_controls_enabled()
        self.hotkey_changed.emit()

    def value(self) -> str | None:
        """Return the current portable key sequence string, or `None` if empty."""
        return self._slot.value()

    def set_value(self, value: str | None) -> None:
        """Set the current shortcut from a portable string or `None`."""
        self._slot.set_value(value)
        self._sync_controls_enabled()


def create_hotkey_widget(key: str, meta: SettingMeta) -> HotkeyEditWidget:
    """Create a keyboard shortcut editor widget for *key* and *meta*.

    Args:
        key: Canonical setting key in `SETTING_METADATA`.
        meta: Setting metadata describing the shortcut's group and tooltip.

    Returns:
        Configured `HotkeyEditWidget` instance.
    """
    raw_default = SETTING_DEFAULTS.get(key)
    default_str = raw_default if isinstance(raw_default, str) else None
    return HotkeyEditWidget(is_global=meta.group != 'Main Window', default_value=default_str)


def build_shortcut_row_card(
    key: str,
    meta: SettingMeta,
    widget: HotkeyEditWidget,
    *,
    tooltip: str | None = None,
) -> tuple[QFrame, QLabel]:
    """Build a styled horizontal row card pairing action title, scope badge, subtitle, and *widget*.

    Args:
        key: Canonical setting key in `SETTING_METADATA`.
        meta: Setting metadata for the shortcut.
        widget: The `HotkeyEditWidget` bound to *key*.
        tooltip: Initial localized tooltip text to apply to the card and title label.

    Returns:
        Tuple of `(row_card_frame, title_label)`.
    """
    card = QFrame()
    card.setObjectName('shortcutRowCard')
    card.setStyleSheet(SHORTCUT_ROW_CARD_STYLESHEET)
    card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    row_layout = QHBoxLayout(card)
    row_layout.setContentsMargins(scale_by_ui(12), scale_by_ui(7), scale_by_ui(10), scale_by_ui(7))
    row_layout.setSpacing(scale_by_ui(10))

    title_label = QLabel()
    title_label.setStyleSheet(SHORTCUT_TITLE_LABEL_STYLESHEET)
    title_label.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Preferred)
    row_layout.addWidget(title_label, 0, Qt.AlignmentFlag.AlignVCenter)

    is_global = meta.group != 'Main Window'
    badge_label: QLabel | None = None
    if is_global:
        badge_label = QLabel()
        badge_label.setStyleSheet(SHORTCUT_GLOBAL_BADGE_STYLESHEET)
        badge_label.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        row_layout.addWidget(badge_label, 0, Qt.AlignmentFlag.AlignVCenter)

    description_key = SHORTCUT_ROW_DESCRIPTIONS.get(key, '')
    desc_label = _ElidedDescriptionLabel(card)
    row_layout.addWidget(desc_label, 1, Qt.AlignmentFlag.AlignVCenter)

    row_layout.addWidget(widget, 0, Qt.AlignmentFlag.AlignVCenter)

    if tooltip is not None and tooltip:
        card.setToolTip(tooltip)
        title_label.setToolTip(tooltip)
        desc_label.setToolTip(tooltip)

    def _refresh_card_texts() -> None:
        title_label.setText(tr(meta.display_label))
        if badge_label is not None:
            badge_label.setText(tr('GLOBAL'))
        if description_key:
            desc_label.set_full_text(tr(description_key))
        live_tip = tr(meta.tooltip) if meta.tooltip else ''
        card.setToolTip(live_tip)
        title_label.setToolTip(live_tip)
        desc_label.setToolTip(live_tip)

    _refresh_card_texts()
    register_language_refresh(card, _refresh_card_texts)
    return card, title_label


def create_shortcuts_master_toggle(meta: SettingMeta) -> PillToggleSwitch:
    """Create the master `Enable Shortcuts` pill toggle switch with localized tooltip."""
    toggle = PillToggleSwitch()
    if meta.tooltip:
        toggle.setToolTip(tr(meta.tooltip))
    return toggle


def populate_shortcut_group_cards(
    group_box: QGroupBox,
    items: Sequence[tuple[str, SettingMeta]],
    widgets: dict[str, QWidget],
    labels: dict[str, QLabel],
) -> None:
    """Populate *group_box* with styled shortcut row cards and register controls in *widgets* and *labels*."""
    shortcut_vbox = QVBoxLayout(group_box)
    shortcut_vbox.setSpacing(scale_by_ui(6))
    for key, meta in items:
        if meta.setting_type != SettingType.HOTKEY:
            continue
        hotkey_widget = create_hotkey_widget(key, meta)
        if (enabled_meta := SETTING_METADATA.get(f'{key}_enabled')) is not None:
            widgets[f'{key}_enabled'] = hotkey_widget.enabled_checkbox
            if enabled_meta.tooltip:
                hotkey_widget.enabled_checkbox.setToolTip(tr(enabled_meta.tooltip))
        tooltip = tr(meta.tooltip) if meta.tooltip else None
        if tooltip is not None and tooltip:
            hotkey_widget.setToolTip(tooltip)
        card, title_label = build_shortcut_row_card(key, meta, hotkey_widget, tooltip=tooltip)
        widgets[key] = hotkey_widget
        labels[key] = title_label
        shortcut_vbox.addWidget(card)
