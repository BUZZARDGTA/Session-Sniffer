"""Themed telemetry pill status bar widget for the main application window."""

from typing import TYPE_CHECKING, Final, override

from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QColor, QPainter, QPaintEvent
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QLayout, QSizePolicy, QStatusBar, QWidget

from session_sniffer.guis.live_language import register_language_refresh
from session_sniffer.guis.live_theme import register_post_theme_refresh
from session_sniffer.guis.stylesheets import (
    STATUS_BAR_DIVIDER_STYLESHEET,
    STATUS_BAR_ISSUES_PILL_STYLESHEET,
    STATUS_BAR_ISSUES_TITLE_STYLESHEET,
    STATUS_BAR_ITEM_LABEL_STYLESHEET,
    STATUS_BAR_PILL_STYLESHEET,
)
from session_sniffer.guis.theming import get_theme_generation, themed_text_qcolor
from session_sniffer.guis.utils import render_svg_pixmap_from_resource, scale_by_ui
from session_sniffer.i18n import tr

if TYPE_CHECKING:
    from session_sniffer.rendering_core.types import StatusBarItem, StatusBarSectionData, StatusBarSectionKey, StatusBarTone

_STATUS_BAR_BG_SPEC: Final = '@statusbar[#252526]'
_MONO_FONT_CSS: Final = "font-family: 'Menlo', 'Consolas', 'Courier New', monospace;"

_SECTION_ICONS: Final[dict[StatusBarSectionKey, str]] = {
    'capture': 'wifi.svg',
    'config': 'sliders-horizontal.svg',
    'issues': 'triangle-alert.svg',
    'performance': 'activity.svg',
}

_TONE_COLOR_SPECS: Final[dict[StatusBarTone, str]] = {
    'neutral': '@text_strong[#ffffff]',
    'accent': '@accent[#88c0d0]',
    'success': '@success[#22c55e]',
    'warning': '@warning[#f59e0b]',
    'danger': '@danger[#ef4444]',
    'muted': '@text_muted[#9ca3af]',
}

_GLOW_TONES: Final[frozenset[StatusBarTone]] = frozenset({'success', 'warning', 'danger'})
_GLOW_ALPHA: Final = 46


def _resolve_tone_qcolor(tone: StatusBarTone) -> QColor:
    """Resolve a contrast-checked `QColor` for *tone* against the active status bar background."""
    return themed_text_qcolor(_TONE_COLOR_SPECS[tone], _STATUS_BAR_BG_SPEC)


def _build_value_qss(tone: StatusBarTone, *, mono: bool) -> str:
    """Build a theme-resolved stylesheet string for a status bar telemetry value label."""
    color_hex = _resolve_tone_qcolor(tone).name(QColor.NameFormat.HexRgb)
    weight = '500' if tone == 'muted' else '600'
    font_rule = f' {_MONO_FONT_CSS}' if mono else ''
    return f'QLabel {{ background: transparent; border: none; color: {color_hex}; font-size: 8.5pt; font-weight: {weight};{font_rule} }}'


class _StatusDot(QWidget):
    """Small circular status indicator with a soft halo ring matching the web panel telemetry dot."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._tone: StatusBarTone = 'muted'
        dot_box = scale_by_ui(10)
        self.setFixedSize(dot_box, dot_box)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)

    def set_tone(self, tone: StatusBarTone) -> None:
        """Update the dot's semantic color tone and repaint if needed."""
        if self._tone != tone:
            self._tone = tone
            self.update()

    @override
    def paintEvent(self, event: QPaintEvent) -> None:
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)

        color = _resolve_tone_qcolor(self._tone)
        center = QPointF(self.width() / 2.0, self.height() / 2.0)
        core_radius = max(2.5, scale_by_ui(3))

        if self._tone in _GLOW_TONES:
            glow_color = QColor(color)
            glow_color.setAlpha(_GLOW_ALPHA)
            painter.setBrush(glow_color)
            halo_radius = min(self.width() / 2.0, core_radius + max(1.5, scale_by_ui(2)))
            painter.drawEllipse(center, halo_radius, halo_radius)

        painter.setBrush(color)
        painter.drawEllipse(center, core_radius, core_radius)
        painter.end()


class _StatusItemWidget(QWidget):
    """Reusable label + optional dot + value telemetry item inside a status pill."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._layout = QHBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(scale_by_ui(5))
        self._layout.setSizeConstraint(QLayout.SizeConstraint.SetFixedSize)

        self._label = QLabel(self)
        self._label.setStyleSheet(STATUS_BAR_ITEM_LABEL_STYLESHEET)
        self._label.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Preferred)
        self._layout.addWidget(self._label)

        self._dot = _StatusDot(self)
        self._layout.addWidget(self._dot)

        self._value = QLabel(self)
        self._value.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Preferred)
        self._layout.addWidget(self._value)

        self._last_value_style_key: tuple[StatusBarTone, bool, int] | None = None

    def apply_item(self, item: StatusBarItem, *, tone_override: StatusBarTone | None, theme_generation: int) -> None:
        """Update label, dot, and value styling in place."""
        effective_tone: StatusBarTone = item.tone if tone_override is None else tone_override

        has_label = bool(item.label)
        self._label.setVisible(has_label)
        if has_label and self._label.text() != item.label:
            self._label.setText(item.label)

        self._dot.setVisible(item.dot)
        if item.dot:
            self._dot.set_tone(effective_tone)

        if self._value.text() != item.value:
            self._value.setText(item.value)

        target_dir = Qt.LayoutDirection.LeftToRight if item.mono else Qt.LayoutDirection.LayoutDirectionAuto
        if self._value.layoutDirection() != target_dir:
            self._value.setLayoutDirection(target_dir)

        style_key = (effective_tone, item.mono, theme_generation)
        if self._last_value_style_key != style_key:
            self._last_value_style_key = style_key
            self._value.setStyleSheet(_build_value_qss(effective_tone, mono=item.mono))
            self._dot.update()

        self._layout.invalidate()
        self._layout.activate()
        self.updateGeometry()


class _StatusBarPill(QFrame):
    """Bordered telemetry pill card displaying an icon, optional title, and divided items."""

    def __init__(self, section_key: StatusBarSectionKey, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._section_key: StatusBarSectionKey = section_key
        is_issues = section_key == 'issues'
        self.setObjectName('statusBarIssuesPill' if is_issues else 'statusBarPill')
        self.setStyleSheet(STATUS_BAR_ISSUES_PILL_STYLESHEET if is_issues else STATUS_BAR_PILL_STYLESHEET)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)

        self._pill_layout = QHBoxLayout(self)
        self._pill_layout.setContentsMargins(scale_by_ui(10), scale_by_ui(3), scale_by_ui(10), scale_by_ui(3))
        self._pill_layout.setSpacing(scale_by_ui(7))
        self._pill_layout.setSizeConstraint(QLayout.SizeConstraint.SetFixedSize)

        icon_px = scale_by_ui(13)
        self._icon_label = QLabel(self)
        self._icon_label.setFixedSize(icon_px, icon_px)
        self._icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._pill_layout.addWidget(self._icon_label)

        self._title_label: QLabel | None = None
        if is_issues:
            self._title_label = QLabel(self)
            self._title_label.setStyleSheet(STATUS_BAR_ISSUES_TITLE_STYLESHEET)
            self._pill_layout.addWidget(self._title_label)

        self._items_layout = QHBoxLayout()
        self._items_layout.setContentsMargins(0, 0, 0, 0)
        self._items_layout.setSpacing(scale_by_ui(9))
        self._pill_layout.addLayout(self._items_layout)

        self._item_widgets: list[_StatusItemWidget] = []
        self._dividers: list[QFrame] = []
        self._last_icon_key: tuple[StatusBarTone, int] | None = None

    def _resolve_icon_tone(self, *, capture_running: bool) -> StatusBarTone:
        if self._section_key == 'capture':
            return 'success' if capture_running else 'danger'
        if self._section_key == 'issues':
            return 'danger'
        return 'accent'

    def _ensure_slot_count(self, count: int) -> None:
        while len(self._item_widgets) < count:
            if self._item_widgets:
                divider = QFrame(self)
                divider.setObjectName('statusBarDivider')
                divider.setFrameShape(QFrame.Shape.VLine)
                divider.setFixedHeight(scale_by_ui(12))
                divider.setStyleSheet(STATUS_BAR_DIVIDER_STYLESHEET)
                self._items_layout.addWidget(divider)
                self._dividers.append(divider)
            slot = _StatusItemWidget(self)
            self._items_layout.addWidget(slot)
            self._item_widgets.append(slot)

        for index, slot in enumerate(self._item_widgets):
            slot.setVisible(index < count)
        for index, divider in enumerate(self._dividers):
            divider.setVisible(index + 1 < count)

    def apply_section(
        self,
        section: StatusBarSectionData,
        *,
        capture_running: bool,
        theme_generation: int,
        preserve_tooltip: bool = False,
    ) -> None:
        """Render *section* inside this pill card."""
        icon_tone = self._resolve_icon_tone(capture_running=capture_running)
        icon_key = (icon_tone, theme_generation)
        if self._last_icon_key != icon_key:
            self._last_icon_key = icon_key
            icon_px = scale_by_ui(13)
            icon_color = _resolve_tone_qcolor(icon_tone).name(QColor.NameFormat.HexRgb)
            self._icon_label.setPixmap(
                render_svg_pixmap_from_resource(_SECTION_ICONS[self._section_key], icon_px, icon_px, icon_color),
            )

        if self._title_label is not None and self._title_label.text() != section.title:
            self._title_label.setText(section.title)

        if not preserve_tooltip and section.title and self.toolTip() != section.title:
            self.setToolTip(section.title)

        self._ensure_slot_count(len(section.items))
        for index, item in enumerate(section.items):
            tone_override: StatusBarTone | None = 'danger' if self._section_key == 'capture' and not index and not capture_running else None
            self._item_widgets[index].apply_item(item, tone_override=tone_override, theme_generation=theme_generation)

        self._items_layout.invalidate()
        self._pill_layout.invalidate()
        self._pill_layout.activate()
        self.adjustSize()
        self.updateGeometry()


class SessionStatusBar(QStatusBar):
    """Status bar displaying themed telemetry pill cards for capture, config, issues, and performance."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Create the status bar and mount the four pill card widgets."""
        super().__init__(parent)
        self.setSizeGripEnabled(False)

        container = QWidget(self)
        container.setObjectName('statusBarContainer')
        container.setStyleSheet('QWidget#statusBarContainer { background: transparent; border: none; }')
        row_layout = QHBoxLayout(container)
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.setSpacing(scale_by_ui(8))

        self._capture_pill = _StatusBarPill('capture', container)
        self._config_pill = _StatusBarPill('config', container)
        self._issues_pill = _StatusBarPill('issues', container)
        self._issues_pill.setVisible(False)
        self._performance_pill = _StatusBarPill('performance', container)

        self._pills: dict[StatusBarSectionKey, _StatusBarPill] = {
            'capture': self._capture_pill,
            'config': self._config_pill,
            'issues': self._issues_pill,
            'performance': self._performance_pill,
        }

        row_layout.addWidget(self._capture_pill)
        row_layout.addWidget(self._config_pill)
        row_layout.addWidget(self._issues_pill)
        row_layout.addStretch(1)
        row_layout.addWidget(self._performance_pill)
        self.addWidget(container, 1)
        self._row_layout = row_layout

        self._last_sections: tuple[StatusBarSectionData, ...] = ()
        self._last_capture_running: bool = True
        self._last_render_key: tuple[tuple[StatusBarSectionData, ...], bool, int] | None = None

        self._refresh_language_texts()
        register_language_refresh(self, self._refresh_language_texts)
        register_post_theme_refresh(self, self._refresh_theme_visuals)

    def _refresh_language_texts(self) -> None:
        self._performance_pill.setToolTip(
            tr(
                'Packet capture performance metrics:\n\n'
                '• Latency: Processing delay between packet arrival at the network driver and capture analysis (not network ping).\n'
                '  If this value steadily increments, the capture engine is falling behind real-time traffic (see Capture Overflow Timer setting).\n\n'
                '• Restarts: Number of times packet capture was automatically restarted.',
            ),
        )

    def _refresh_theme_visuals(self) -> None:
        """Re-apply contrast-checked pill icons, dots, and value colors after a runtime theme switch."""
        self._last_render_key = None
        if self._last_sections:
            self.set_sections(self._last_sections, capture_running=self._last_capture_running)

    def set_sections(self, sections: tuple[StatusBarSectionData, ...], *, capture_running: bool) -> None:
        """Update all visible status bar pill cards from *sections*."""
        theme_generation = get_theme_generation()
        render_key = (sections, capture_running, theme_generation)
        if self._last_render_key == render_key:
            return
        self._last_render_key = render_key
        self._last_sections = sections
        self._last_capture_running = capture_running

        sections_by_key = {section.key: section for section in sections}
        for key, pill in self._pills.items():
            section = sections_by_key.get(key)
            if section is None or not section.items:
                pill.setVisible(False)
                continue
            pill.apply_section(
                section,
                capture_running=capture_running,
                theme_generation=theme_generation,
                preserve_tooltip=key == 'performance',
            )
            pill.setVisible(True)
        self._row_layout.invalidate()
        self._row_layout.activate()
