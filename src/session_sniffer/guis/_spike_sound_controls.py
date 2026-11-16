"""Shared Spike Sound quick-controls widget and preview button state helper."""

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum, auto
from typing import Final

from PySide6.QtCore import QSignalBlocker, Qt
from PySide6.QtWidgets import QAbstractButton, QComboBox, QHBoxLayout, QLabel, QSlider, QWidget

from session_sniffer.constants.standalone import SPIKE_SOUND_MODES, SPIKE_SOUND_SCOPES
from session_sniffer.guis.live_language import register_language_refresh, set_i18n_colon_label
from session_sniffer.guis.theming import themed_text_qcolor
from session_sniffer.guis.utils import render_svg_icon_from_resource, render_svg_pixmap_with_pair, scale_by_ui
from session_sniffer.i18n import tr

SPIKE_VOLUME_MIN: Final[int] = 0
SPIKE_VOLUME_MAX: Final[int] = 100


class SpikeVolumePersistMode(Enum):
    """Persistence strategy when updating Spike Sound volume from live UI controls."""

    DEBOUNCED = auto()
    IMMEDIATE = auto()


type SpikeVolumeChangedCallback = Callable[[int, SpikeVolumePersistMode], None]


@dataclass(frozen=True, slots=True)
class SpikeSoundQuickBarState:
    """Current Spike Sound values displayed by `SpikeSoundQuickBar`."""

    scope: str = 'Open Graphs'
    mode: str = 'Repeating'
    volume: int = SPIKE_VOLUME_MAX


@dataclass(frozen=True, slots=True)
class SpikeSoundQuickBarCallbacks:
    """Change callbacks wired into `SpikeSoundQuickBar`."""

    on_scope_changed: Callable[[str], None] | None = None
    on_mode_changed: Callable[[str], None] | None = None
    on_volume_changed: SpikeVolumeChangedCallback | None = None


def refresh_spike_preview_button(
    button: QAbstractButton,
    *,
    sound_active: bool,
    volume: int,
    scope_disabled_note: str,
) -> None:
    """Update a Spike Sound Preview button's enabled state, volume/mute icon, and contextual tooltip."""
    preview_enabled = sound_active and volume > 0
    tint_hex = themed_text_qcolor('@text[#e5e7eb]', '@surface[#1f2937]').name()
    button.setEnabled(preview_enabled)
    button.setIcon(
        render_svg_icon_from_resource('volume-2.svg' if preview_enabled else 'volume-x.svg', 14, 14, tint_hex),
    )
    preview_tip = tr('Play a preview of the selected spike sound preset.')
    if not sound_active:
        preview_tip = f'{preview_tip}\n\n{scope_disabled_note}'
    elif volume <= 0:
        preview_tip = f"{preview_tip}\n\n{tr('Disabled when Spike Sound Volume is set to 0%.')}"
    button.setToolTip(preview_tip)


class SpikeSoundQuickBar(QWidget):
    """Inline quick-controls bar for Spike Sound scope, behavior, and volume."""

    def __init__(
        self,
        state: SpikeSoundQuickBarState,
        callbacks: SpikeSoundQuickBarCallbacks | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the Spike Sound quick-controls bar."""
        super().__init__(parent)
        cbs = callbacks or SpikeSoundQuickBarCallbacks()
        self._scope = state.scope
        self._mode = state.mode
        self._volume = min(SPIKE_VOLUME_MAX, max(SPIKE_VOLUME_MIN, state.volume))
        self._on_scope_changed = cbs.on_scope_changed
        self._on_mode_changed = cbs.on_mode_changed
        self._on_volume_changed = cbs.on_volume_changed

        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(scale_by_ui(6))

        self._sound_label = QLabel()
        set_i18n_colon_label(self._sound_label, 'Spike Sound')
        row.addWidget(self._sound_label)

        self._scope_combo = QComboBox()
        self._scope_combo.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        for scope_opt in SPIKE_SOUND_SCOPES:
            self._scope_combo.addItem(tr(scope_opt), scope_opt)
        if (scope_idx := self._scope_combo.findData(self._scope)) >= 0:
            self._scope_combo.setCurrentIndex(scope_idx)
        self._scope_combo.currentIndexChanged.connect(self._handle_scope_changed)
        row.addWidget(self._scope_combo)

        self._mode_combo = QComboBox()
        self._mode_combo.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        for mode_opt in SPIKE_SOUND_MODES:
            self._mode_combo.addItem(tr(mode_opt), mode_opt)
        if (mode_idx := self._mode_combo.findData(self._mode)) >= 0:
            self._mode_combo.setCurrentIndex(mode_idx)
        self._mode_combo.currentIndexChanged.connect(self._handle_mode_changed)
        row.addWidget(self._mode_combo)

        row.addSpacing(scale_by_ui(4))

        self._volume_icon_label = QLabel()
        self._volume_icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        row.addWidget(self._volume_icon_label)

        self._volume_slider = QSlider(Qt.Orientation.Horizontal)
        self._volume_slider.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self._volume_slider.setRange(SPIKE_VOLUME_MIN, SPIKE_VOLUME_MAX)
        self._volume_slider.setSingleStep(1)
        self._volume_slider.setPageStep(5)
        self._volume_slider.setFixedWidth(scale_by_ui(72))
        self._volume_slider.setValue(self._volume)
        self._volume_slider.valueChanged.connect(self._handle_volume_changed)
        self._volume_slider.sliderReleased.connect(self._handle_volume_released)
        row.addWidget(self._volume_slider)

        self._volume_value_label = QLabel()
        self._volume_value_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        row.addWidget(self._volume_value_label)

        self.refresh_translations_and_state()
        register_language_refresh(self, self.refresh_translations_and_state)

    @property
    def volume(self) -> int:
        """Return the current volume percentage (`0..100`)."""
        return self._volume

    def sync_state(self, state: SpikeSoundQuickBarState) -> None:
        """Synchronize displayed controls with *state* without emitting change callbacks."""
        self._scope = state.scope
        self._mode = state.mode
        self._volume = min(SPIKE_VOLUME_MAX, max(SPIKE_VOLUME_MIN, state.volume))

        with QSignalBlocker(self._scope_combo):
            if (scope_idx := self._scope_combo.findData(self._scope)) >= 0:
                self._scope_combo.setCurrentIndex(scope_idx)
        with QSignalBlocker(self._mode_combo):
            if (mode_idx := self._mode_combo.findData(self._mode)) >= 0:
                self._mode_combo.setCurrentIndex(mode_idx)
        if not self._volume_slider.isSliderDown() and self._volume_slider.value() != self._volume:
            with QSignalBlocker(self._volume_slider):
                self._volume_slider.setValue(self._volume)
        self.refresh_state()

    def refresh_translations_and_state(self) -> None:
        """Refresh translated combo items, static tooltips, and dependent control states."""
        for i, canonical_scope in enumerate(SPIKE_SOUND_SCOPES):
            if i < self._scope_combo.count():
                self._scope_combo.setItemText(i, tr(canonical_scope))
        for i, canonical_mode in enumerate(SPIKE_SOUND_MODES):
            if i < self._mode_combo.count():
                self._mode_combo.setItemText(i, tr(canonical_mode))
        scope_tip = tr('Choose where spike alert sounds are active (Disabled, Open Graphs, or Global).')
        self._sound_label.setToolTip(scope_tip)
        self._scope_combo.setToolTip(scope_tip)
        self.refresh_state()

    def refresh_state(self) -> None:
        """Update enabled state, non-clickable speaker indicator, percentage readout, and contextual tooltips."""
        sound_active = self._scope != 'Disabled'
        is_audible = sound_active and self._volume > 0
        scope_disabled_note = tr('Disabled when Spike Sound Scope is set to Disabled.')

        self._mode_combo.setEnabled(sound_active)
        mode_tip = tr('Choose how spike alert sounds behave when traffic crosses above the threshold.')
        self._mode_combo.setToolTip(mode_tip if sound_active else f'{mode_tip}\n\n{scope_disabled_note}')

        icon_px = scale_by_ui(15)
        fg_token = '@text[#e5e7eb]' if is_audible else '@text_muted[#888888]'
        self._volume_icon_label.setPixmap(
            render_svg_pixmap_with_pair(
                'volume-2.svg' if is_audible else 'volume-x.svg',
                icon_px,
                icon_px,
                (fg_token, '@surface[#1f2937]'),
            ),
        )
        self._volume_icon_label.setEnabled(sound_active)

        percent_symbol = tr('%')
        self._volume_value_label.setMinimumWidth(
            max(scale_by_ui(32), self._volume_value_label.fontMetrics().horizontalAdvance(f'100{percent_symbol}') + scale_by_ui(4)),
        )
        self._volume_value_label.setText(f'{self._volume}{percent_symbol}')
        self._volume_slider.setEnabled(sound_active)
        self._volume_value_label.setEnabled(sound_active)

        volume_base_tip = tr(
            'Spike Sound Volume: {volume}%\n\nAdjust playback volume for traffic spike alert sounds.',
            volume=self._volume,
        )
        volume_tip = volume_base_tip if sound_active else f'{volume_base_tip}\n\n{scope_disabled_note}'
        self._volume_icon_label.setToolTip(volume_tip)
        self._volume_slider.setToolTip(volume_tip)
        self._volume_value_label.setToolTip(volume_tip)

    def _handle_scope_changed(self, index: int) -> None:
        self._scope = str(self._scope_combo.itemData(index))
        self.refresh_state()
        if self._on_scope_changed is not None:
            self._on_scope_changed(self._scope)

    def _handle_mode_changed(self, index: int) -> None:
        self._mode = str(self._mode_combo.itemData(index))
        self.refresh_state()
        if self._on_mode_changed is not None:
            self._on_mode_changed(self._mode)

    def _handle_volume_changed(self, value: int) -> None:
        self._volume = value
        self.refresh_state()
        if self._on_volume_changed is not None:
            mode = SpikeVolumePersistMode.DEBOUNCED if self._volume_slider.isSliderDown() else SpikeVolumePersistMode.IMMEDIATE
            self._on_volume_changed(value, mode)

    def _handle_volume_released(self) -> None:
        if self._on_volume_changed is not None:
            self._on_volume_changed(self._volume, SpikeVolumePersistMode.IMMEDIATE)
