"""Player High Rate Monitor & Spike Alerts UI mixin for `SettingsDialog`."""

from typing import cast

from PySide6.QtCore import QSignalBlocker, Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QSlider,
    QSpinBox,
    QWidget,
)

from session_sniffer.background.voice_notifications import play_spike_sound
from session_sniffer.guis._settings_widget_builders import combo_canonical_value, format_setting_tooltip
from session_sniffer.guis._spike_sound_controls import refresh_spike_preview_button
from session_sniffer.guis.stylesheets import COMPACT_BUTTON_STYLESHEET
from session_sniffer.guis.theming import themed_text_qcolor
from session_sniffer.guis.utils import render_svg_icon_from_resource
from session_sniffer.i18n import tr
from session_sniffer.settings import SETTING_METADATA


class SettingsDialogHighRateMonitorMixin(QDialog):
    """Player High Rate Monitor and Spike Alerts helpers for `SettingsDialog`.

    Expects these attributes on the concrete class:
        `_widgets`, `_labels`, `_spike_sound_preview_button`, `_spike_sound_volume_slider`
    """

    _widgets: dict[str, QWidget]
    _labels: dict[str, QLabel]
    _spike_sound_preview_button: QPushButton | None
    _spike_sound_volume_slider: QSlider | None

    def _on_high_rate_monitor_mode_changed(self, mode: str) -> None:
        """Enable or disable manual threshold inputs based on whether High Rate Monitor is in Smart or Manual mode."""
        is_manual = mode == 'Manual'
        for setting_key in ('high_rate_monitor_pps_threshold', 'high_rate_monitor_bps_threshold'):
            label = self._labels.get(setting_key)
            widget = self._widgets.get(setting_key)
            meta = SETTING_METADATA.get(setting_key)
            if label is not None:
                label.setEnabled(is_manual)
            if widget is not None:
                widget.setEnabled(is_manual)
            if meta is not None:
                tooltip = format_setting_tooltip(meta) or ''
                if not is_manual:
                    disabled_note = tr('Disabled in Smart mode (packet rate thresholds are calculated dynamically from the session average).')
                    tooltip = f'{tooltip}\n\n{disabled_note}' if tooltip else disabled_note
                if label is not None:
                    label.setToolTip(tooltip)
                if widget is not None:
                    widget.setToolTip(tooltip)

    def _on_spike_sound_preview_clicked(self) -> None:
        """Play a preview of the currently selected preset at the dialog's current volume without mutating Settings."""
        preset_widget = self._widgets.get('high_rate_monitor_spike_sound_preset')
        volume_widget = self._widgets.get('high_rate_monitor_spike_sound_volume')
        preset = combo_canonical_value(preset_widget) if isinstance(preset_widget, QComboBox) else 'Ding'
        volume = volume_widget.value() if isinstance(volume_widget, QSpinBox) else 100
        play_spike_sound(preset, volume=volume, bypass_cooldown=True)

    def _build_spike_sound_preset_row(self, combo_widget: QWidget) -> QWidget:
        """Build a composite row pairing the Spike Sound Preset combo box with an instant Preview button."""
        row = QWidget()
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.setSpacing(6)
        combo_widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        row_layout.addWidget(combo_widget, 1)

        preview_btn = QPushButton(tr('Preview'))
        tint_hex = themed_text_qcolor('@text[#e5e7eb]', '@surface[#1f2937]').name()
        preview_btn.setIcon(render_svg_icon_from_resource('volume-2.svg', 14, 14, tint_hex))
        preview_btn.setStyleSheet(COMPACT_BUTTON_STYLESHEET)
        preview_btn.setToolTip(tr('Play a preview of the selected spike sound preset.'))
        preview_btn.clicked.connect(self._on_spike_sound_preview_clicked)
        row_layout.addWidget(preview_btn)
        self._spike_sound_preview_button = preview_btn
        return row

    def _build_spike_sound_volume_row(self, spin_widget: QWidget) -> QWidget:
        """Build a composite row pairing a horizontal volume slider with the percentage spinbox."""
        row = QWidget()
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.setSpacing(8)

        spin_box = cast('QSpinBox', spin_widget)
        slider = QSlider(Qt.Orientation.Horizontal)
        slider.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        slider.setRange(spin_box.minimum(), spin_box.maximum())
        slider.setSingleStep(1)
        slider.setPageStep(5)
        slider.setValue(spin_box.value())
        slider.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        def _sync_spin_from_slider(value: int) -> None:
            if spin_box.value() != value:
                spin_box.setValue(value)

        def _sync_slider_from_spin(value: int) -> None:
            if slider.value() != value:
                with QSignalBlocker(slider):
                    slider.setValue(value)

        slider.valueChanged.connect(_sync_spin_from_slider)
        spin_box.valueChanged.connect(_sync_slider_from_spin)

        row_layout.addWidget(slider, 1)
        row_layout.addWidget(spin_widget)
        self._spike_sound_volume_slider = slider
        return row

    def _update_spike_alerts_state(self) -> None:
        """Enable or disable dependent Spike Alert controls and refresh their contextual tooltips."""
        scope_widget = self._widgets.get('high_rate_monitor_spike_sound_scope')
        mode_widget = self._widgets.get('high_rate_monitor_spike_sound_mode')
        volume_widget = self._widgets.get('high_rate_monitor_spike_sound_volume')
        visual_widget = self._widgets.get('high_rate_monitor_spike_visual_alert')

        scope = combo_canonical_value(scope_widget) if isinstance(scope_widget, QComboBox) else 'Open Graphs'
        mode = combo_canonical_value(mode_widget) if isinstance(mode_widget, QComboBox) else 'Repeating'
        dialog_volume = volume_widget.value() if isinstance(volume_widget, QSpinBox) else 100
        visual_enabled = not isinstance(visual_widget, QCheckBox) or visual_widget.isChecked()

        sound_active = scope != 'Disabled'
        repeats_active = sound_active and mode in ('Repeating', 'Repeating + End', 'Adaptive Geiger')
        trigger_active = sound_active or visual_enabled

        scope_disabled_note = tr('Disabled when Spike Sound Scope is set to Disabled.')
        repeat_disabled_note = tr('Only applies when Spike Sound Behavior repeats while spiking (Repeating, Repeating + End, or Adaptive Geiger).')
        trigger_disabled_note = tr('Disabled when both Spike Sound Scope and Spike Visual Highlight are disabled.')

        dependent_rules: tuple[tuple[str, bool, str], ...] = (
            ('high_rate_monitor_spike_sound_mode', sound_active, scope_disabled_note),
            ('high_rate_monitor_spike_sound_preset', sound_active, scope_disabled_note),
            ('high_rate_monitor_spike_sound_volume', sound_active, scope_disabled_note),
            ('high_rate_monitor_spike_repeat_interval', repeats_active, scope_disabled_note if not sound_active else repeat_disabled_note),
            ('high_rate_monitor_spike_trigger_metric', trigger_active, trigger_disabled_note),
        )
        for setting_key, is_enabled, disabled_note in dependent_rules:
            label = self._labels.get(setting_key)
            widget = self._widgets.get(setting_key)
            meta = SETTING_METADATA.get(setting_key)
            if label is not None:
                label.setEnabled(is_enabled)
            if widget is not None:
                widget.setEnabled(is_enabled)
            if meta is not None:
                tooltip = format_setting_tooltip(meta) or ''
                if not is_enabled:
                    tooltip = f'{tooltip}\n\n{disabled_note}' if tooltip else disabled_note
                if label is not None:
                    label.setToolTip(tooltip)
                if widget is not None:
                    widget.setToolTip(tooltip)

        if self._spike_sound_volume_slider is not None:
            self._spike_sound_volume_slider.setEnabled(sound_active)
            if volume_widget is not None:
                self._spike_sound_volume_slider.setToolTip(volume_widget.toolTip())

        if self._spike_sound_preview_button is not None:
            self._spike_sound_preview_button.setText(tr('Preview'))
            refresh_spike_preview_button(
                self._spike_sound_preview_button,
                sound_active=sound_active,
                volume=dialog_volume,
                scope_disabled_note=scope_disabled_note,
            )

    def _update_high_rate_monitor_mode_state(self) -> None:
        """Update enabled state of High Rate Monitor threshold and Spike Alert fields."""
        hrm_mode_widget = self._widgets.get('high_rate_monitor_mode')
        if isinstance(hrm_mode_widget, QComboBox):
            self._on_high_rate_monitor_mode_changed(combo_canonical_value(hrm_mode_widget))
        self._update_spike_alerts_state()
