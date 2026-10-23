"""Discord tab UI mixin for `SettingsDialog`."""

from functools import partial
from typing import TYPE_CHECKING, cast

from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.discord.webhook import send_test_message
from session_sniffer.guis._settings_widget_builders import (
    create_boolean_widget,
    create_setting_label,
    create_standard_form_layout,
    create_text_widget,
    format_setting_tooltip,
)
from session_sniffer.guis.stylesheets import (
    DIALOG_DANGER_BUTTON_STYLESHEET,
    WEBHOOK_NOTE_LABEL_STYLESHEET,
)
from session_sniffer.settings.settings import Settings

if TYPE_CHECKING:
    from collections.abc import Callable

    from PySide6.QtWidgets import QCheckBox

    from session_sniffer.settings import SettingMeta


class SettingsDialogDiscordMixin(QDialog):
    """Discord tab helpers — server webhook group and related actions.

    Expects these attributes on the concrete class:
        `_widgets`
    """

    _widgets: dict[str, QWidget]
    _old_values: dict[str, bool | str | int | float | tuple[str, ...] | None]

    def _build_discord_webhook_group(
        self,
        items: list[tuple[str, SettingMeta]],
        add_setting_row: Callable[[QFormLayout, str, SettingMeta], None],
    ) -> QGroupBox:
        """Build the custom Discord Webhook group with masked URL and enable cascade."""
        group_box = QGroupBox('Webhook')
        outer = QVBoxLayout(group_box)
        outer.setSpacing(8)

        meta_by_key = dict(items)

        # Top form: Enabled + Webhook URL row.
        top_form = create_standard_form_layout()

        # Enabled checkbox
        enabled_meta = meta_by_key.get('discord_webhook_enabled')
        if enabled_meta is not None:
            enabled_widget = create_boolean_widget(enabled_meta)
            self._widgets['discord_webhook_enabled'] = enabled_widget
            enabled_label = QLabel(enabled_meta.display_label + ':')
            enabled_tooltip = format_setting_tooltip(enabled_meta)
            if enabled_tooltip is not None and enabled_tooltip:
                enabled_label.setToolTip(enabled_tooltip)
            top_form.addRow(enabled_label, enabled_widget)

        # Use the standard text-field widget directly in the form row so its label
        # aligns the same way as other settings, such as Presence Title.
        url_meta = meta_by_key.get('discord_webhook_url')
        url_line: QLineEdit | None = None
        test_button: QPushButton | None = None
        if url_meta is not None:
            url_line = create_text_widget(url_meta)
            url_line.setPlaceholderText('https://discord.com/api/webhooks/<id>/<token>')
            self._widgets['discord_webhook_url'] = url_line

            url_row = QWidget()
            url_row_layout = QHBoxLayout(url_row)
            url_row_layout.setContentsMargins(0, 0, 0, 0)
            url_row_layout.setSpacing(6)
            url_row_layout.addWidget(url_line, 1)

            test_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'settings.svg')), ' Test')
            test_button.setFixedHeight(url_line.sizeHint().height())
            test_button.setToolTip('Send a one-time test message to this webhook URL')
            test_button.clicked.connect(partial(self._test_webhook, url_line))
            url_row_layout.addWidget(test_button)

            url_label = create_setting_label(url_meta)
            url_label.setToolTip(url_line.toolTip())
            top_form.addRow(url_label, url_row)

        outer.addLayout(top_form)

        # Remaining settings (refresh interval, include flags, max rows) in a
        # separate form so we can disable them all when 'Enabled' is unchecked.
        details_widget = QWidget()
        details_form = create_standard_form_layout(details_widget)
        details_form.setContentsMargins(0, 0, 0, 0)

        for key, meta in items:
            if key in ('discord_webhook_enabled', 'discord_webhook_url'):
                continue
            add_setting_row(details_form, key, meta)

        form_labels: list[QLabel] = []
        for form in (top_form, details_form):
            for row in range(form.rowCount()):
                label_item = form.itemAt(row, QFormLayout.ItemRole.LabelRole)
                label = label_item.widget() if label_item is not None else None
                if isinstance(label, QLabel):
                    form_labels.append(label)
        if form_labels:
            label_width = max(label.sizeHint().width() for label in form_labels)
            for label in form_labels:
                label.setMinimumWidth(label_width)
                label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        outer.addWidget(details_widget)

        # Reset Stored Messages button (separate row, also gated on enabled).
        reset_messages_row = QHBoxLayout()
        reset_messages_row.addStretch()
        reset_messages_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'refresh-cw.svg')), ' Reset Stored Messages')
        reset_messages_button.setToolTip(
            'Forget the IDs of the two posted messages so the next refresh creates fresh ones.\n'
            'Use this after changing channels or after Wick/automod deletes the old messages.',
        )
        reset_messages_button.setStyleSheet(DIALOG_DANGER_BUTTON_STYLESHEET)
        reset_messages_button.clicked.connect(self._reset_stored_messages)
        reset_messages_row.addWidget(reset_messages_button)
        outer.addLayout(reset_messages_row)

        # Footer note about automod / Wick.
        note = QLabel(
            'If your server runs Wick or another automod with a "wall of text" filter, '
            'whitelist this webhook (or its channel) to prevent the messages — and the webhook itself — from being deleted.',
        )
        note.setWordWrap(True)
        note.setStyleSheet(WEBHOOK_NOTE_LABEL_STYLESHEET)
        outer.addWidget(note)

        # Wire enable cascade.
        if enabled_meta is not None:
            enabled_checkbox = cast('QCheckBox', self._widgets['discord_webhook_enabled'])

            def _on_enable_toggled() -> None:
                self._on_webhook_enabled_toggled(
                    details_widget,
                    url_line,
                    test_button,
                    reset_messages_button,
                )

            enabled_checkbox.toggled.connect(_on_enable_toggled)

        return group_box

    def _on_webhook_enabled_toggled(
        self,
        details_widget: QWidget,
        url_line: QLineEdit | None,
        test_button: QPushButton | None = None,
        reset_messages_button: QPushButton | None = None,
    ) -> None:
        """Enable/disable child webhook fields based on the master checkbox."""
        enabled_checkbox = cast('QCheckBox', self._widgets['discord_webhook_enabled'])
        checked = enabled_checkbox.isChecked()
        details_widget.setEnabled(checked)
        if url_line is not None:
            url_line.setEnabled(checked)
        if test_button is not None:
            test_button.setEnabled(checked)
        if reset_messages_button is not None:
            reset_messages_button.setEnabled(checked)

    def _reset_stored_messages(self) -> None:
        """Clear persisted Discord webhook message IDs so the next post creates new messages."""
        if Settings.discord_webhook_message_ids in (None, ''):
            QMessageBox.information(self, TITLE, 'No stored Discord messages to reset.')
            return
        confirm = QMessageBox.question(
            self,
            TITLE,
            'Forget the IDs of the two posted Discord messages?\n\nThe next refresh will create two fresh messages instead of editing the old ones.',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return
        Settings.discord_webhook_message_ids = None
        self._old_values['discord_webhook_message_ids'] = None
        Settings.rewrite_settings_file()
        QMessageBox.information(self, TITLE, 'Stored Discord message IDs cleared.')

    def _test_webhook(self, url_widget: QLineEdit) -> None:
        """Send a test message to the URL currently in the URL widget."""
        url = url_widget.text().strip()
        if not url:
            QMessageBox.warning(self, TITLE, 'Please enter a Discord webhook URL first.')
            return
        success, message = send_test_message(url)
        if success:
            QMessageBox.information(self, TITLE, message)
        else:
            QMessageBox.critical(self, TITLE, message)
