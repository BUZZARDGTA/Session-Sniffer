"""Discord tab UI mixin for `SettingsDialog`."""

from functools import partial
from typing import TYPE_CHECKING, cast

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QDialog,
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
    create_standard_form_layout,
    format_setting_tooltip,
)
from session_sniffer.guis.secret_line_edit import SecretLineEdit
from session_sniffer.guis.stylesheets import (
    DIALOG_BUTTON_STYLESHEET,
    DIALOG_DANGER_BUTTON_STYLESHEET,
    WEBHOOK_NOTE_LABEL_STYLESHEET,
)
from session_sniffer.settings.settings import Settings

if TYPE_CHECKING:
    from collections.abc import Callable

    from PySide6.QtWidgets import QCheckBox, QFormLayout

    from session_sniffer.settings import SettingMeta


class SettingsDialogDiscordMixin(QDialog):
    """Discord tab helpers — server webhook group and related actions.

    Expects these attributes on the concrete class:
        `_widgets`
    """

    _widgets: dict[str, QWidget]

    def _build_discord_webhook_group(
        self,
        items: list[tuple[str, SettingMeta]],
        add_setting_row: Callable[[QFormLayout, str, SettingMeta], None],
    ) -> QGroupBox:
        """Build the custom Discord Webhook group with masked URL and enable cascade."""
        group_box = QGroupBox('Server Webhook')
        outer = QVBoxLayout(group_box)
        outer.setSpacing(8)

        meta_by_key = dict(items)

        # Top form: Enabled + Webhook URL row (with Show + Test buttons).
        top_form = create_standard_form_layout()

        # Enabled checkbox
        enabled_meta = meta_by_key.get('discord_webhook_enabled')
        if enabled_meta is not None:
            enabled_widget = create_boolean_widget(enabled_meta)
            self._widgets['discord_webhook_enabled'] = enabled_widget
            enabled_label = QLabel(enabled_meta.display_label + ':')
            enabled_tooltip = format_setting_tooltip(enabled_meta)
            if enabled_tooltip:
                enabled_label.setToolTip(enabled_tooltip)
            top_form.addRow(enabled_label, enabled_widget)

        # URL row: QLineEdit (masked) + 'Show' toggle + 'Test' button
        url_meta = meta_by_key.get('discord_webhook_url')
        url_line: QLineEdit | None = None
        if url_meta is not None:
            url_line = SecretLineEdit()
            url_line.setPlaceholderText('https://discord.com/api/webhooks/<id>/<token>')
            url_line.setToolTip(
                url_meta.tooltip or 'Discord channel webhook URL. Treat this like a password — anyone with it can post to the channel.',
            )
            self._widgets['discord_webhook_url'] = url_line

            url_row = QWidget()
            url_row_layout = QHBoxLayout(url_row)
            url_row_layout.setContentsMargins(0, 0, 0, 0)
            url_row_layout.setSpacing(6)
            url_row_layout.addWidget(url_line, 1)

            show_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'eye.svg')), ' Show')
            show_button.setCheckable(True)
            show_button.setToolTip('Reveal or hide the webhook URL')
            show_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
            show_button.toggled.connect(partial(self._toggle_url_visibility, url_line, show_button))
            url_row_layout.addWidget(show_button)

            test_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'settings.svg')), ' Test')
            test_button.setToolTip('Send a one-time test message to this webhook URL')
            test_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
            test_button.clicked.connect(partial(self._test_webhook, url_line))
            url_row_layout.addWidget(test_button)

            url_label = QLabel(url_meta.display_label + ':')
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

        outer.addWidget(details_widget)

        # Reset Stored Messages button (separate row, also gated on enabled).
        reset_messages_row = QHBoxLayout()
        reset_messages_row.addStretch()
        reset_messages_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'refresh.svg')), ' Reset Stored Messages')
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
            enabled_checkbox.toggled.connect(partial(self._on_webhook_enabled_toggled, details_widget, url_line))

        return group_box

    def _on_webhook_enabled_toggled(self, details_widget: QWidget, url_line: QLineEdit | None, checked: bool) -> None:  # noqa: FBT001
        """Enable/disable child webhook fields based on the master checkbox."""
        details_widget.setEnabled(checked)
        if url_line is not None:
            url_line.setEnabled(checked)

    def _toggle_url_visibility(self, url_line: QLineEdit, show_button: QPushButton, checked: bool) -> None:  # noqa: FBT001
        """Toggle masked/plain echo for the webhook URL."""
        if isinstance(url_line, SecretLineEdit):
            url_line.set_revealed(revealed=checked)
        else:
            url_line.setEchoMode(QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password)
        show_button.setText(' Hide' if checked else ' Show')
        show_button.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / ('eye_hide.svg' if checked else 'eye.svg'))))

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
