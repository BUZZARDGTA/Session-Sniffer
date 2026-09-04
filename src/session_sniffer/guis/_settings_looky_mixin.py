"""Looky System UI mixin and verify worker for `SettingsDialog`."""

from typing import TYPE_CHECKING, cast, override

import pydantic
import requests
from PySide6.QtCore import QEvent, QObject, Qt, QTimer, Signal
from PySide6.QtGui import QGuiApplication, QKeySequence
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.standalone import LOOKY_BASE_HOST
from session_sniffer.guis._crashing_qthread import CrashingQThread
from session_sniffer.guis.sensitive_value_widget import SensitiveValueWidget
from session_sniffer.guis.stylesheets import (
    LOOKY_ACCOUNT_CARD_STYLESHEET,
    LOOKY_CARD_LABEL_STYLESHEET,
    LOOKY_CARD_VALUE_STYLESHEET,
    LOOKY_INFO_LABEL_STYLESHEET,
)
from session_sniffer.networking.looky_system import LookyState
from session_sniffer.networking.looky_system import verify_token as looky_verify_token

if TYPE_CHECKING:
    from PySide6.QtGui import QCloseEvent, QKeyEvent

    from session_sniffer.models.looky_system import LookyVerifyResponse


def _bool_badge(value: bool, true_text: str, false_text: str) -> str:  # noqa: FBT001
    """Return an HTML-coloured badge string: green for `True`, red for `False`."""
    if value:
        return f'<span style="color:#4ade80; font-size:10.5pt; font-weight:600;">✓ {true_text}</span>'
    return f'<span style="color:#f87171; font-size:10.5pt; font-weight:600;">✗ {false_text}</span>'


class _LookyVerifyWorker(CrashingQThread):
    """Background thread that verifies a Looky System API key via `/api/whoami`."""

    verified: Signal = Signal(object)  # LookyVerifyResponse
    failed: Signal = Signal(str)  # error message

    def __init__(self, api_key: str) -> None:
        super().__init__()
        self._api_key = api_key

    @override
    def _run(self) -> None:
        """Call `looky_verify_token` and emit the result or error signal."""
        try:
            result = looky_verify_token(self._api_key)
            self.verified.emit(result)
        except requests.HTTPError as e:
            status = e.response.status_code if e.response is not None else 'unknown'
            self.failed.emit(f'Invalid API key (HTTP {status}).')
        except requests.RequestException as e:
            self.failed.emit(f'Connection error: {e}')
        except pydantic.ValidationError as e:
            self.failed.emit(f'Unexpected response format: {e}')


class SettingsDialogLookyMixin(QDialog):
    """Looky System tab helpers — account info card, verify worker, and related slots.

    Expects these attributes on the concrete class (set in `__init__`):
        `_widgets`, `_last_verified_key`, `_verify_worker`, `_verify_debounce`
    """

    # -- Attribute stubs (Looky System widgets, set during _build_tab) --
    _looky_account_card: QFrame
    _looky_account_info_group: QGroupBox
    _looky_card_grid: QGridLayout
    _looky_verify_status_label: QLabel
    _looky_card_forms_container: QWidget
    _looky_account_sensitive_widgets: list[SensitiveValueWidget]

    # -- Attribute stubs (set in SettingsDialog.__init__) --
    _widgets: dict[str, QWidget]
    _last_verified_key: str
    _verify_worker: _LookyVerifyWorker | None
    _verify_debounce: QTimer

    def _build_looky_info_group(self) -> QGroupBox:
        """Build an informational banner for the Looky System API key setting."""
        group_box = QGroupBox('Looky System — GTA IP Lookup')
        layout = QVBoxLayout(group_box)

        info_label = QLabel(
            '<b>Looky System is a paid API for GTA Online PC username resolution.</b><br><br>'
            'To obtain an API key, purchase access through their official '
            '<a href="https://discord.gg/umZ4yXRVfE" title="https://discord.gg/umZ4yXRVfE" style="color: #a78bfa; text-decoration: underline;">Discord server</a> or visit '
            f'<a href="{LOOKY_BASE_HOST}" title="{LOOKY_BASE_HOST}" style="color: #a78bfa; text-decoration: underline;">{LOOKY_BASE_HOST}</a>.<br><br>'
            'Once you have your key, paste it in the <b>API Key</b> field below.<br><br>'
            'Player names will be resolved automatically in the background and shown in the <b>Usernames</b> column.<br><br>'
            '<i>Note: Looky System features are only active when the <b>Feature Set</b> under <b>Capture → General</b> is set to <b>GTA5</b>.</i>',
        )
        info_label.setWordWrap(True)
        info_label.setTextFormat(Qt.TextFormat.RichText)
        info_label.setOpenExternalLinks(True)
        info_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)
        info_label.setStyleSheet(LOOKY_INFO_LABEL_STYLESHEET)
        info_label.linkHovered.connect(info_label.setToolTip)
        layout.addWidget(info_label)

        return group_box

    def _build_looky_account_info_group(self) -> QGroupBox:
        """Build the Account Information panel for the Looky System tab."""
        self._looky_account_sensitive_widgets = []
        group_box = QGroupBox('Account Information')
        outer = QVBoxLayout(group_box)
        outer.setSpacing(8)

        self._looky_account_card = QFrame()
        self._looky_account_card.setObjectName('lookyAccountCard')
        self._looky_account_card.setStyleSheet(LOOKY_ACCOUNT_CARD_STYLESHEET)
        card_layout = QVBoxLayout(self._looky_account_card)
        card_layout.setContentsMargins(14, 10, 14, 10)
        card_layout.setSpacing(6)

        self._looky_verify_status_label = QLabel()
        self._looky_verify_status_label.setStyleSheet(LOOKY_CARD_LABEL_STYLESHEET)
        self._looky_verify_status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._looky_verify_status_label.setVisible(False)
        card_layout.addWidget(self._looky_verify_status_label)

        self._looky_card_forms_container = QWidget()
        self._looky_card_forms_container.setStyleSheet('background: transparent;')
        forms_row = QHBoxLayout(self._looky_card_forms_container)
        forms_row.setContentsMargins(0, 0, 0, 0)
        forms_row.setSpacing(0)

        self._looky_card_grid = QGridLayout()
        self._looky_card_grid.setHorizontalSpacing(16)
        self._looky_card_grid.setVerticalSpacing(10)
        self._looky_card_grid.setColumnMinimumWidth(2, 108)

        forms_row.addStretch(1)
        forms_row.addLayout(self._looky_card_grid)
        forms_row.addStretch(1)
        self._looky_card_forms_container.setVisible(False)
        card_layout.addWidget(self._looky_card_forms_container)

        outer.addWidget(self._looky_account_card)

        if LookyState.user_data is not None:
            self._populate_looky_account_card(LookyState.user_data)

        return group_box

    def _make_card_label(self, text: str) -> QLabel:
        """Return a right-aligned label styled for the account card."""
        lbl = QLabel(text + ':')
        lbl.setStyleSheet(LOOKY_CARD_LABEL_STYLESHEET)
        return lbl

    def _make_card_value(self, html: str) -> QLabel:
        """Return a value label with rich-text support for the account card."""
        lbl = QLabel(html)
        lbl.setTextFormat(Qt.TextFormat.RichText)
        lbl.setStyleSheet(LOOKY_CARD_VALUE_STYLESHEET)
        lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        return lbl

    def _populate_looky_account_card(self, data: LookyVerifyResponse) -> None:
        """Fill the account info card with `data` and make it visible."""
        # Clear previous items from grid
        while self._looky_card_grid.count() > 0:
            item = self._looky_card_grid.takeAt(0)
            if item is not None:
                widget = item.widget()
                if widget is not None:
                    widget.deleteLater()

        self._looky_account_sensitive_widgets.clear()
        username_widget = SensitiveValueWidget(data.userData.username)
        rid_widget = SensitiveValueWidget(str(data.userData.rid))
        self._looky_account_sensitive_widgets.extend([username_widget, rid_widget])

        # Row 0: Username & API Access (aligned on the exact same horizontal line)
        self._looky_card_grid.addWidget(
            self._make_card_label('Username'), 0, 0, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        )
        self._looky_card_grid.addWidget(
            username_widget, 0, 1, Qt.AlignmentFlag.AlignVCenter
        )
        self._looky_card_grid.addWidget(
            self._make_card_label('API Access'), 0, 3, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        )
        self._looky_card_grid.addWidget(
            self._make_card_value(_bool_badge(data.userData.apiAccess, 'Enabled', 'Disabled')),
            0,
            4,
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
        )

        # Row 1: Rockstar ID & Status (aligned on the exact same horizontal line)
        self._looky_card_grid.addWidget(
            self._make_card_label('Rockstar ID'), 1, 0, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        )
        self._looky_card_grid.addWidget(
            rid_widget, 1, 1, Qt.AlignmentFlag.AlignVCenter
        )
        self._looky_card_grid.addWidget(
            self._make_card_label('Status'), 1, 3, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        )
        self._looky_card_grid.addWidget(
            self._make_card_value(_bool_badge(data.userData.status, 'Active', 'Inactive')),
            1,
            4,
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
        )

        self._looky_card_forms_container.setVisible(True)

    def _hide_looky_account_sensitive_values(self) -> None:
        """Re-blur any revealed sensitive values in the account info card."""
        for widget in getattr(self, '_looky_account_sensitive_widgets', []):
            widget.set_revealed(revealed=False)

    def _on_looky_api_key_changed(self, text: str) -> None:
        """Show/hide Account Information and schedule a debounced verify when the key changes."""
        stripped = text.strip()
        self._looky_account_info_group.setVisible(bool(stripped))
        if not stripped or stripped == self._last_verified_key:
            self._verify_debounce.stop()
            return
        self._looky_verify_status_label.setText('⟳ Verifying...')
        self._looky_verify_status_label.setVisible(True)
        self._looky_card_forms_container.setVisible(False)
        self._verify_debounce.start(1500)

    def _trigger_looky_verify(self) -> None:
        """Start a background `/api/whoami` verify for the current API key value."""
        api_key_widget = self._widgets.get('looky_api_key')
        if not isinstance(api_key_widget, QLineEdit):
            return
        api_key = api_key_widget.text().strip()
        if not api_key:
            return
        if self._verify_worker is not None and self._verify_worker.isRunning():
            self._verify_worker.quit()
            self._verify_worker.wait()
        self._verify_worker = _LookyVerifyWorker(api_key)
        self._verify_worker.verified.connect(self._on_verify_success)
        self._verify_worker.failed.connect(self._on_verify_failed)
        self._verify_worker.start()

    def _on_verify_success(self, data: LookyVerifyResponse) -> None:
        """Handle a successful whoami response — populate the account card."""
        api_key_widget = self._widgets.get('looky_api_key')
        if isinstance(api_key_widget, QLineEdit):
            self._last_verified_key = api_key_widget.text().strip()
        self._looky_verify_status_label.setVisible(False)
        self._populate_looky_account_card(data)

    def _on_verify_failed(self, error: str) -> None:
        """Handle a failed whoami response — show the error in the status label."""
        self._last_verified_key = ''
        self._looky_verify_status_label.setText(f'✗ {error}')
        self._looky_verify_status_label.setVisible(True)
        self._looky_card_forms_container.setVisible(False)

    @override
    def closeEvent(self, event: QCloseEvent) -> None:
        """Wait for any in-flight verify worker before the dialog is destroyed."""
        super().closeEvent(event)
        if event and not event.isAccepted():
            return
        if self._verify_worker is not None and self._verify_worker.isRunning():
            self._verify_worker.quit()
            self._verify_worker.wait()

    @override
    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        """Detect Ctrl+V on the API key field and trigger immediate verification."""
        api_key_widget = self._widgets.get('looky_api_key')
        if watched is api_key_widget and event and event.type() == QEvent.Type.KeyPress and cast('QKeyEvent', event).matches(QKeySequence.StandardKey.Paste):
            clipboard = QGuiApplication.clipboard()
            clipboard_text = clipboard.text() if clipboard else ''
            if any(char.isspace() for char in clipboard_text.strip()):
                return True
            QTimer.singleShot(0, self._on_looky_api_key_pasted)
        return super().eventFilter(watched, event)

    def _on_looky_api_key_pasted(self) -> None:
        """Trigger immediate verification after the pasted text has been inserted."""
        api_key_widget = self._widgets.get('looky_api_key')
        if not isinstance(api_key_widget, QLineEdit):
            return
        stripped = api_key_widget.text().strip()
        if stripped and stripped != self._last_verified_key:
            self._verify_debounce.stop()
            self._trigger_looky_verify()
