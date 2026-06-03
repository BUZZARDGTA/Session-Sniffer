"""Looky System UI mixin and verify worker for `SettingsDialog`."""

from typing import TYPE_CHECKING, cast, override

import pydantic
import requests
from PyQt6.QtCore import QEvent, QObject, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QGuiApplication, QKeySequence
from PyQt6.QtWidgets import (
    QDialog,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.standalone import LOOKY_BASE_HOST
from session_sniffer.guis._crashing_qthread import CrashingQThread
from session_sniffer.guis.stylesheets import (
    LOOKY_ACCOUNT_CARD_STYLESHEET,
    LOOKY_CARD_LABEL_STYLESHEET,
    LOOKY_CARD_VALUE_STYLESHEET,
    LOOKY_INFO_LABEL_STYLESHEET,
)
from session_sniffer.networking.looky_system import LookyState
from session_sniffer.networking.looky_system import verify_token as looky_verify_token

if TYPE_CHECKING:
    from PyQt6.QtGui import QKeyEvent

    from session_sniffer.models.looky_system import LookyVerifyResponse


def _bool_badge(value: bool, true_text: str, false_text: str) -> str:  # noqa: FBT001
    """Return an HTML-coloured badge string: green for `True`, red for `False`."""
    if value:
        return f'<span style="color:#4ade80; font-weight:600;">✓ {true_text}</span>'
    return f'<span style="color:#f87171; font-weight:600;">✗ {false_text}</span>'


class _LookyVerifyWorker(CrashingQThread):
    """Background thread that verifies a Looky System API key via `/api/whoami`."""

    verified: pyqtSignal = pyqtSignal(object)  # LookyVerifyResponse
    failed: pyqtSignal = pyqtSignal(str)        # error message

    def __init__(self, api_key: str) -> None:
        super().__init__()
        self._api_key = api_key

    @override
    def _run(self) -> None:
        """Call `looky_verify_token` and emit the result or error signal."""
        try:
            result = looky_verify_token(self._api_key)
            self.verified.emit(result)
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else 'unknown'
            self.failed.emit(f'Invalid API key (HTTP {status}).')
        except requests.RequestException as exc:
            self.failed.emit(f'Connection error: {exc}')
        except pydantic.ValidationError as exc:
            self.failed.emit(f'Unexpected response format: {exc}')


class SettingsDialogLookyMixin(QDialog):
    """Looky System tab helpers — account info card, verify worker, and related slots.

    Expects these attributes on the concrete class (set in `__init__`):
        `_widgets`, `_last_verified_key`, `_verify_worker`, `_verify_debounce`
    """

    # -- Attribute stubs (Looky System widgets, set during _build_tab) --
    _looky_account_card: QFrame
    _looky_account_info_group: QGroupBox
    _looky_card_form_left: QFormLayout
    _looky_card_form_right: QFormLayout
    _looky_verify_status_label: QLabel
    _looky_card_forms_container: QWidget

    # -- Attribute stubs (set in SettingsDialog.__init__) --
    _widgets: dict[str, QWidget]
    _last_verified_key: str
    _verify_worker: _LookyVerifyWorker | None
    _verify_debounce: QTimer

    def _build_looky_info_group(self) -> QGroupBox:
        """Build an informational banner for the Looky System API key setting."""
        group_box = QGroupBox('\U0001f6b9 Looky System — GTA IP Lookup')
        layout = QVBoxLayout(group_box)

        info_label = QLabel(
            '<b>Looky System is a paid API for GTA Online PC username resolution.</b><br><br>'
            'To obtain an API key, purchase access through their official '
            '<a href="https://discord.gg/XqggW7QpFg" title="https://discord.gg/XqggW7QpFg" style="color: #a78bfa; text-decoration: underline;">Discord server</a> or visit '
            f'<a href="{LOOKY_BASE_HOST}" title="{LOOKY_BASE_HOST}" style="color: #a78bfa; text-decoration: underline;">{LOOKY_BASE_HOST}</a>.<br><br>'
            'Once you have your key, paste it in the <b>Looky System API Key</b> field below.<br><br>'
            'Player names will be resolved automatically in the background and shown in the <b>Usernames</b> column.<br>',
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
        group_box = QGroupBox('Account Information')
        outer = QVBoxLayout(group_box)
        outer.setSpacing(8)

        self._looky_account_card = QFrame()
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
        forms_row = QHBoxLayout(self._looky_card_forms_container)
        forms_row.setContentsMargins(0, 0, 0, 0)
        forms_row.setSpacing(32)

        self._looky_card_form_left = QFormLayout()
        self._looky_card_form_left.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
        self._looky_card_form_left.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self._looky_card_form_left.setHorizontalSpacing(16)
        self._looky_card_form_left.setVerticalSpacing(6)

        self._looky_card_form_right = QFormLayout()
        self._looky_card_form_right.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
        self._looky_card_form_right.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self._looky_card_form_right.setHorizontalSpacing(16)
        self._looky_card_form_right.setVerticalSpacing(6)

        forms_row.addLayout(self._looky_card_form_left)
        forms_row.addLayout(self._looky_card_form_right)
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
        # Clear previous rows from both columns
        while self._looky_card_form_left.rowCount() > 0:
            self._looky_card_form_left.removeRow(0)
        while self._looky_card_form_right.rowCount() > 0:
            self._looky_card_form_right.removeRow(0)

        def add_left(label: str, html: str) -> None:
            self._looky_card_form_left.addRow(self._make_card_label(label), self._make_card_value(html))

        def add_right(label: str, html: str) -> None:
            self._looky_card_form_right.addRow(self._make_card_label(label), self._make_card_value(html))

        add_left('Username',    f'<b style="color:#b09fe0; font-size:10pt;">{data.userData.username}</b>')
        add_left('Rockstar ID', f'<b style="color:#b09fe0; font-size:10pt;">{data.userData.rid}</b>')
        add_right('API Access', _bool_badge(data.userData.apiAccess, 'Enabled', 'Disabled'))
        add_right('Status',     _bool_badge(data.userData.status, 'Active', 'Inactive'))

        self._looky_card_forms_container.setVisible(True)

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
    def eventFilter(self, a0: QObject | None, a1: QEvent | None) -> bool:
        """Detect Ctrl+V on the API key field and trigger immediate verification."""
        api_key_widget = self._widgets.get('looky_api_key')
        if a0 is api_key_widget and a1 is not None and a1.type() == QEvent.Type.KeyPress and cast('QKeyEvent', a1).matches(QKeySequence.StandardKey.Paste):
            clipboard = QGuiApplication.clipboard()
            clipboard_text = clipboard.text() if clipboard is not None else ''
            if any(c.isspace() for c in clipboard_text.strip()):
                return True
            QTimer.singleShot(0, self._on_looky_api_key_pasted)
        return super().eventFilter(a0, a1)

    def _on_looky_api_key_pasted(self) -> None:
        """Trigger immediate verification after the pasted text has been inserted."""
        api_key_widget = self._widgets.get('looky_api_key')
        if not isinstance(api_key_widget, QLineEdit):
            return
        stripped = api_key_widget.text().strip()
        if stripped and stripped != self._last_verified_key:
            self._verify_debounce.stop()
            self._trigger_looky_verify()
