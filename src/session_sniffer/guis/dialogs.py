"""Dialog helpers and reusable dialog windows."""


from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QStyle,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.utils import (
    ActiveDialogRegistry,
    activate_window,
    animate_button_feedback,
    find_main_window,
    scale_by_ui,
    set_clipboard_text,
    set_dialog_window_flags,
)


def create_nonmodal_warning(parent: QWidget | None, text: str) -> QMessageBox:
    """Create a pre-configured non-modal warning QMessageBox without showing it."""
    dlg = QMessageBox(parent)
    dlg.setWindowModality(Qt.WindowModality.NonModal)
    dlg.setWindowTitle(TITLE)
    dlg.setText(text)
    dlg.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse | Qt.TextInteractionFlag.LinksAccessibleByMouse)
    dlg.setIcon(QMessageBox.Icon.Warning)
    dlg.setStandardButtons(QMessageBox.StandardButton.Ok)

    copy_button = dlg.addButton('Copy', QMessageBox.ButtonRole.ActionRole)
    copy_button.setCursor(Qt.CursorShape.PointingHandCursor)
    copy_button.clicked.disconnect()

    def _on_copy() -> None:
        copy_text = (dlg.detailedText() or dlg.text()).strip()
        if copy_text:
            set_clipboard_text(copy_text)
            animate_button_feedback(copy_button)

    copy_button.clicked.connect(_on_copy)

    return dlg


class DetailedMessageDialog(QDialog):
    """A non-modal dialog displaying a message with a standard icon."""

    def __init__(
        self,
        parent: QWidget | None,
        title: str,
        text: str,
        *,
        icon: QMessageBox.Icon = QMessageBox.Icon.Information,
    ) -> None:
        """Initialize the message dialog and construct its layout."""
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        set_dialog_window_flags(self)
        self.setMinimumWidth(scale_by_ui(520))

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(12)

        content_layout = QHBoxLayout()
        content_layout.setSpacing(12)

        standard_pixmap = self._get_standard_pixmap(icon)
        if standard_pixmap is not None:
            icon_label = QLabel()
            icon_size = scale_by_ui(32)
            icon_label.setPixmap(self.style().standardIcon(standard_pixmap).pixmap(icon_size, icon_size))
            icon_label.setAlignment(Qt.AlignmentFlag.AlignTop)
            content_layout.addWidget(icon_label)

        self._message_label = QLabel(text)
        self._message_label.setWordWrap(True)
        self._message_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        content_layout.addWidget(self._message_label, stretch=1)
        main_layout.addLayout(content_layout)

        button_layout = QHBoxLayout()
        button_layout.addStretch(1)

        ok_button = QPushButton('OK')
        ok_button.setDefault(True)
        ok_button.clicked.connect(self.accept)
        button_layout.addWidget(ok_button)

        main_layout.addLayout(button_layout)

        initial_height = self.heightForWidth(scale_by_ui(520)) if self.hasHeightForWidth() else self.sizeHint().height()
        self.resize(scale_by_ui(520), max(scale_by_ui(160), initial_height))

    @staticmethod
    def _get_standard_pixmap(icon: QMessageBox.Icon) -> QStyle.StandardPixmap | None:
        if icon == QMessageBox.Icon.Information:
            return QStyle.StandardPixmap.SP_MessageBoxInformation
        if icon == QMessageBox.Icon.Warning:
            return QStyle.StandardPixmap.SP_MessageBoxWarning
        if icon == QMessageBox.Icon.Critical:
            return QStyle.StandardPixmap.SP_MessageBoxCritical
        if icon == QMessageBox.Icon.Question:
            return QStyle.StandardPixmap.SP_MessageBoxQuestion
        return None

    def set_text(self, text: str) -> None:
        """Update the displayed message text."""
        self._message_label.setText(text)
        dialog_layout = self.layout()
        if dialog_layout is not None:
            dialog_layout.activate()


_active_ipapi_dialogs: ActiveDialogRegistry[str, DetailedMessageDialog] = ActiveDialogRegistry()


def show_ipapi_unavailable_dialog(reason: str) -> None:
    """Show or focus the singleton warning dialog indicating ip-api.com geolocation is unavailable."""
    text = (
        'IP geolocation via ip-api.com is currently unavailable.\n\n'
        f'{reason}\n\n'
        'Country, City, ISP, ASN and related ip-api.com fields will not be populated until the network connection '
        'to ip-api.com is restored (e.g. disconnecting a VPN or switching to an unblocked interface). Lookups will '
        'automatically resume once the connection is restored.'
    )
    existing = _active_ipapi_dialogs.get('ipapi_unavailable')
    if existing is not None:
        existing.set_text(text)
        activate_window(existing)
        return

    parent = find_main_window()
    _active_ipapi_dialogs.show_or_focus(
        'ipapi_unavailable',
        lambda: DetailedMessageDialog(parent, TITLE, text, icon=QMessageBox.Icon.Warning),
    )
