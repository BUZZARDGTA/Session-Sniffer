"""Categorized 20-token Color Palette editor and preset-reset menus for `ThemeManagerDialog`."""

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from PySide6.QtCore import QPoint, QRegularExpression, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPen, QPixmap, QRegularExpressionValidator
from PySide6.QtWidgets import (
    QColorDialog,
    QDialog,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.guis._theme_preview_card import create_theme_list_icon
from session_sniffer.guis.live_language import register_language_refresh, set_i18n_colon_label
from session_sniffer.guis.stylesheets import SVG_ICON_CONTEXT_MENU_STYLESHEET
from session_sniffer.guis.theming import (
    BUILTIN_THEMES,
    THEME_COLOR_TOKENS,
    THEME_TOKEN_CATEGORIES,
    ThemeColors,
    ThemeColorToken,
    themed_qss,
)
from session_sniffer.guis.utils import scale_by_ui
from session_sniffer.i18n import tr

if TYPE_CHECKING:
    from collections.abc import Callable

    from PySide6.QtGui import QAction

_COLUMNS_PER_CATEGORY: Final = 3
_CATEGORY_LABEL_QSS: Final = themed_qss('color: @accent; font-size: 8.5pt; font-weight: 700; background: transparent;')
_CATEGORY_RULE_QSS: Final = themed_qss('background-color: @border/60; border: none; min-height: 1px; max-height: 1px;')
_PALETTE_SCROLL_QSS: Final = themed_qss('QScrollArea#themePaletteScroll { border: none; background: transparent; }')


@dataclass(frozen=True, slots=True)
class PaletteEditorCallbacks:
    """Callbacks invoked by token swatch buttons, hex fields, and preset-reset context menus."""

    pick_token_color: Callable[[str, str], None]
    preview_token_hex_edit: Callable[[str, str], None]
    on_hex_return_pressed: Callable[[str, QLineEdit], None]
    commit_token_hex_edit: Callable[[str], None]
    apply_token_color: Callable[[str, str], None]
    is_editable: Callable[[], bool]


@dataclass(frozen=True, slots=True)
class PaletteGridControls:
    """Constructed `Color Palette` group box and per-token widget lookup maps."""

    group_box: QGroupBox
    swatch_buttons: dict[str, QPushButton]
    hex_edits: dict[str, QLineEdit]


def _create_single_color_icon(hex_color: str) -> QIcon:
    size = scale_by_ui(14)
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, on=True)
    painter.setPen(QPen(QColor('#6e7681'), 1))
    painter.setBrush(QColor(hex_color))
    painter.drawRoundedRect(1, 1, size - 2, size - 2, 3, 3)
    painter.end()
    return QIcon(pixmap)


def _show_token_preset_menu(parent: QWidget, global_pos: QPoint, token: ThemeColorToken, callbacks: PaletteEditorCallbacks) -> None:
    if not callbacks.is_editable():
        return
    menu = QMenu(parent)
    menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)
    actions_to_hex: dict[QAction, str] = {}
    for preset in BUILTIN_THEMES:
        preset_hex = str(getattr(preset.colors, token.name))
        action = menu.addAction(
            _create_single_color_icon(preset_hex),
            tr('Reset "{token}" to {preset} ({color})', token=tr(token.label), preset=preset.name, color=preset_hex),
        )
        actions_to_hex[action] = preset_hex

    chosen = menu.exec(global_pos)
    if chosen in actions_to_hex:
        callbacks.apply_token_color(token.name, actions_to_hex[chosen])


def show_full_palette_preset_menu(parent: QWidget, anchor_button: QPushButton, apply_preset: Callable[[ThemeColors], None]) -> None:
    """Open a popup menu under *anchor_button* to reset all 20 tokens to any built-in theme preset."""
    menu = QMenu(parent)
    menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)
    actions_to_colors: dict[QAction, ThemeColors] = {
        menu.addAction(create_theme_list_icon(preset.colors), tr('Copy All Colors from {preset}', preset=preset.name)): preset.colors
        for preset in BUILTIN_THEMES
    }
    chosen = menu.exec(anchor_button.mapToGlobal(anchor_button.rect().bottomLeft()))
    if chosen in actions_to_colors:
        apply_preset(actions_to_colors[chosen])


def pick_color_with_live_preview(
    parent: QWidget,
    initial_hex: str,
    title: str,
    on_live_color: Callable[[str], None],
) -> str | None:
    """Open a non-native `QColorDialog` streaming `#rrggbb` changes live; return accepted hex or `None`."""
    color_dialog = QColorDialog(QColor(initial_hex), parent)
    color_dialog.setWindowTitle(title)
    color_dialog.setOption(QColorDialog.ColorDialogOption.DontUseNativeDialog, on=True)

    def _on_changed(color: QColor) -> None:
        if color.isValid():
            on_live_color(color.name(QColor.NameFormat.HexRgb).lower())

    color_dialog.currentColorChanged.connect(_on_changed)
    if color_dialog.exec() == QDialog.DialogCode.Accepted and color_dialog.selectedColor().isValid():
        return color_dialog.selectedColor().name(QColor.NameFormat.HexRgb).lower()
    return None


def _build_category_header(title: str) -> QWidget:
    header = QWidget()
    row = QHBoxLayout(header)
    row.setContentsMargins(0, 2, 0, 1)
    row.setSpacing(8)
    label = QLabel(tr(title))
    label.setStyleSheet(_CATEGORY_LABEL_QSS)
    line = QFrame()
    line.setFrameShape(QFrame.Shape.HLine)
    line.setStyleSheet(_CATEGORY_RULE_QSS)
    row.addWidget(label, 0)
    row.addWidget(line, 1, Qt.AlignmentFlag.AlignVCenter)
    return header


def _attach_token_context_menu(widget: QWidget, parent: QWidget, token: ThemeColorToken, callbacks: PaletteEditorCallbacks) -> None:
    widget.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)

    def _on_context_menu(pos: QPoint) -> None:
        _show_token_preset_menu(parent, widget.mapToGlobal(pos), token, callbacks)

    widget.customContextMenuRequested.connect(_on_context_menu)


def _build_token_cell(
    parent: QWidget,
    token: ThemeColorToken,
    hex_validator: QRegularExpressionValidator,
    callbacks: PaletteEditorCallbacks,
) -> tuple[QLabel, QWidget, QPushButton, QLineEdit]:
    label = QLabel()
    set_i18n_colon_label(label, token.label)
    label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
    _attach_token_context_menu(label, parent, token, callbacks)

    field_container = QWidget()
    field_row = QHBoxLayout(field_container)
    field_row.setContentsMargins(0, 0, 0, 0)
    field_row.setSpacing(5)

    swatch_button = QPushButton()
    swatch_button.setFixedSize(scale_by_ui(28), scale_by_ui(22))
    swatch_button.setCursor(Qt.CursorShape.PointingHandCursor)
    swatch_button.setAutoDefault(False)

    def _on_swatch_clicked() -> None:
        callbacks.pick_token_color(token.name, token.label)

    swatch_button.clicked.connect(_on_swatch_clicked)
    _attach_token_context_menu(swatch_button, parent, token, callbacks)

    hex_edit = QLineEdit()
    hex_edit.setMaxLength(7)
    hex_edit.setValidator(hex_validator)
    hex_edit.setFixedWidth(scale_by_ui(78))
    hex_edit.setPlaceholderText('#rrggbb')

    def _apply_tooltips() -> None:
        header = f'{tr(token.label)} (@{token.name})'
        reset_hint = tr('Right-click to reset "{token}" from a built-in preset.', token=tr(token.label))
        rich_tip = f'{header}\n{tr(token.description)}\n{reset_hint}'
        label.setToolTip(rich_tip)
        hex_edit.setToolTip(rich_tip)
        swatch_button.setToolTip(f"{header}\n{tr(token.description)}\n{tr('Click to pick a color • Right-click to reset from a built-in preset.')}")

    _apply_tooltips()
    register_language_refresh(label, _apply_tooltips)

    def _on_text_edited(text: str) -> None:
        callbacks.preview_token_hex_edit(token.name, text)

    def _on_return_pressed() -> None:
        callbacks.on_hex_return_pressed(token.name, hex_edit)

    def _on_editing_finished() -> None:
        callbacks.commit_token_hex_edit(token.name)

    hex_edit.textEdited.connect(_on_text_edited)
    hex_edit.returnPressed.connect(_on_return_pressed)
    hex_edit.editingFinished.connect(_on_editing_finished)
    _attach_token_context_menu(hex_edit, parent, token, callbacks)

    field_row.addWidget(swatch_button)
    field_row.addWidget(hex_edit)
    field_row.addStretch()
    return label, field_container, swatch_button, hex_edit


def build_palette_group(parent: QWidget, callbacks: PaletteEditorCallbacks) -> PaletteGridControls:
    """Build the scrollable, categorized 20-token `Color Palette` group box."""
    palette_group = QGroupBox(tr('Color Palette'))
    outer_layout = QVBoxLayout(palette_group)
    outer_layout.setContentsMargins(8, 8, 8, 8)
    outer_layout.setSpacing(0)

    scroll = QScrollArea()
    scroll.setObjectName('themePaletteScroll')
    scroll.setWidgetResizable(True)
    scroll.setFrameShape(QFrame.Shape.NoFrame)
    scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
    scroll.setStyleSheet(_PALETTE_SCROLL_QSS)

    content = QWidget()
    content_layout = QVBoxLayout(content)
    content_layout.setContentsMargins(2, 0, 6, 2)
    content_layout.setSpacing(6)

    hex_validator = QRegularExpressionValidator(QRegularExpression(r'#?[0-9A-Fa-f]{0,6}'), parent)
    swatch_buttons: dict[str, QPushButton] = {}
    hex_edits: dict[str, QLineEdit] = {}

    tokens_by_category: dict[str, list[ThemeColorToken]] = {category: [] for category in THEME_TOKEN_CATEGORIES}
    for token in THEME_COLOR_TOKENS:
        tokens_by_category[token.category].append(token)

    for category in THEME_TOKEN_CATEGORIES:
        category_tokens = tokens_by_category[category]
        if not category_tokens:
            continue
        content_layout.addWidget(_build_category_header(category))

        grid = QGridLayout()
        grid.setContentsMargins(0, 0, 0, 2)
        grid.setHorizontalSpacing(8)
        grid.setVerticalSpacing(5)
        for col_idx in range(_COLUMNS_PER_CATEGORY):
            grid.setColumnStretch(col_idx * 3 + 1, 1)
            if col_idx < _COLUMNS_PER_CATEGORY - 1:
                grid.setColumnMinimumWidth(col_idx * 3 + 2, scale_by_ui(8))

        for idx, token in enumerate(category_tokens):
            row, col_group = divmod(idx, _COLUMNS_PER_CATEGORY)
            base_col = col_group * 3
            label, field_container, swatch_button, hex_edit = _build_token_cell(parent, token, hex_validator, callbacks)
            grid.addWidget(label, row, base_col)
            grid.addWidget(field_container, row, base_col + 1)
            swatch_buttons[token.name] = swatch_button
            hex_edits[token.name] = hex_edit

        content_layout.addLayout(grid)

    content_layout.addStretch()
    scroll.setWidget(content)
    outer_layout.addWidget(scroll)
    return PaletteGridControls(group_box=palette_group, swatch_buttons=swatch_buttons, hex_edits=hex_edits)
