"""Custom item delegates for table and tree views."""

import html
from typing import TYPE_CHECKING, cast, override

from PySide6.QtCore import QEvent, QModelIndex, QPersistentModelIndex, QPointF, QRect, QSize, Qt
from PySide6.QtGui import (
    QBrush,
    QColor,
    QFontMetrics,
    QHelpEvent,
    QIcon,
    QLinearGradient,
    QPainter,
    QPalette,
    QPixmap,
    QTextCharFormat,
    QTextLayout,
    QTextOption,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QStyle,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QToolTip,
    QWidget,
)

from session_sniffer.constants.local import USERIP_DATABASES_DIR_PATH
from session_sniffer.guis.colors import TableColors
from session_sniffer.models.userip_settings_model import format_iso_timestamp_display
from session_sniffer.text_utils import pluralize, split_usernames

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from PySide6.QtGui import QFont

    from session_sniffer.models.player import Player
    from session_sniffer.player.userip import UserIP

_STANDARD_ICON_SIZE = 16
_DISCONNECTED_TEXT_COLOR = QColor(TableColors.DISCONNECTED_TEXT)

_COLOR_WHITE = QColor('#ffffff')
_COLOR_CONNECTED_SEL_TOP = QColor(42, 110, 85, 160)
_COLOR_CONNECTED_SEL_BOTTOM = QColor(28, 75, 58, 160)
_COLOR_CONNECTED_UNSEL_TOP = QColor(42, 110, 85, 100)
_COLOR_CONNECTED_UNSEL_BOTTOM = QColor(28, 75, 58, 100)
_COLOR_DISCONNECTED_SEL_TOP = QColor(130, 45, 45, 160)
_COLOR_DISCONNECTED_SEL_BOTTOM = QColor(85, 28, 28, 160)
_COLOR_DISCONNECTED_UNSEL_TOP = QColor(130, 45, 45, 100)
_COLOR_DISCONNECTED_UNSEL_BOTTOM = QColor(85, 28, 28, 100)
_COLOR_DEFAULT_SEL = QColor('#2f4f64')
_COLOR_DEFAULT_UNSEL = QColor('#2d2d30')
_LOOKY_TEXT_COLOR = QColor(TableColors.LOOKY_TEXT)
_DISCONNECTED_LOOKY_TEXT_COLOR = QColor(TableColors.DISCONNECTED_LOOKY_TEXT)
_SEARCH_HIGHLIGHT_BG_COLOR = QColor('#e3b341')
_SEARCH_HIGHLIGHT_FG_COLOR = QColor('#000000')


def _get_option_rect(option: QStyleOptionViewItem) -> QRect:
    """Return the cell rectangle from a style option."""
    return cast('QRect', object.__getattribute__(option, 'rect'))


def _get_option_font(option: QStyleOptionViewItem) -> QFont:
    """Return the font from a style option."""
    return cast('QFont', object.__getattribute__(option, 'font'))


def _is_disconnected_cell(view: object, index: QModelIndex | QPersistentModelIndex) -> bool:
    """Return True if the cell belongs to a disconnected table or has disconnected styling."""
    raw_is_connected = getattr(view, 'is_connected_table', None)
    if isinstance(raw_is_connected, bool):
        return not raw_is_connected
    foreground_brush = index.data(Qt.ItemDataRole.ForegroundRole)
    resolved_foreground_color = (
        foreground_brush if isinstance(foreground_brush, QColor) else (foreground_brush.color() if isinstance(foreground_brush, QBrush) else None)
    )
    return resolved_foreground_color is not None and resolved_foreground_color == _DISCONNECTED_TEXT_COLOR


def _strip_usernames_note_suffix(text: str, model: object, row: int) -> str:
    """Return `text` with any appended UserIP ` (notes)` suffix removed."""
    get_player = getattr(model, 'get_player_for_row', None)
    if callable(get_player):
        player = cast('Player | None', get_player(row))
        if player is not None and player.userip is not None and player.userip.notes:
            suffix = f' ({", ".join(player.userip.notes)})'
            if text.endswith(suffix):
                return text[: -len(suffix)]
    return text


def _format_looky_tooltip_html(text: str, looky_names: set[str], *, is_disconnected: bool) -> str:
    """Format elided username text for tooltip with HTML highlighting for Looky-resolved usernames."""
    looky_casefolded = {name.casefold() for name in looky_names}
    looky_color_hex = TableColors.DISCONNECTED_LOOKY_TEXT if is_disconnected else TableColors.LOOKY_TEXT
    formatted_tokens: list[str] = []
    for token in split_usernames(text):
        escaped_token = html.escape(token)
        if token.casefold() in looky_casefolded:
            formatted_tokens.append(f'<span style="color: {looky_color_hex};">{escaped_token}</span>')
        else:
            formatted_tokens.append(escaped_token)
    return f'<span>{", ".join(formatted_tokens)}</span>'


def _format_username_source_lines(
    player: Player,
    *,
    looky_names: set[str] | None = None,
    is_disconnected: bool = False,
) -> list[str]:
    """Format deduplicated per-source username HTML lines for a player tooltip."""
    lines: list[str] = []
    seen_casefolded: set[str] = set()

    def _append_source_line(label_prefix: str, raw_names: Sequence[str]) -> None:
        unique_names: list[str] = []
        for raw_name in raw_names:
            cleaned = raw_name.strip()
            if not cleaned:
                continue
            folded = cleaned.casefold()
            if folded not in seen_casefolded:
                seen_casefolded.add(folded)
                unique_names.append(cleaned)
        if not unique_names:
            return
        label = f'{label_prefix}{pluralize(len(unique_names))}'
        joined_text = ', '.join(unique_names)
        value_html = (
            _format_looky_tooltip_html(joined_text, looky_names, is_disconnected=is_disconnected)
            if looky_names is not None
            else html.escape(joined_text)
        )
        lines.append(f'<span style="color: #9ca3af;">{label}:</span> {value_html}')

    if player.userip is not None and player.userip.usernames:
        _append_source_line('DB Username', player.userip.usernames)
    if player.ps3_username is not None and player.ps3_username:
        _append_source_line('PS3 Username', (player.ps3_username,))
    if player.mod_menus is not None and player.mod_menus.usernames:
        _append_source_line('Mod Menu Username', player.mod_menus.usernames)
    if looky_names is not None:
        with player.looky_system.lock:
            looky_list = list(player.looky_system.usernames) if player.looky_system.is_initialized else []
        if looky_list:
            _append_source_line('Looky Username', looky_list)

    return lines


def _format_userip_tooltip_lines(
    player: Player,
    userip: UserIP,
    *,
    looky_names: set[str] | None = None,
    is_disconnected: bool = False,
) -> list[str]:
    """Format HTML lines describing a player's UserIP metadata and timestamps for tooltips."""
    lines: list[str] = []
    try:
        db_display = str(userip.db_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix(''))
    except ValueError:
        db_display = str(userip.db_path)
    lines.append(f'<span style="color: #9ca3af;">Database:</span> {html.escape(db_display)}')
    lines.extend(
        _format_username_source_lines(
            player,
            looky_names=looky_names,
            is_disconnected=is_disconnected,
        ),
    )
    if userip.notes:
        notes_label = f'Note{pluralize(len(userip.notes))}'
        lines.append(f'<span style="color: #9ca3af;">{notes_label}:</span> {html.escape(", ".join(userip.notes))}')
    if userip.sources:
        sources_label = f'Source{pluralize(len(userip.sources))}'
        lines.append(f'<span style="color: #9ca3af;">{sources_label}:</span> {html.escape(", ".join(userip.sources))}')
    lines.append(f'<span style="color: #9ca3af;">Detections:</span> {userip.detections_count}')
    for label_text, raw_timestamp in (
        ('Added', userip.added_at),
        ('Updated', userip.updated_at),
        ('First Seen', userip.first_seen_at),
        ('Last Seen', userip.last_seen_at),
    ):
        formatted_display = format_iso_timestamp_display(raw_timestamp)
        if formatted_display:
            lines.append(f'<span style="color: #9ca3af;">{label_text}:</span> {html.escape(formatted_display)}')
    return lines


class ElidedTextTooltipDelegate(QStyledItemDelegate):
    """Custom delegate that reliably shows a tooltip only if the text is horizontally truncated."""

    @override
    def helpEvent(
        self,
        event: QHelpEvent,
        view: QAbstractItemView,
        option: QStyleOptionViewItem,
        index: QModelIndex | QPersistentModelIndex,
    ) -> bool:
        """Show tooltip for elided cells, let the default handle the rest."""
        if not event or event.type() != QEvent.Type.ToolTip:
            return super().helpEvent(event, view, option, index)

        if index.data(Qt.ItemDataRole.ToolTipRole):
            return super().helpEvent(event, view, option, index)

        text = index.data(Qt.ItemDataRole.DisplayRole)
        if not isinstance(text, str) or not text:
            return super().helpEvent(event, view, option, index)

        model = index.model()
        username_column = getattr(model, 'username_column_index', -1)
        matched_player: Player | None = None
        if 0 <= username_column == index.column():
            get_player = getattr(model, 'get_player_for_row', None)
            if callable(get_player):
                raw_player = get_player(index.row())
                if raw_player is not None:
                    matched_player = cast('Player', raw_player)
        player_userip: UserIP | None = matched_player.userip if matched_player is not None else None

        opt = QStyleOptionViewItem(option)
        if not opt.rect.isValid():
            opt.rect = view.visualRect(index)
        self.initStyleOption(opt, index)
        style = view.style()
        text_rectangle = style.subElementRect(QStyle.SubElement.SE_ItemViewItemText, opt, view)
        text_margin = style.pixelMetric(QStyle.PixelMetric.PM_FocusFrameHMargin, opt, view) + 1
        usable_text_width = max(0, text_rectangle.width() - text_margin * 2)
        is_truncated = QFontMetrics(_get_option_font(opt)).horizontalAdvance(text) > usable_text_width
        if not is_truncated and player_userip is None:
            return super().helpEvent(event, view, option, index)

        tooltip_text = text
        user_role_data = index.data(Qt.ItemDataRole.UserRole)
        looky_names: set[str] | None = cast('set[str]', user_role_data) if isinstance(user_role_data, set) and user_role_data else None
        if matched_player is not None or looky_names is not None:
            is_disconnected = _is_disconnected_cell(view, index)
            if matched_player is not None and player_userip is not None:
                userip_lines = _format_userip_tooltip_lines(
                    matched_player,
                    player_userip,
                    looky_names=looky_names,
                    is_disconnected=is_disconnected,
                )
                tooltip_text = '<br>'.join(userip_lines)
            elif matched_player is not None:
                source_lines = _format_username_source_lines(
                    matched_player,
                    looky_names=looky_names,
                    is_disconnected=is_disconnected,
                )
                tooltip_text = '<br>'.join(source_lines) if source_lines else f'<span>{html.escape(text)}</span>'
            elif looky_names is not None:
                tooltip_text = _format_looky_tooltip_html(text, looky_names, is_disconnected=is_disconnected)

        QToolTip.showText(event.globalPos(), tooltip_text, view)
        return True

    @override
    def initStyleOption(self, option: QStyleOptionViewItem, index: QModelIndex | QPersistentModelIndex) -> None:
        """Initialize style option and adjust decoration size for custom-sized decorations."""
        super().initStyleOption(option, index)
        if option.features & QStyleOptionViewItem.ViewItemFeature.HasDecoration and not option.icon.isNull():
            if option.decorationSize.width() <= 0 or option.decorationSize.height() <= 0:
                option.decorationSize = QSize(_STANDARD_ICON_SIZE, _STANDARD_ICON_SIZE)
            model = index.model()
            ip_column = getattr(model, 'ip_column_index', -1)
            if 0 <= ip_column == index.column():
                size = option.icon.actualSize(QSize(100, _STANDARD_ICON_SIZE))
                if size.width() > _STANDARD_ICON_SIZE:
                    option.decorationSize = size

    def _paint_cell_background(
        self,
        painter: QPainter,
        option: QStyleOptionViewItem,
        index: QModelIndex | QPersistentModelIndex,
        *,
        paint_selection: bool = False,
    ) -> None:
        """Paint custom cell background and hover/selection overlay."""
        rect = _get_option_rect(option)
        is_hovered = bool(option.state & QStyle.StateFlag.State_MouseOver)
        is_selected = bool(option.state & QStyle.StateFlag.State_Selected)
        background_brush = index.data(Qt.ItemDataRole.BackgroundRole)
        has_background_brush = isinstance(background_brush, (QColor, QBrush))

        if has_background_brush and not is_selected:
            painter.save()
            painter.fillRect(rect, background_brush)
            painter.restore()
        elif paint_selection and is_selected and not is_hovered:
            painter.save()
            painter.fillRect(rect, option.palette.highlight())
            painter.restore()

        if not is_hovered:
            return

        raw_is_connected = getattr(self.parent(), 'is_connected_table', None)
        is_connected: bool | None = raw_is_connected if isinstance(raw_is_connected, bool) else None

        if is_connected is None and has_background_brush and not is_selected:
            return

        painter.save()
        grad = QLinearGradient(rect.topLeft(), rect.bottomLeft())
        if is_connected is True:
            if is_selected:
                grad.setColorAt(0, _COLOR_CONNECTED_SEL_TOP)
                grad.setColorAt(1, _COLOR_CONNECTED_SEL_BOTTOM)
            else:
                grad.setColorAt(0, _COLOR_CONNECTED_UNSEL_TOP)
                grad.setColorAt(1, _COLOR_CONNECTED_UNSEL_BOTTOM)
        elif is_connected is False:
            if is_selected:
                grad.setColorAt(0, _COLOR_DISCONNECTED_SEL_TOP)
                grad.setColorAt(1, _COLOR_DISCONNECTED_SEL_BOTTOM)
            else:
                grad.setColorAt(0, _COLOR_DISCONNECTED_UNSEL_TOP)
                grad.setColorAt(1, _COLOR_DISCONNECTED_UNSEL_BOTTOM)
        elif is_selected:
            grad.setColorAt(0, _COLOR_DEFAULT_SEL)
            grad.setColorAt(1, _COLOR_DEFAULT_SEL)
        else:
            grad.setColorAt(0, _COLOR_DEFAULT_UNSEL)
            grad.setColorAt(1, _COLOR_DEFAULT_UNSEL)

        painter.fillRect(rect, grad)
        painter.restore()

    @override
    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index: QModelIndex | QPersistentModelIndex) -> None:
        """Paint table cell with hover gradient and preserve custom ForegroundRole/BackgroundRole."""
        if painter:
            self._paint_cell_background(painter, option, index, paint_selection=False)

        opt = QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)
        # Clear HasFocus so that global stylesheet focus rules do not force white text onto unselected cells
        opt.state &= ~QStyle.StateFlag.State_HasFocus
        if not bool(opt.state & QStyle.StateFlag.State_Selected):
            foreground_brush = index.data(Qt.ItemDataRole.ForegroundRole)
            if isinstance(foreground_brush, (QColor, QBrush)):
                opt.palette.setBrush(QPalette.ColorRole.Text, foreground_brush)
                opt.palette.setBrush(QPalette.ColorRole.WindowText, foreground_brush)
        else:
            opt.palette.setColor(QPalette.ColorRole.Text, _COLOR_WHITE)
            opt.palette.setColor(QPalette.ColorRole.HighlightedText, _COLOR_WHITE)

        super().paint(painter, opt, index)


class SearchHighlightDelegate(ElidedTextTooltipDelegate):
    """Item delegate that highlights search query matches and Looky-resolved usernames."""

    def __init__(
        self,
        parent: QWidget,
        get_search_text: Callable[[], str],
        get_search_column: Callable[[], int] | None = None,
        configure_editor: Callable[[QWidget, QModelIndex | QPersistentModelIndex], None] | None = None,
    ) -> None:
        """Initialize the delegate with callables for the active search query and target column."""
        super().__init__(parent)
        self._get_search_text = get_search_text
        self._get_search_column = get_search_column
        self._configure_editor = configure_editor

    @override
    def createEditor(
        self,
        parent: QWidget,
        option: QStyleOptionViewItem,
        index: QModelIndex | QPersistentModelIndex,
    ) -> QWidget:
        """Create the cell editor widget and apply optional caller configuration."""
        editor = super().createEditor(parent, option, index)
        if self._configure_editor is not None:
            self._configure_editor(editor, index)
        return editor

    @override
    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index: QModelIndex | QPersistentModelIndex) -> None:
        """Paint cell with highlighted search substrings or Looky usernames."""
        search_column_matches = True
        if self._get_search_column is not None:
            target_column = self._get_search_column()
            if target_column >= 0 and index.column() != target_column:
                search_column_matches = False

        search_query = self._get_search_text().strip()
        text = index.data(Qt.ItemDataRole.DisplayRole)
        user_role_data = index.data(Qt.ItemDataRole.UserRole)
        looky_names: set[str] | None = cast('set[str]', user_role_data) if isinstance(user_role_data, set) and user_role_data else None

        has_search_match = bool(search_column_matches and search_query and isinstance(text, str) and search_query.lower() in text.lower())

        if not isinstance(text, str) or (not has_search_match and not bool(looky_names)):
            super().paint(painter, option, index)
            return

        cell_rectangle = _get_option_rect(option)

        if painter:
            self._paint_cell_background(painter, option, index, paint_selection=True)

        style_option = QStyleOptionViewItem(option)
        self.initStyleOption(style_option, index)
        style_option.state &= ~QStyle.StateFlag.State_HasFocus

        text_color = _COLOR_WHITE
        if not bool(style_option.state & QStyle.StateFlag.State_Selected):
            foreground_brush = index.data(Qt.ItemDataRole.ForegroundRole)
            if isinstance(foreground_brush, QColor):
                text_color = foreground_brush
            elif isinstance(foreground_brush, QBrush):
                text_color = foreground_brush.color()

        if painter:
            font = _get_option_font(style_option)
            painter.save()
            painter.setFont(font)

            view = self.parent()
            widget = view if isinstance(view, QWidget) else None
            style = widget.style() if widget is not None else QApplication.style()

            decoration_rectangle = style.subElementRect(QStyle.SubElement.SE_ItemViewItemDecoration, style_option, widget)
            text_rectangle = style.subElementRect(QStyle.SubElement.SE_ItemViewItemText, style_option, widget)
            text_margin = style.pixelMetric(QStyle.PixelMetric.PM_FocusFrameHMargin, style_option, widget) + 1

            icon_data = index.data(Qt.ItemDataRole.DecorationRole)
            if isinstance(icon_data, (QIcon, QPixmap)) and not (isinstance(icon_data, QIcon) and icon_data.isNull()):
                icon_rectangle = QRect(
                    decoration_rectangle.left(),
                    cell_rectangle.top() + (cell_rectangle.height() - style_option.decorationSize.height()) // 2,
                    style_option.decorationSize.width(),
                    style_option.decorationSize.height(),
                )
                if isinstance(icon_data, QIcon):
                    icon_data.paint(painter, icon_rectangle, Qt.AlignmentFlag.AlignCenter)
                else:
                    painter.drawPixmap(icon_rectangle, icon_data)

            painter.setClipRect(cell_rectangle)

            font_metrics = QFontMetrics(font)
            display_text = text
            usable_text_width = max(0, text_rectangle.width() - text_margin * 2)
            if font_metrics.horizontalAdvance(text) > usable_text_width:
                display_text = font_metrics.elidedText(text, Qt.TextElideMode.ElideRight, usable_text_width)

            formats: list[QTextLayout.FormatRange] = []

            base_format = QTextLayout.FormatRange()
            base_format.start = 0
            base_format.length = len(display_text)
            base_char_format = QTextCharFormat()
            base_char_format.setForeground(text_color)
            base_format.format = base_char_format
            formats.append(base_format)

            if looky_names is not None:
                looky_casefolded = {name.casefold() for name in looky_names}
                looky_format = QTextCharFormat()
                is_disconnected = _is_disconnected_cell(self.parent(), index)
                looky_color = _DISCONNECTED_LOOKY_TEXT_COLOR if is_disconnected else _LOOKY_TEXT_COLOR
                looky_format.setForeground(looky_color)

                usernames_text = _strip_usernames_note_suffix(text, index.model(), index.row())
                display_usernames_text = (
                    display_text[: len(usernames_text)]
                    if len(display_text) > len(usernames_text) and display_text.startswith(usernames_text)
                    else display_text
                )
                tokens = split_usernames(usernames_text)
                display_segments = split_usernames(display_usernames_text)
                current_offset = 0

                for i, segment in enumerate(display_segments):
                    segment_position = display_usernames_text.find(segment, current_offset)
                    if segment_position == -1:
                        segment_position = current_offset
                    if i < len(tokens) and tokens[i].casefold() in looky_casefolded:
                        format_range = QTextLayout.FormatRange()
                        format_range.start = segment_position
                        if i + 1 < len(display_segments):
                            next_segment = display_segments[i + 1]
                            next_position = display_usernames_text.find(next_segment, segment_position + len(segment))
                            end_position = next_position if next_position != -1 else segment_position + len(segment)
                        else:
                            end_position = len(display_usernames_text) if display_usernames_text.endswith(('…', '...')) else segment_position + len(segment)
                        format_range.length = end_position - segment_position
                        format_range.format = looky_format
                        formats.append(format_range)
                    current_offset = segment_position + len(segment)

            if has_search_match:
                lower_display_text = display_text.lower()
                lower_query = search_query.lower()
                search_position = 0

                highlight_format = QTextCharFormat()
                highlight_format.setBackground(_SEARCH_HIGHLIGHT_BG_COLOR)
                highlight_format.setForeground(_SEARCH_HIGHLIGHT_FG_COLOR)

                while True:
                    match_index = lower_display_text.find(lower_query, search_position)
                    if match_index == -1:
                        break
                    format_range = QTextLayout.FormatRange()
                    format_range.start = match_index
                    format_range.length = len(lower_query)
                    format_range.format = highlight_format
                    formats.append(format_range)
                    search_position = match_index + len(lower_query)

            text_option = QTextOption()
            text_option.setWrapMode(QTextOption.WrapMode.NoWrap)

            layout = QTextLayout(display_text, font)
            layout.setTextOption(text_option)
            layout.setFormats(formats)

            layout.beginLayout()
            line = layout.createLine()
            if line.isValid():
                line.setLineWidth(usable_text_width)
            layout.endLayout()

            vertical_offset = cell_rectangle.top() + max(0, round((cell_rectangle.height() - line.height()) / 2))

            alignment_data = index.data(Qt.ItemDataRole.TextAlignmentRole)
            alignment = Qt.AlignmentFlag(alignment_data) if isinstance(alignment_data, int) else Qt.AlignmentFlag.AlignLeft
            if bool(alignment & Qt.AlignmentFlag.AlignRight):
                horizontal_offset = text_rectangle.right() - line.naturalTextWidth() - text_margin
            elif bool(alignment & Qt.AlignmentFlag.AlignHCenter):
                horizontal_offset = text_rectangle.left() + max(0.0, (text_rectangle.width() - line.naturalTextWidth()) / 2)
            else:
                horizontal_offset = float(text_rectangle.left() + text_margin)

            layout.draw(painter, QPointF(horizontal_offset, float(vertical_offset)))
            painter.restore()
