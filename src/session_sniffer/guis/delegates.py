"""Custom item delegates for table and tree views."""

import html
from typing import TYPE_CHECKING, cast, override

from PySide6.QtCore import QEvent, QModelIndex, QPersistentModelIndex, QPointF, QRect, QRectF, QSize, Qt
from PySide6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QFontMetrics,
    QHelpEvent,
    QIcon,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPalette,
    QPen,
    QPixmap,
    QTextCharFormat,
    QTextLayout,
    QTextOption,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QLineEdit,
    QStyle,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QToolTip,
    QWidget,
)

from session_sniffer.constants.local import USERIP_DATABASES_DIR_PATH
from session_sniffer.guis.colors import TableColors
from session_sniffer.models.combo_rules import ComboRule, split_condition_key
from session_sniffer.models.userip_settings_model import format_iso_timestamp_display
from session_sniffer.text_utils import pluralize, split_usernames

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

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
_OPAQUE_ALPHA = 255


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
    resolved_foreground_color = foreground_brush if isinstance(foreground_brush, QColor) else (foreground_brush.color() if isinstance(foreground_brush, QBrush) else None)
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
        value_html = _format_looky_tooltip_html(joined_text, looky_names, is_disconnected=is_disconnected) if looky_names is not None else html.escape(joined_text)
        lines.append(f'<span style="color: #9ca3af;">{label}:</span> {value_html}')

    if player.userip is not None and player.userip.usernames:
        if player.userip.known_alts:
            known_alts_cf = {alt.casefold() for alt in player.userip.known_alts}
            direct_db_usernames = [name for name in player.userip.usernames if name.casefold() not in known_alts_cf]
            _append_source_line('DB Username', direct_db_usernames)
            _append_source_line('DB Known Alt', player.userip.known_alts)
        else:
            _append_source_line('DB Username', player.userip.usernames)
    if player.ps3_username is not None and player.ps3_username:
        _append_source_line('PS3 Username', (player.ps3_username,))
    if player.mod_menus is not None and player.mod_menus.usernames:
        modmenu_label = 'Relay Username' if player.mod_menus.is_relay else 'Mod Menu Username'
        _append_source_line(modmenu_label, player.mod_menus.usernames)
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
            bg_color = background_brush if isinstance(background_brush, QColor) else background_brush.color()
            if bg_color.alpha() < _OPAQUE_ALPHA:
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
        self._highlight_format = QTextCharFormat()
        self._highlight_format.setBackground(_SEARCH_HIGHLIGHT_BG_COLOR)
        self._highlight_format.setForeground(_SEARCH_HIGHLIGHT_FG_COLOR)

    @override
    def createEditor(
        self,
        parent: QWidget,
        option: QStyleOptionViewItem,
        index: QModelIndex | QPersistentModelIndex,
    ) -> QWidget:
        """Create the cell editor widget and apply optional caller configuration."""
        editor = super().createEditor(parent, option, index)
        if isinstance(editor, QLineEdit):
            editor.setTextMargins(0, -2, 0, 0)
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
                    display_text[: len(usernames_text)] if len(display_text) > len(usernames_text) and display_text.startswith(usernames_text) else display_text
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
                highlight_format = self._highlight_format

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


_COMBO_CONDITION_LABELS: dict[str, str] = {
    'event': 'Player Event',
    'continent': 'Continent',
    'country': 'Country',
    'city': 'City',
    'region': 'Region',
    'org': 'Organization',
    'isp': 'ISP',
    'asn': 'ASN',
    'as_name': 'AS Name',
    'ip_range': 'IP / Range',
    'mobile': 'Mobile',
    'vpn': 'VPN / Proxy',
    'hosting': 'Hosting',
}
_COMBO_EVENT_NAMES: dict[str, str] = {
    'join': 'Joined',
    'rejoin': 'Rejoined',
    'leave': 'Left',
}


class ComboRuleCardDelegate(QStyledItemDelegate):
    """Custom item delegate that renders each ComboRule as a structured multi-line card with condition chips and action badges."""

    def __init__(
        self,
        parent: QWidget,
        get_rule: Callable[[int], ComboRule | None],
        is_suspend_supported: Callable[[], bool],
        scale_fn: Callable[[int], int],
    ) -> None:
        """Initialize the delegate with callables to look up rules, suspend availability, and UI scaling."""
        super().__init__(parent)
        self._get_rule = get_rule
        self._is_suspend_supported = is_suspend_supported
        self._scale = scale_fn

    @staticmethod
    def _format_condition_chips(rule: ComboRule) -> list[tuple[str, str, bool]]:
        """Return `(prefix_text, value_text, is_negated)` tuples for all conditions in *rule*."""
        chips: list[tuple[str, str, bool]] = []
        for key, value in rule.conditions.items():
            base_key, is_negated = split_condition_key(key)
            label = _COMBO_CONDITION_LABELS.get(base_key, base_key)
            operator = ' ≠ ' if is_negated else ': '
            prefix_text = f'{label}{operator}'
            if base_key == 'event' and isinstance(value, list):
                value_text = ' | '.join(_COMBO_EVENT_NAMES.get(item, item) for item in value)
            elif isinstance(value, bool):
                value_text = 'Yes' if value else 'No'
            elif isinstance(value, list):
                value_text = ' | '.join(value)
            else:
                value_text = value
            chips.append((prefix_text, value_text, is_negated))
        return chips

    def _format_action_badges(self, rule: ComboRule) -> list[tuple[str, QColor, QColor, QColor]]:
        """Return `(text, bg_color, border_color, text_color)` badges for the rule's configured actions."""
        badges: list[tuple[str, QColor, QColor, QColor]] = []
        if self._is_suspend_supported() and rule.protection_enabled:
            dur_str = 'Auto' if rule.duration == 'Auto' else f'{rule.duration}s'
            badges.append((f'Suspend: {dur_str}', QColor(245, 158, 11, 38), QColor(245, 158, 11, 115), QColor('#fbbf24')))
        if rule.voice_notifications:
            badges.append((f'Voice: {rule.voice_notifications}', QColor(56, 189, 248, 38), QColor(56, 189, 248, 115), QColor('#38bdf8')))
        if rule.message_box:
            badges.append(('Message Box', QColor(168, 85, 247, 38), QColor(168, 85, 247, 115), QColor('#c084fc')))
        if rule.logging:
            badges.append(('Logging', QColor(45, 212, 191, 34), QColor(45, 212, 191, 105), QColor('#2dd4bf')))
        if not badges:
            badges.append(('No Actions', QColor(148, 163, 184, 24), QColor(148, 163, 184, 65), QColor('#64748b')))
        return badges

    @staticmethod
    def _chip_fonts(base_font: QFont) -> tuple[QFont, QFont]:
        """Return `(bold_font, regular_font)` sized for condition chips."""
        reg_font = QFont(base_font)
        reg_font.setPointSizeF(8.5)
        reg_font.setBold(False)
        bold_font = QFont(reg_font)
        bold_font.setBold(True)
        return bold_font, reg_font

    def _layout_chips(
        self,
        content_left: int,
        content_width: int,
        start_y: int,
        base_font: QFont,
        chips: Sequence[tuple[str, str, bool]],
    ) -> tuple[list[tuple[QRect, str, str, bool]], int]:
        """Compute flow-wrapped chip rectangles and return `(placed_chips, bottom_y)`."""
        bold_font, reg_font = self._chip_fonts(base_font)
        bold_fm, reg_fm = QFontMetrics(bold_font), QFontMetrics(reg_font)
        chip_pad_h = self._scale(8)
        chip_h = max(bold_fm.height(), reg_fm.height()) + self._scale(6)
        chip_h_gap = self._scale(6)
        chip_v_gap = self._scale(5)
        x = content_left
        y = start_y
        placed: list[tuple[QRect, str, str, bool]] = []
        for prefix_text, value_text, is_negated in chips:
            prefix_w = bold_fm.horizontalAdvance(prefix_text)
            val_w = reg_fm.horizontalAdvance(value_text) + 2
            chip_w = min(content_width, chip_pad_h * 2 + prefix_w + val_w)
            if x > content_left and x + chip_w > content_left + content_width:
                x = content_left
                y += chip_h + chip_v_gap
            placed.append((QRect(x, y, chip_w, chip_h), prefix_text, value_text, is_negated))
            x += chip_w + chip_h_gap
        bottom_y = (y + chip_h) if placed else (start_y + chip_h)
        return placed, bottom_y

    @override
    def sizeHint(self, option: QStyleOptionViewItem, index: QModelIndex | QPersistentModelIndex) -> QSize:
        """Return the dynamically wrapped card height for the combo rule at *index*."""
        rule = self._get_rule(index.row())
        if rule is None:
            return super().sizeHint(option, index)

        scale = self._scale
        view = self.parent()
        viewport = view.viewport() if isinstance(view, QAbstractItemView) else None
        viewport_w = viewport.width() if viewport is not None and viewport.width() > 0 else 0
        opt_w = _get_option_rect(option).width()
        total_width = viewport_w or opt_w or scale(640)

        outer_h = scale(4)
        outer_v = scale(4)
        accent_w = scale(4)
        pad_h = scale(12)
        pad_top = scale(9)
        pad_bottom = scale(9)
        header_h = scale(22)
        divider_space = scale(13)

        content_left = outer_h + accent_w + pad_h
        content_width = max(scale(120), total_width - outer_h * 2 - accent_w - pad_h * 2)
        chips_start_y = outer_v + pad_top + header_h + divider_space

        chips = self._format_condition_chips(rule)
        _, bottom_y = self._layout_chips(content_left, content_width, chips_start_y, _get_option_font(option), chips)
        return QSize(total_width, bottom_y + pad_bottom + outer_v)

    @override
    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index: QModelIndex | QPersistentModelIndex) -> None:
        """Paint the combo rule card with status pill, rule name, action badges, and wrapped condition chips."""
        rule = self._get_rule(index.row())
        if rule is None or not painter:
            super().paint(painter, option, index)
            return

        scale = self._scale
        rect = _get_option_rect(option)
        is_selected = bool(option.state & QStyle.StateFlag.State_Selected)
        is_hovered = bool(option.state & QStyle.StateFlag.State_MouseOver)
        is_enabled = rule.enabled

        outer_h = scale(4)
        outer_v = scale(4)
        accent_w = scale(4)
        pad_h = scale(12)
        pad_top = scale(9)
        header_h = scale(22)
        divider_space = scale(13)
        radius = float(scale(7))

        card_rect = rect.adjusted(outer_h, outer_v, -outer_h, -outer_v)
        if card_rect.width() <= 0 or card_rect.height() <= 0:
            return

        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, on=True)
        painter.setRenderHint(QPainter.RenderHint.TextAntialiasing, on=True)

        card_path = QPainterPath()
        card_path.addRoundedRect(QRectF(card_rect), radius, radius)

        bg_grad = QLinearGradient(card_rect.topLeft(), card_rect.bottomLeft())
        if is_selected:
            bg_grad.setColorAt(0.0, QColor('#1e3246'))
            bg_grad.setColorAt(1.0, QColor('#152434'))
            border_color = QColor('#38bdf8')
            border_width = 1.5
        elif is_hovered:
            bg_grad.setColorAt(0.0, QColor('#1b2735'))
            bg_grad.setColorAt(1.0, QColor('#141d28'))
            border_color = QColor('#3b556e')
            border_width = 1.0
        elif is_enabled:
            bg_grad.setColorAt(0.0, QColor('#17212c'))
            bg_grad.setColorAt(1.0, QColor('#111820'))
            border_color = QColor('#263747')
            border_width = 1.0
        else:
            bg_grad.setColorAt(0.0, QColor('#131820'))
            bg_grad.setColorAt(1.0, QColor('#0e1218'))
            border_color = QColor('#1e2832')
            border_width = 1.0

        painter.fillPath(card_path, bg_grad)

        painter.save()
        painter.setClipPath(card_path)
        accent_rect = QRect(card_rect.left(), card_rect.top(), accent_w, card_rect.height())
        painter.fillRect(accent_rect, QColor('#10b981') if is_enabled else QColor('#475569'))
        painter.restore()

        painter.setPen(QPen(border_color, border_width))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPath(card_path)

        base_font = _get_option_font(option)
        content_left = card_rect.left() + accent_w + pad_h
        content_right = card_rect.right() - pad_h
        content_width = max(scale(120), content_right - content_left)
        header_top = card_rect.top() + pad_top
        header_rect = QRect(content_left, header_top, content_width, header_h)

        # --- Right-aligned Action Badges ---
        badge_font = QFont(base_font)
        badge_font.setPointSizeF(8.0)
        badge_font.setBold(True)
        badge_fm = QFontMetrics(badge_font)
        badge_pad_h = scale(7)
        badge_gap = scale(5)
        badge_h = scale(19)
        badge_y = header_top + (header_h - badge_h) // 2
        badge_radius = float(scale(4))

        badges_right_x = content_right
        painter.setFont(badge_font)
        for badge_text, b_bg, b_border, b_fg in reversed(self._format_action_badges(rule)):
            b_w = badge_fm.horizontalAdvance(badge_text) + badge_pad_h * 2
            b_rect = QRect(badges_right_x - b_w, badge_y, b_w, badge_h)
            if b_rect.left() < content_left + scale(140):
                break
            b_path = QPainterPath()
            b_path.addRoundedRect(QRectF(b_rect), badge_radius, badge_radius)
            painter.fillPath(b_path, b_bg)
            painter.setPen(QPen(b_border, 1.0))
            painter.drawPath(b_path)
            painter.setPen(b_fg if is_enabled else QColor('#7c8d9e'))
            painter.drawText(b_rect, Qt.AlignmentFlag.AlignCenter, badge_text)
            badges_right_x = b_rect.left() - badge_gap

        # --- Left-aligned Status Pill + Rule Name + Condition Count ---
        status_text = '✓ ENABLED' if is_enabled else '✕ DISABLED'
        status_bg = QColor(16, 185, 129, 42) if is_enabled else QColor(239, 68, 68, 34)
        status_border = QColor(16, 185, 129, 120) if is_enabled else QColor(239, 68, 68, 95)
        status_fg = QColor('#34d399') if is_enabled else QColor('#f87171')
        status_w = badge_fm.horizontalAdvance(status_text) + badge_pad_h * 2
        status_rect = QRect(content_left, badge_y, status_w, badge_h)
        status_path = QPainterPath()
        status_path.addRoundedRect(QRectF(status_rect), badge_radius, badge_radius)
        painter.fillPath(status_path, status_bg)
        painter.setPen(QPen(status_border, 1.0))
        painter.drawPath(status_path)
        painter.setPen(status_fg)
        painter.drawText(status_rect, Qt.AlignmentFlag.AlignCenter, status_text)

        title_left = status_rect.right() + scale(9)
        title_max_right = max(title_left, badges_right_x - scale(8))

        name_font = QFont(base_font)
        name_font.setPointSizeF(10.0)
        name_font.setBold(True)
        name_fm = QFontMetrics(name_font)
        painter.setFont(name_font)
        painter.setPen(QColor('#ffffff') if is_selected else (QColor('#f1f5f9') if is_enabled else QColor('#94a3b8')))

        avail_title_w = max(0, title_max_right - title_left)
        elided_name = name_fm.elidedText(rule.name, Qt.TextElideMode.ElideRight, avail_title_w)
        name_rect = QRect(title_left, header_rect.top(), avail_title_w, header_rect.height())
        painter.drawText(name_rect, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, elided_name)

        name_drawn_w = name_fm.horizontalAdvance(elided_name)
        count_left = title_left + name_drawn_w + scale(8)
        cond_count = len(rule.conditions)
        count_text = f'({cond_count} condition{pluralize(cond_count)})'
        bold_chip_font, reg_chip_font = self._chip_fonts(base_font)
        reg_chip_fm = QFontMetrics(reg_chip_font)
        if count_left + reg_chip_fm.horizontalAdvance(count_text) <= title_max_right:
            painter.setFont(reg_chip_font)
            painter.setPen(QColor('#64748b'))
            count_rect = QRect(count_left, header_rect.top(), title_max_right - count_left, header_rect.height())
            painter.drawText(count_rect, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, count_text)

        # --- Horizontal Divider ---
        divider_y = header_rect.bottom() + scale(6)
        painter.setPen(QPen(QColor(255, 255, 255, 16), 1.0))
        painter.drawLine(content_left, divider_y, content_right, divider_y)

        # --- Flow-Wrapped Condition Chips ---
        chips_start_y = header_rect.top() + header_h + divider_space
        bold_chip_fm = QFontMetrics(bold_chip_font)
        chips = self._format_condition_chips(rule)
        placed_chips, _ = self._layout_chips(content_left, content_width, chips_start_y, base_font, chips)

        chip_pad_h = scale(8)
        chip_radius = float(scale(4))
        for chip_rect, prefix_text, value_text, is_negated in placed_chips:
            chip_path = QPainterPath()
            chip_path.addRoundedRect(QRectF(chip_rect), chip_radius, chip_radius)
            if is_negated:
                c_bg = QColor(239, 68, 68, 30 if is_enabled else 16)
                c_border = QColor(239, 68, 68, 90 if is_enabled else 45)
                prefix_color = QColor('#fca5a5') if is_enabled else QColor('#9ca3af')
            else:
                c_bg = QColor(56, 189, 248, 22 if is_enabled else 12)
                c_border = QColor(136, 192, 208, 72 if is_enabled else 38)
                prefix_color = QColor('#88c0d0') if is_enabled else QColor('#7c8d9e')
            value_color = QColor('#f1f5f9') if is_enabled else QColor('#94a3b8')

            painter.fillPath(chip_path, c_bg)
            painter.setPen(QPen(c_border, 1.0))
            painter.drawPath(chip_path)

            inner_left = chip_rect.left() + chip_pad_h
            inner_w = max(0, chip_rect.width() - chip_pad_h * 2)
            prefix_w = bold_chip_fm.horizontalAdvance(prefix_text)

            painter.setFont(bold_chip_font)
            painter.setPen(prefix_color)
            prefix_rect = QRect(inner_left, chip_rect.top(), min(prefix_w, inner_w), chip_rect.height())
            painter.drawText(prefix_rect, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, prefix_text)

            val_left = inner_left + prefix_w
            avail_val_w = max(0, inner_w - prefix_w)
            if avail_val_w > 0:
                painter.setFont(reg_chip_font)
                painter.setPen(value_color)
                elided_val = reg_chip_fm.elidedText(value_text, Qt.TextElideMode.ElideRight, avail_val_w)
                val_rect = QRect(val_left, chip_rect.top(), avail_val_w, chip_rect.height())
                painter.drawText(val_rect, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, elided_val)

        painter.restore()
