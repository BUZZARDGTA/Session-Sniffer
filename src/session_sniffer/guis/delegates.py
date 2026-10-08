"""Custom item delegates for table and tree views."""

from typing import TYPE_CHECKING, cast, override

if TYPE_CHECKING:
    from PySide6.QtGui import QFont

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
    QStyle,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QToolTip,
    QWidget,
)

from session_sniffer.guis.colors import TableColors
from session_sniffer.text_utils import split_usernames

if TYPE_CHECKING:
    from collections.abc import Callable

_STANDARD_ICON_SIZE = 16
_CONNECTED_TEXT_COLOR = QColor(TableColors.CONNECTED_TEXT)
_DISCONNECTED_TEXT_COLOR = QColor(TableColors.DISCONNECTED_TEXT)
_DEFAULT_FOREGROUND_COLORS = (_CONNECTED_TEXT_COLOR, _DISCONNECTED_TEXT_COLOR)


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
        if event and event.type() == QEvent.Type.ToolTip:
            if index.data(Qt.ItemDataRole.ToolTipRole):
                return super().helpEvent(event, view, option, index)

            text = index.data(Qt.ItemDataRole.DisplayRole)
            if isinstance(text, str) and text:
                opt = QStyleOptionViewItem(option)
                self.initStyleOption(opt, index)
                if QFontMetrics(cast('QFont', opt.font)).horizontalAdvance(text) > view.visualRect(index).width() - 6:  # type: ignore[redundant-cast]
                    QToolTip.showText(event.globalPos(), text, view)
                    return True

        return super().helpEvent(event, view, option, index)

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

    @override
    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index: QModelIndex | QPersistentModelIndex) -> None:
        """Paint table cell with hover gradient and preserve custom ForegroundRole/BackgroundRole."""
        if painter:
            is_hovered = bool(option.state & QStyle.StateFlag.State_MouseOver)
            is_selected = bool(option.state & QStyle.StateFlag.State_Selected)

            if is_hovered:
                is_connected: bool | None = None
                view = self.parent()
                if view is not None and hasattr(view, 'is_connected_table'):
                    raw_is_connected = getattr(view, 'is_connected_table', None)
                    if isinstance(raw_is_connected, bool):
                        is_connected = raw_is_connected

                painter.save()
                rect = cast('QRect', option.rect)  # type: ignore[redundant-cast]

                if is_connected is True:
                    grad = QLinearGradient(rect.topLeft(), rect.bottomLeft())
                    if is_selected:
                        grad.setColorAt(0, QColor(42, 110, 85, 160))
                        grad.setColorAt(1, QColor(28, 75, 58, 160))
                    else:
                        grad.setColorAt(0, QColor(42, 110, 85, 100))
                        grad.setColorAt(1, QColor(28, 75, 58, 100))
                elif is_connected is False:
                    grad = QLinearGradient(rect.topLeft(), rect.bottomLeft())
                    if is_selected:
                        grad.setColorAt(0, QColor(130, 45, 45, 160))
                        grad.setColorAt(1, QColor(85, 28, 28, 160))
                    else:
                        grad.setColorAt(0, QColor(130, 45, 45, 100))
                        grad.setColorAt(1, QColor(85, 28, 28, 100))
                else:
                    grad = QLinearGradient(rect.topLeft(), rect.bottomLeft())
                    if is_selected:
                        grad.setColorAt(0, QColor('#2f4f64'))
                        grad.setColorAt(1, QColor('#2f4f64'))
                    else:
                        grad.setColorAt(0, QColor('#2d2d30'))
                        grad.setColorAt(1, QColor('#2d2d30'))

                painter.fillRect(rect, grad)
                painter.restore()
            else:
                background_brush = index.data(Qt.ItemDataRole.BackgroundRole)
                if isinstance(background_brush, (QColor, QBrush)) and not is_selected:
                    painter.save()
                    painter.fillRect(cast('QRect', option.rect), background_brush)  # type: ignore[redundant-cast]
                    painter.restore()

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
            opt.palette.setColor(QPalette.ColorRole.Text, QColor('#ffffff'))
            opt.palette.setColor(QPalette.ColorRole.HighlightedText, QColor('#ffffff'))

        super().paint(painter, opt, index)


class SearchHighlightDelegate(ElidedTextTooltipDelegate):
    """Item delegate that highlights search query matches and Looky-resolved usernames."""

    def __init__(
        self,
        parent: QWidget,
        get_search_text: Callable[[], str],
        get_search_column: Callable[[], int] | None = None,
    ) -> None:
        """Initialize the delegate with callables for the active search query and target column."""
        super().__init__(parent)
        self._get_search_text = get_search_text
        self._get_search_column = get_search_column

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
        unregistered_looky_names: set[str] | None = cast('set[str]', user_role_data) if isinstance(user_role_data, set) and user_role_data else None
        background_brush = index.data(Qt.ItemDataRole.BackgroundRole)

        has_search_match = bool(search_column_matches and search_query and isinstance(text, str) and search_query.lower() in text.lower())

        if not isinstance(text, str) or (not has_search_match and not bool(unregistered_looky_names)):
            super().paint(painter, option, index)
            return

        if painter:
            cell_rectangle = cast('QRect', option.rect)  # type: ignore[redundant-cast]
            is_hovered = bool(option.state & QStyle.StateFlag.State_MouseOver)
            is_selected = bool(option.state & QStyle.StateFlag.State_Selected)

            if is_hovered:
                painter.save()
                gradient = QLinearGradient(cell_rectangle.topLeft(), cell_rectangle.bottomLeft())
                if is_selected:
                    gradient.setColorAt(0, QColor('#2f4f64'))
                    gradient.setColorAt(1, QColor('#2f4f64'))
                else:
                    gradient.setColorAt(0, QColor('#2d2d30'))
                    gradient.setColorAt(1, QColor('#2d2d30'))
                painter.fillRect(cell_rectangle, gradient)
                painter.restore()
            elif is_selected:
                painter.save()
                painter.fillRect(cell_rectangle, option.palette.highlight())
                painter.restore()
            elif isinstance(background_brush, (QColor, QBrush)):
                painter.save()
                painter.fillRect(cell_rectangle, background_brush)
                painter.restore()

        style_option = QStyleOptionViewItem(option)
        self.initStyleOption(style_option, index)
        style_option.state &= ~QStyle.StateFlag.State_HasFocus

        text_color = QColor('#ffffff')
        if not bool(style_option.state & QStyle.StateFlag.State_Selected):
            foreground_brush = index.data(Qt.ItemDataRole.ForegroundRole)
            if isinstance(foreground_brush, QColor):
                text_color = foreground_brush
            elif isinstance(foreground_brush, QBrush):
                text_color = foreground_brush.color()

        if painter:
            cell_rectangle = cast('QRect', option.rect)  # type: ignore[redundant-cast]
            font = cast('QFont', style_option.font)  # type: ignore[redundant-cast]
            painter.save()
            painter.setFont(font)

            icon_offset = 0
            icon_data = index.data(Qt.ItemDataRole.DecorationRole)
            if isinstance(icon_data, (QIcon, QPixmap)) and not (isinstance(icon_data, QIcon) and icon_data.isNull()):
                view = self.parent()
                icon_size = view.iconSize() if isinstance(view, QAbstractItemView) else None
                if icon_size is None or not icon_size.isValid():
                    icon_size = option.decorationSize if option.decorationSize.isValid() else None
                if icon_size is None or not icon_size.isValid():
                    icon_size = QSize(16, 16)
                icon_rectangle = QRect(
                    cell_rectangle.left() + 6,
                    cell_rectangle.top() + (cell_rectangle.height() - icon_size.height()) // 2,
                    icon_size.width(),
                    icon_size.height(),
                )
                if isinstance(icon_data, QIcon):
                    icon_data.paint(painter, icon_rectangle, Qt.AlignmentFlag.AlignCenter)
                else:
                    painter.drawPixmap(icon_rectangle, icon_data)
                icon_offset = icon_size.width() + 6

            text_rectangle = cell_rectangle.adjusted(6 + icon_offset, 0, -6, 0)
            painter.setClipRect(cell_rectangle)

            font_metrics = QFontMetrics(font)
            display_text = text
            if font_metrics.horizontalAdvance(text) > text_rectangle.width():
                display_text = font_metrics.elidedText(text, Qt.TextElideMode.ElideRight, text_rectangle.width())

            formats: list[QTextLayout.FormatRange] = []

            base_format = QTextLayout.FormatRange()
            base_format.start = 0
            base_format.length = len(display_text)
            base_char_format = QTextCharFormat()
            base_char_format.setForeground(text_color)
            base_format.format = base_char_format
            formats.append(base_format)

            if (
                unregistered_looky_names is not None
                and unregistered_looky_names
                and not isinstance(background_brush, (QColor, QBrush))
                and text_color in _DEFAULT_FOREGROUND_COLORS
            ):
                unregistered_looky_casefolded = {name.casefold() for name in unregistered_looky_names}
                looky_format = QTextCharFormat()
                is_disconnected = False
                view = self.parent()
                if view is not None and hasattr(view, 'is_connected_table'):
                    raw_is_connected = getattr(view, 'is_connected_table', None)
                    if isinstance(raw_is_connected, bool):
                        is_disconnected = not raw_is_connected
                if not is_disconnected:
                    foreground_brush = index.data(Qt.ItemDataRole.ForegroundRole)
                    resolved_foreground_color = (
                        foreground_brush if isinstance(foreground_brush, QColor) else (foreground_brush.color() if isinstance(foreground_brush, QBrush) else None)
                    )
                    if resolved_foreground_color is not None and resolved_foreground_color == QColor(TableColors.DISCONNECTED_TEXT):
                        is_disconnected = True
                looky_color = QColor(TableColors.DISCONNECTED_LOOKY_TEXT) if is_disconnected else QColor(TableColors.LOOKY_TEXT)
                looky_format.setForeground(looky_color)

                tokens = split_usernames(text)
                display_segments = split_usernames(display_text)
                current_offset = 0

                for i, segment in enumerate(display_segments):
                    segment_position = display_text.find(segment, current_offset)
                    if segment_position == -1:
                        segment_position = current_offset
                    if i < len(tokens) and tokens[i].casefold() in unregistered_looky_casefolded:
                        format_range = QTextLayout.FormatRange()
                        format_range.start = segment_position
                        if i + 1 < len(display_segments):
                            next_segment = display_segments[i + 1]
                            next_position = display_text.find(next_segment, segment_position + len(segment))
                            end_position = next_position if next_position != -1 else segment_position + len(segment)
                        else:
                            end_position = len(display_text) if display_text.endswith(('…', '...')) else segment_position + len(segment)
                        format_range.length = end_position - segment_position
                        format_range.format = looky_format
                        formats.append(format_range)
                    current_offset = segment_position + len(segment)

            if has_search_match:
                lower_display_text = display_text.lower()
                lower_query = search_query.lower()
                search_position = 0

                highlight_format = QTextCharFormat()
                highlight_format.setBackground(QColor('#e3b341'))
                highlight_format.setForeground(QColor('#000000'))

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
                line.setLineWidth(text_rectangle.width())
            layout.endLayout()

            vertical_offset = text_rectangle.top() + max(0, round((text_rectangle.height() - line.height()) / 2))

            alignment_data = index.data(Qt.ItemDataRole.TextAlignmentRole)
            alignment = Qt.AlignmentFlag(alignment_data) if isinstance(alignment_data, int) else Qt.AlignmentFlag.AlignLeft
            if bool(alignment & Qt.AlignmentFlag.AlignRight):
                horizontal_offset = text_rectangle.right() - line.naturalTextWidth()
            elif bool(alignment & Qt.AlignmentFlag.AlignHCenter):
                horizontal_offset = text_rectangle.left() + max(0.0, (text_rectangle.width() - line.naturalTextWidth()) / 2)
            else:
                horizontal_offset = float(text_rectangle.left())

            layout.draw(painter, QPointF(horizontal_offset, float(vertical_offset)))
            painter.restore()
