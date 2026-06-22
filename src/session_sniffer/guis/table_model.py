"""Session table model for connected and disconnected player tables."""

import ipaddress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from operator import attrgetter
from typing import TYPE_CHECKING, override

from PyQt6.QtCore import (
    QAbstractTableModel,
    QItemSelection,
    QItemSelectionModel,
    QModelIndex,
    Qt,
)
from PyQt6.QtGui import QBrush, QIcon
from PyQt6.QtWidgets import (
    QHeaderView,
    QTableView,
)

from session_sniffer.constants.standalone import (
    BANDWIDTH_BASE_COLUMN_ATTRS,
    BANDWIDTH_RATE_STAT_COLUMNS,
    LOCATION_COLUMNS,
    ORGANIZATION_COLUMNS,
    PACKET_STAT_COLUMNS,
    STATUS_COLUMNS,
)
from session_sniffer.error_messages import format_type_error
from session_sniffer.guis.exceptions import TableDataConsistencyError, UnsupportedSortColumnError
from session_sniffer.player.registry import PlayersRegistry

if TYPE_CHECKING:
    from session_sniffer.guis.tables import SessionTableView
    from session_sniffer.rendering_core.types import CellColor

GUI_COLUMN_HEADERS_TOOLTIPS = {
    'Usernames': (
        'Displays the usernames of players from your UserIP database files.\n\n'
        'For GTA V PC users who have used the Session Sniffer mod menu plugin,\n'
        'it automatically resolves usernames while the plugin is running,\n'
        'or shows previously resolved players that were seen by the plugin.'
    ),
    'First Seen': 'The very first time the player was observed across all sessions.',
    'Last Rejoin': 'The most recent time the player rejoined your session.',
    'Last Seen': 'The most recent time the player was active in your session.',
    'T. Session Time': 'The total amount of time the player has been playing across all sessions.',
    'Session Time': 'The amount of time the player was playing in the last session before disconnecting.',
    'Rejoins': 'The number of times the player has left and joined again your session across all sessions.',
    'T. Packets': 'The total number of packets exchanged with the player across all sessions.',
    'Packets': 'The number of packets exchanged (Received + Sent) with the player during the current session.',
    'T. Packets Received': 'The total number of packets received from the player across all sessions.',
    'Packets Received': 'The number of packets received from the player during the current session.',
    'T. Packets Sent': 'The total number of packets sent to the player across all sessions.',
    'Packets Sent': 'The number of packets sent to the player during the current session.',
    'T. Min Packet Length': 'The minimum packet length (in bytes) exchanged with the player across all sessions.',
    'Min Packet Length': 'The minimum packet length (in bytes) exchanged with the player during the current session.',
    'T. Avg Packet Length': 'The average packet length (in bytes) exchanged with the player across all sessions.',
    'Avg Packet Length': 'The average packet length (in bytes) exchanged with the player during the current session.',
    'T. Max Packet Length': 'The maximum packet length (in bytes) exchanged with the player across all sessions.',
    'Max Packet Length': 'The maximum packet length (in bytes) exchanged with the player during the current session.',
    'PPS': 'The number of Packets exchanged (Received + Sent) with the player Per Second during the current session.',
    'PPM': 'The number of Packets exchanged (Received + Sent) with the player Per Minute during the current session.',
    'T. Bandwidth': 'The total amount of bytes transferred (Download + Upload) with the player across all sessions.',
    'Bandwidth': 'The amount of bytes transferred (Download + Upload) with the player during the current session.',
    'T. Download': 'The total amount of bytes downloaded from the player across all sessions.',
    'Download': 'The amount of bytes downloaded from the player during the current session.',
    'T. Upload': 'The total amount of bytes uploaded to the player across all sessions.',
    'Upload': 'The amount of bytes uploaded to the player during the current session.',
    'BPS': 'The number of Bytes transferred (Downloaded + Uploaded) with the player Per Second during the current session.',
    'BPM': 'The number of Bytes transferred (Downloaded + Uploaded) with the player Per Minute during the current session.',
    'IP Address': 'The IP address of the player.',
    'Hostname': "The domain name associated with the player's IP address, resolved through a reverse DNS lookup.",
    'Last Port': "The port used by the player's last captured packet.",
    'Middle Ports': 'The ports used by the player between the first and last captured packets.',
    'First Port': "The port used by the player's first captured packet.",
    'Continent': "The continent of the player's IP location.",
    'Country': "The country of the player's IP location.",
    'Region': "The region of the player's IP location.",
    'R. Code': "The region code of the player's IP location.",
    'City': "The city associated with the player's IP location (typically representing the ISP or an intermediate location, not the player's home address city).",
    'District': "The district of the player's IP location.",
    'ZIP Code': "The ZIP/postal code of the player's IP location.",
    'Lat': "The latitude of the player's IP location.",
    'Lon': "The longitude of the player's IP location.",
    'Time Zone': "The time zone of the player's IP location.",
    'Offset': "The time zone offset of the player's IP location.",
    'Currency': "The currency associated with the player's IP location.",
    'Organization': "The organization associated with the player's IP address.",
    'ISP': "The Internet Service Provider of the player's IP address.",
    'ASN / ISP': 'The Autonomous System Number or Internet Service Provider of the player.',
    'AS': "The Autonomous System code of the player's IP.",
    'ASN': "The Autonomous System Number name associated with the player's IP.",
    'Mobile': 'Indicates if the player is using a mobile network (e.g., through a cellular hotspot or mobile data).',
    'VPN': 'Indicates if the player is using a VPN, Proxy, or Tor relay.',
    'Hosting': 'Indicates if the player is using a hosting provider (similar to VPN).',
}


@dataclass(frozen=True, slots=True)
class _ColumnIndices:
    """Immutable cache of frequently used column indices."""

    ip: int
    username: int
    country: int | None


class SessionTableModel(QAbstractTableModel):  # pylint: disable=too-many-public-methods
    """Provide a Qt table model for rendering connected/disconnected sessions."""

    TABLE_CELL_TOOLTIP_MARGIN = 8  # Margin in pixels for determining when to show tooltips for truncated text

    def __init__(self, headers: list[str]) -> None:
        """Initialize the table model with a set of column headers.

        Args:
            headers: Column header labels for the table.
        """
        super().__init__()

        self._view: SessionTableView | None = None  # Initially, no view is attached
        self._data: list[list[str]] = []  # The data to be displayed in the table
        self._compiled_colors: list[list[CellColor]] = []  # The compiled colors for the table
        self._headers = headers  # The column headers
        self._column_indices = _ColumnIndices(
            ip=self._headers.index('IP Address'),
            username=self._headers.index('Usernames'),
            country=self.get_column_index('Country'),
        )
        self._ip_to_row_index: dict[str, int] = {}  # O(1) row lookup by IP

    # --------------------------------------------------------------------------
    # Public properties
    # --------------------------------------------------------------------------

    @staticmethod
    def _remove_session_host_crown_from_ip(ip_address: str) -> str:
        """Remove the crown suffix from an IP address string if present.

        The crown emoji (👑) is used to indicate that this IP address belongs to the session host.
        This method removes that visual indicator to get the clean IP address string.

        Args:
            ip_address: The IP address string that may contain a session host crown suffix.

        Returns:
            The IP address string with session host crown suffix removed.
        """
        return ip_address.removesuffix(' 👑')

    @property
    def view(self) -> SessionTableView:
        """Get or attach a `SessionTableView` to this model."""
        if self._view is None:
            raise TypeError(format_type_error(self._view, QTableView))
        return self._view

    @view.setter
    def view(self, new_view: SessionTableView) -> None:
        """Attach a `SessionTableView` to this model."""
        self._view = new_view

    # --------------------------------------------------------------------------
    # Public read-only properties
    # --------------------------------------------------------------------------

    @property
    def column_names(self) -> list[str]:
        """Return the current column header names."""
        return self._headers

    @property
    def ip_column_index(self) -> int:
        """Returns the index of the 'IP Address' column in this table model.

        This value is computed during initialization based on the `headers` provided.<br>
        It is read-only and specific to this instance.
        """
        return self._column_indices.ip

    @property
    def username_column_index(self) -> int:
        """Returns the index of the 'Usernames' column in this table model.

        This value is computed during initialization based on the `headers` provided.<br>
        It is read-only and specific to this instance.
        """
        return self._column_indices.username

    # --------------------------------------------------------------------------
    # Qt model methods (overrides)
    # --------------------------------------------------------------------------

    @override
    def rowCount(self, parent: QModelIndex | None = None) -> int:
        """Return number of rows in the model."""
        if parent is None:
            parent = QModelIndex()
        return len(self._data)

    @override
    def columnCount(self, parent: QModelIndex | None = None) -> int:
        """Return number of columns in the model."""
        if parent is None:
            parent = QModelIndex()
        return len(self._headers)

    @override
    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> str | QBrush | QIcon | None:
        """Override data method to customize data retrieval and alignment."""
        if not index.isValid():
            return None

        row_index = index.row()
        column_index = index.column()

        # Check bounds
        if row_index >= len(self._data) or column_index >= len(self._data[row_index]):
            return None  # Return None for invalid index

        output: str | QBrush | QIcon | None = None

        if role == Qt.ItemDataRole.DecorationRole and self._column_indices.country is not None and self._column_indices.country == column_index:
            ip = self.get_ip_from_data_safely(self._data[row_index])

            matched_player = PlayersRegistry.get_player_by_ip(ip)
            if matched_player is not None and matched_player.country_flag is not None:
                output = matched_player.country_flag.icon
        elif role == Qt.ItemDataRole.DisplayRole:
            # Return the cell's text
            output = self._data[row_index][column_index]
        elif role == Qt.ItemDataRole.ForegroundRole and row_index < len(self._compiled_colors) and column_index < len(self._compiled_colors[row_index]):
            # Return the cell's foreground color
            output = QBrush(self._compiled_colors[row_index][column_index].foreground)
        elif role == Qt.ItemDataRole.BackgroundRole and row_index < len(self._compiled_colors) and column_index < len(self._compiled_colors[row_index]):
            # Return the cell's background color
            output = QBrush(self._compiled_colors[row_index][column_index].background)
        elif role == Qt.ItemDataRole.ToolTipRole:
            # Return the tooltip text for the cell
            view = self.view
            horizontal_header = view.horizontalHeader()
            resize_mode = horizontal_header.sectionResizeMode(index.column())

            # Return None if the column resize mode isn't set to Stretch, as it shouldn't be truncated
            if resize_mode == QHeaderView.ResizeMode.Stretch:
                cell_text = self._data[row_index][column_index]

                font_metrics = view.fontMetrics()
                text_width = font_metrics.horizontalAdvance(cell_text)
                column_width = view.columnWidth(index.column())

                if text_width > column_width - self.TABLE_CELL_TOOLTIP_MARGIN:
                    output = cell_text

        return output

    @override
    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> str | None:
        """Return header display text and tooltips for the table model."""
        if orientation == Qt.Orientation.Horizontal:
            if role == Qt.ItemDataRole.DisplayRole:
                return self._headers[section]  # Display the header name
            if role == Qt.ItemDataRole.ToolTipRole:
                # Fetch the header name and return the corresponding tooltip
                header_name = self._headers[section]
                return GUI_COLUMN_HEADERS_TOOLTIPS.get(header_name)

        return None

    @override
    def flags(self, index: QModelIndex) -> Qt.ItemFlag:
        """Return Qt flags controlling whether the item is enabled/selectable."""
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags

        return Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable

    @override
    def sort(self, column: int, order: Qt.SortOrder = Qt.SortOrder.AscendingOrder) -> None:
        """Sort the table by a specific column.

        Args:
            column: The column index to sort by.
            order: The order (ascending/descending) to sort in.
        """
        if not self._data:
            if self._compiled_colors:
                raise TableDataConsistencyError(case='colors_without_data')
            return  # No data to process, exit early.

        if not self._compiled_colors:
            raise TableDataConsistencyError(case='data_without_colors')

        self.layoutAboutToBeChanged.emit()

        sorted_column_name = self._headers[column]

        # Combine data and colors for sorting
        combined = list(zip(self._data, self._compiled_colors, strict=True))
        if not combined:
            raise TableDataConsistencyError(case='empty_combined')
        sort_order_bool = order == Qt.SortOrder.DescendingOrder

        if sorted_column_name == 'Usernames':
            combined.sort(
                key=lambda row: ', '.join(row[0][column]).casefold(),
                reverse=sort_order_bool,
            )
        elif sorted_column_name in {'First Seen', 'Last Rejoin', 'Last Seen'}:
            # Precompute datetime values once to avoid O(n log n) registry lookups in the sort key
            _datetime_attr = {'First Seen': 'first_seen', 'Last Rejoin': 'last_rejoin', 'Last Seen': 'last_seen'}[sorted_column_name]
            _default_datetime = datetime.min.replace(tzinfo=UTC)
            _ip_datetime_map: dict[str, datetime] = {
                self.get_ip_from_data_safely(row): (
                    getattr(matched_player.datetime, _datetime_attr)
                    if (matched_player := PlayersRegistry.get_player_by_ip(self.get_ip_from_data_safely(row))) is not None
                    else _default_datetime
                )
                for row, _ in combined
            }

            combined.sort(
                key=lambda row: _ip_datetime_map[self.get_ip_from_data_safely(row[0])],
                reverse=not sort_order_bool,
            )
        elif sorted_column_name == 'T. Session Time':
            # Precompute total session time values once to avoid O(n log n) registry lookups in the sort key
            _ip_total_session_time_map: dict[str, timedelta] = {
                self.get_ip_from_data_safely(row): (
                    matched_player.datetime.get_total_session_time()
                    if (matched_player := PlayersRegistry.get_player_by_ip(self.get_ip_from_data_safely(row))) is not None
                    else timedelta(0)
                )
                for row, _ in combined
            }

            combined.sort(
                key=lambda row: _ip_total_session_time_map[self.get_ip_from_data_safely(row[0])],
                reverse=sort_order_bool,
            )
        elif sorted_column_name == 'Session Time':
            # Precompute session time values once to avoid O(n log n) registry lookups in the sort key
            _ip_session_time_map: dict[str, timedelta] = {
                self.get_ip_from_data_safely(row): (
                    matched_player.datetime.get_session_time()
                    if (matched_player := PlayersRegistry.get_player_by_ip(self.get_ip_from_data_safely(row))) is not None
                    else timedelta(0)
                )
                for row, _ in combined
            }

            combined.sort(
                key=lambda row: (
                    _ip_session_time_map[self.get_ip_from_data_safely(row[0])],
                    ipaddress.ip_address(self.get_ip_from_data_safely(row[0])),
                ),
                reverse=sort_order_bool,
            )
        elif sorted_column_name in {
            'Rejoins',
            *PACKET_STAT_COLUMNS,
            'PPS',
            'PPM',
            'Last Port',
            'First Port',
        }:
            # Sort by integer/float value of the column value
            combined.sort(
                key=lambda row: float(row[0][column]),
                reverse=sort_order_bool,
            )
        elif sorted_column_name in BANDWIDTH_RATE_STAT_COLUMNS:
            # Precompute bandwidth values once to avoid O(n log n) registry lookups in the sort key
            _bandwidth_attr_map = {
                **BANDWIDTH_BASE_COLUMN_ATTRS,
                'BPS': 'bandwidth.bps.calculated_rate',
                'BPM': 'bandwidth.bpm.calculated_rate',
            }
            _bw_attr = _bandwidth_attr_map[sorted_column_name]
            _ip_bandwidth_map: dict[str, int] = {
                self.get_ip_from_data_safely(row): (
                    attrgetter(_bw_attr)(matched_player) if (matched_player := PlayersRegistry.get_player_by_ip(self.get_ip_from_data_safely(row))) is not None else 0
                )
                for row, _ in combined
            }

            combined.sort(
                key=lambda row: _ip_bandwidth_map[self.get_ip_from_data_safely(row[0])],
                reverse=sort_order_bool,
            )
        elif sorted_column_name == 'Middle Ports':
            # Sort by the number of ports in the list (length)
            combined.sort(
                key=lambda row: len(row[0][column]),
                reverse=sort_order_bool,
            )
        elif sorted_column_name in {'Lat', 'Lon', 'Offset'}:
            # Sort by integer/float value of the column value but keep "..." at the end
            combined.sort(
                key=lambda row: float(row[0][column]) if row[0][column] != '...' else float('-inf'),
                reverse=sort_order_bool,
            )
        elif sorted_column_name == 'IP Address':
            # Sort by numeric IP address value
            combined.sort(
                key=lambda row: ipaddress.ip_address(self.get_ip_from_data_safely(row[0])),
                reverse=sort_order_bool,
            )
        elif sorted_column_name in {
            'Hostname',
            *LOCATION_COLUMNS,
            *ORGANIZATION_COLUMNS,
            *STATUS_COLUMNS,
        }:
            # Sort by string representation of the column value
            combined.sort(
                key=lambda row: str(row[0][column]).casefold(),
                reverse=sort_order_bool,
            )
        else:
            raise UnsupportedSortColumnError(sorted_column_name)

        # Unpack the sorted data
        self._data, self._compiled_colors = map(list, zip(*combined, strict=True))
        self._rebuild_ip_index()

        self.layoutChanged.emit()

    # --------------------------------------------------------------------------
    # Custom / internal management methods
    # --------------------------------------------------------------------------

    def _rebuild_ip_index(self) -> None:
        """Rebuild the IP-to-row-index cache from current data."""
        self._ip_to_row_index = {self.get_ip_from_data_safely(row): i for i, row in enumerate(self._data)}

    def get_column_index(self, column_name: str, /) -> int | None:
        """Get the table index of a specified column, or None if not present.

        Args:
            column_name: The column name to look for.

        Returns:
            The column index, or None if the column is not visible.
        """
        try:
            return self._headers.index(column_name)
        except ValueError:
            return None

    def get_row_index_by_ip(self, ip: str, /) -> int | None:
        """Find the row index for the given IP address.

        Args:
            ip: The IP address to search for.

        Returns:
            The index of the row containing the IP address, or None if not found.
        """
        return self._ip_to_row_index.get(ip)

    def get_ip_for_row(self, row: int, /) -> str:
        """Return the IP address for the given row index.

        Args:
            row: The row index.

        Returns:
            The IP address string for the row.

        Raises:
            IndexError: If the row index is out of bounds.
        """
        return self.get_ip_from_data_safely(self._data[row])

    def get_all_ips(self) -> list[str]:
        """Return the IP address for every row currently in the model."""
        return [self.get_ip_from_data_safely(row_data) for row_data in self._data]

    def get_ip_from_data_safely(self, row_data: list[str]) -> str:
        """Safely extract an IP address as a string from row data.

        This method ensures the IP address is always returned as a string type.

        Args:
            row_data: The row data list containing the IP address.

        Returns:
            The IP address as a clean string (with crown suffix removed if present).

        Raises:
            IndexError: If the IP column index is out of bounds.
            TypeError: If the IP data is not a string.
        """
        if self.ip_column_index >= len(row_data):
            message = f'IP column index {self.ip_column_index} is out of bounds for row data with {len(row_data)} columns'
            raise IndexError(message)

        ip_data = row_data[self.ip_column_index]

        return self._remove_session_host_crown_from_ip(ip_data)

    def get_display_text(self, index: QModelIndex) -> str | None:
        """Extract display text as a string from model data.

        This method handles the case where model data might return `str`, `QBrush`, `QIcon` or `None` for decoration roles, but we only want the display text as a string.<br>
        For 'IP Address' column, it automatically removes the session host crown suffix (👑) if present.

        Args:
            index: The QModelIndex to get display text from.

        Returns:
            The display text as a string, or `None` if no valid display text is available.
            For the 'IP Address' column, the crown suffix is automatically removed.

        Raises:
            TypeError: If the display data is not a string and is not `None`.
        """
        # Explicitly request DisplayRole to get only the text content
        display_data = self.data(index, Qt.ItemDataRole.DisplayRole)
        if display_data is None:
            return None
        if not isinstance(display_data, str):
            raise TypeError(format_type_error(display_data, str))

        # If this is an IP Address column, remove the crown suffix
        if index.column() == self.ip_column_index:
            return self._remove_session_host_crown_from_ip(display_data)

        return display_data

    def add_row_without_refresh(self, row_data: list[str], row_colors: list[CellColor]) -> None:
        """Add a new row to the model without notifying the view in real time.

        Args:
            row_data: The data for the new row.
            row_colors: A list of `CellColor` objects corresponding to the row's colors.
        """
        # Only update internal data without triggering signals
        row_index = len(self._data)
        self._data.append(row_data)
        self._compiled_colors.append(row_colors)
        ip = self.get_ip_from_data_safely(row_data)
        self._ip_to_row_index[ip] = row_index

    def update_row_without_refresh(self, row_index: int, row_data: list[str], row_colors: list[CellColor]) -> None:
        """Update an existing row in the model with new data and colors without notifying the view in real time.

        Args:
            row_index: The index of the row to update.
            row_data: The new data for the row.
            row_colors: A list of `CellColor` objects corresponding to the row's colors.
        """
        if 0 <= row_index < self.rowCount():
            # Remove old IP mapping before updating
            old_ip = self.get_ip_from_data_safely(self._data[row_index])
            self._ip_to_row_index.pop(old_ip, None)
            self._data[row_index] = row_data
            self._compiled_colors[row_index] = row_colors
            new_ip = self.get_ip_from_data_safely(row_data)
            self._ip_to_row_index[new_ip] = row_index

    def delete_row(self, row_index: int) -> None:
        """Delete a row from the model along with its associated colors.

        If any items are selected under this row, their selection moves one row up.

        Args:
            row_index: The index of the row to delete.
        """
        if 0 <= row_index < self.rowCount():
            view = self.view
            selection_model = view.selectionModel()

            # Adjust selection for the deleted row
            for model_index in selection_model.selection().indexes():
                if model_index.row() == row_index:  # Row to be deleted
                    # Deselect the row because it's about to be deleted
                    # Select the row to be deleted
                    selection = QItemSelection(
                        self.index(model_index.row(), model_index.column()),
                        self.index(model_index.row(), model_index.column()),
                    )
                    selection_model.select(selection, QItemSelectionModel.SelectionFlag.Deselect)

            # Notify the view that rows are about to be removed
            self.beginRemoveRows(QModelIndex(), row_index, row_index)

            # Remove the data and compiled colors at the specified index
            self._data.pop(row_index)
            self._compiled_colors.pop(row_index)
            self._rebuild_ip_index()

            # Adjust selection for rows below the deleted one
            for model_index in selection_model.selection().indexes():
                if model_index.row() > row_index:  # Items below the deleted row
                    # Deselect the original row
                    selection_to_deselect = QItemSelection(
                        self.index(model_index.row(), model_index.column()),  # Original row
                        self.index(model_index.row(), model_index.column()),
                    )
                    selection_model.select(selection_to_deselect, QItemSelectionModel.SelectionFlag.Deselect)

                    # Move the selection up by one row
                    selection_to_select = QItemSelection(
                        self.index(model_index.row() - 1, model_index.column()),  # New row after deletion
                        self.index(model_index.row() - 1, model_index.column()),
                    )
                    selection_model.select(selection_to_select, QItemSelectionModel.SelectionFlag.Select)

            # Notify the view that the rows have been removed
            self.endRemoveRows()

            # NOTE: Fixes a weird UI bug that when someone leaves, it makes it an empty row
            if not self._data:
                # Begin resetting the model to indicate it's empty
                self.beginResetModel()
                self._data = []
                self._compiled_colors = []
                self._ip_to_row_index.clear()
                # End reset and notify the view that the model has been reset
                self.endResetModel()

            # Ensure the view resizes properly after a row is removed
            # view.resizeRowsToContents()
            # view.viewport().update()

    def reset_columns(self, headers: list[str] | None = None) -> None:
        """Replace column headers and clear all data.

        When *headers* is `None` the current headers are kept and only the
        row data is cleared (equivalent to the old `clear_all_data`).

        Args:
            headers: New column header labels, or `None` to keep the current ones.
        """
        self.beginResetModel()
        if headers is not None:
            self._headers = headers
            self._column_indices = _ColumnIndices(
                ip=self._headers.index('IP Address'),
                username=self._headers.index('Usernames'),
                country=self.get_column_index('Country'),
            )
        self._data = []
        self._compiled_colors = []
        self._ip_to_row_index.clear()
        self.endResetModel()

    def remove_player_by_ip(self, ip: str) -> None:
        """Remove a single player row from the table by IP address.

        Args:
            ip: The IP address of the player to remove.
        """
        row_index = self._ip_to_row_index.get(ip)
        if row_index is None:
            return

        # Remove the row
        self.beginRemoveRows(QModelIndex(), row_index, row_index)
        self._data.pop(row_index)
        if row_index < len(self._compiled_colors):
            self._compiled_colors.pop(row_index)
        self._rebuild_ip_index()
        self.endRemoveRows()

    def refresh_view(self) -> None:
        """Notifies the view to refresh and reflect all changes made to the model."""
        self.layoutAboutToBeChanged.emit()
        self.layoutChanged.emit()
