"""Session table model for connected and disconnected player tables."""

import ipaddress
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

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
)

from session_sniffer.error_messages import format_type_error
from session_sniffer.guis.exceptions import TableDataConsistencyError, UnsupportedSortColumnError
from session_sniffer.player.registry import PlayersRegistry

if TYPE_CHECKING:
    from session_sniffer.guis.tables import SessionTableView
    from session_sniffer.rendering_core.types import CellColor

GUI_COLUMN_HEADERS_TOOLTIPS = {
    'Usernames': (
        'Displays the username(s) of players from your UserIP database files.\n\n'
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
    'PPS': 'The number of Packets exchanged (Received + Sent) with the player Per Second during the current session.',
    'PPM': 'The number of Packets exchanged (Received + Sent) with the player Per Minute during the current session.',
    'T. Bandwith': 'The total amount of bytes transferred (Download + Upload) with the player across all sessions.',
    'Bandwith': 'The amount of bytes transferred (Download + Upload) with the player during the current session.',
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


class SessionTableModel(QAbstractTableModel):
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
        self._ip_column_index = self._headers.index('IP Address')
        self._username_column_index = self._headers.index('Usernames')

    # --------------------------------------------------------------------------
    # Public properties
    # --------------------------------------------------------------------------

    @classmethod
    def remove_session_host_crown_from_ip(cls, ip_address: str) -> str:
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
            error_message = 'SessionTableView is not attached to this model'
            raise TypeError(error_message)
        return self._view

    @view.setter
    def view(self, new_view: SessionTableView) -> None:
        """Attach a `SessionTableView` to this model."""
        self._view = new_view

    # --------------------------------------------------------------------------
    # Public read-only properties
    # --------------------------------------------------------------------------

    @property
    def ip_column_index(self) -> int:
        """Returns the index of the 'IP Address' column in this table model.

        This value is computed during initialization based on the `headers` provided.<br>
        It is read-only and specific to this instance.
        """
        return self._ip_column_index

    @property
    def username_column_index(self) -> int:
        """Returns the index of the 'Usernames' column in this table model.

        This value is computed during initialization based on the `headers` provided.<br>
        It is read-only and specific to this instance.
        """
        return self._username_column_index

    # --------------------------------------------------------------------------
    # Qt model methods (overrides)
    # --------------------------------------------------------------------------

    def rowCount(self, parent: QModelIndex | None = None) -> int:
        """Return number of rows in the model."""
        if parent is None:
            parent = QModelIndex()
        return len(self._data)

    def columnCount(self, parent: QModelIndex | None = None) -> int:
        """Return number of columns in the model."""
        if parent is None:
            parent = QModelIndex()
        return len(self._headers)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> str | QBrush | QIcon | None:
        """Override data method to customize data retrieval and alignment."""
        if not index.isValid():
            return None

        row_idx = index.row()
        col_idx = index.column()

        # Check bounds
        if row_idx >= len(self._data) or col_idx >= len(self._data[row_idx]):
            return None  # Return None for invalid index

        output: str | QBrush | QIcon | None = None

        if role == Qt.ItemDataRole.DecorationRole and self.has_column('Country') and self.get_column_index('Country') == col_idx:
            ip = self.get_ip_from_data_safely(self._data[row_idx])

            matched_player = PlayersRegistry.get_player_by_ip(ip)
            if matched_player is not None and matched_player.country_flag is not None:
                output = matched_player.country_flag.icon
        elif role == Qt.ItemDataRole.DisplayRole:
            # Return the cell's text
            output = self._data[row_idx][col_idx]
        elif role == Qt.ItemDataRole.ForegroundRole and row_idx < len(self._compiled_colors) and col_idx < len(self._compiled_colors[row_idx]):
            # Return the cell's foreground color
            output = QBrush(self._compiled_colors[row_idx][col_idx].foreground)
        elif role == Qt.ItemDataRole.BackgroundRole and row_idx < len(self._compiled_colors) and col_idx < len(self._compiled_colors[row_idx]):
            # Return the cell's background color
            output = QBrush(self._compiled_colors[row_idx][col_idx].background)
        elif role == Qt.ItemDataRole.ToolTipRole:
            # Return the tooltip text for the cell
            view = self.view
            horizontal_header = view.horizontalHeader()
            resize_mode = horizontal_header.sectionResizeMode(index.column())

            # Return None if the column resize mode isn't set to Stretch, as it shouldn't be truncated
            if resize_mode == QHeaderView.ResizeMode.Stretch:
                cell_text = self._data[row_idx][col_idx]

                font_metrics = view.fontMetrics()
                text_width = font_metrics.horizontalAdvance(cell_text)
                column_width = view.columnWidth(index.column())

                if text_width > column_width - self.TABLE_CELL_TOOLTIP_MARGIN:
                    output = cell_text

        return output

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

    def flags(self, index: QModelIndex) -> Qt.ItemFlag:
        """Return Qt flags controlling whether the item is enabled/selectable."""
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags

        return Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable

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
            # Sort by raw datetime values from player objects
            def extract_datetime_for_ip(ip: str) -> datetime:
                """Extract datetime value for a given IP address."""
                matched_player = PlayersRegistry.get_player_by_ip(ip)
                if matched_player is None:
                    return datetime.min.replace(tzinfo=UTC)

                datetime_mapping = {
                    'First Seen': matched_player.datetime.first_seen,
                    'Last Rejoin': matched_player.datetime.last_rejoin,
                    'Last Seen': matched_player.datetime.last_seen,
                }
                return datetime_mapping[sorted_column_name]

            combined.sort(
                key=lambda row: extract_datetime_for_ip(self.get_ip_from_data_safely(row[0])),
                reverse=not sort_order_bool,
            )
        elif sorted_column_name == 'T. Session Time':
            # Sort by total session time duration from player objects
            def extract_total_session_time_for_ip(ip: str) -> timedelta:
                """Extract total session time value for a given IP address."""
                matched_player = PlayersRegistry.get_player_by_ip(ip)
                if matched_player is None:
                    return timedelta(0)
                return matched_player.datetime.get_total_session_time()

            combined.sort(
                key=lambda row: extract_total_session_time_for_ip(self.get_ip_from_data_safely(row[0])),
                reverse=sort_order_bool,
            )
        elif sorted_column_name == 'Session Time':
            # Sort by session time duration from player objects
            def extract_session_time_for_ip(ip: str) -> timedelta:
                """Extract session time value for a given IP address."""
                matched_player = PlayersRegistry.get_player_by_ip(ip)
                if matched_player is None:
                    return timedelta(0)
                return matched_player.datetime.get_session_time()

            combined.sort(
                key=lambda row: extract_session_time_for_ip(self.get_ip_from_data_safely(row[0])),
                reverse=sort_order_bool,
            )
        elif sorted_column_name == 'IP Address':
            combined.sort(
                key=lambda row: ipaddress.ip_address(self.get_ip_from_data_safely(row[0])),
                reverse=sort_order_bool,
            )
        elif sorted_column_name in {
            'Rejoins',
            'T. Packets', 'Packets', 'T. Packets Sent', 'Packets Sent', 'T. Packets Received', 'Packets Received', 'PPS', 'PPM',
            'Last Port', 'First Port',
        }:
            # Sort by integer/float value of the column value
            combined.sort(
                key=lambda row: float(row[0][column]),
                reverse=sort_order_bool,
            )
        elif sorted_column_name in {
            'T. Bandwith', 'Bandwith', 'T. Download', 'Download', 'T. Upload', 'Upload', 'BPS', 'BPM',
        }:
            # Sort by raw bandwidth integer values from player objects
            def extract_bandwidth_for_ip(ip: str) -> int:
                """Extract bandwidth value for a given IP address."""
                matched_player = PlayersRegistry.get_player_by_ip(ip)
                if matched_player is None:
                    return 0

                bandwidth_mapping = {
                    'T. Bandwith': matched_player.bandwidth.total_exchanged,
                    'Bandwith': matched_player.bandwidth.exchanged,
                    'T. Download': matched_player.bandwidth.total_download,
                    'Download': matched_player.bandwidth.download,
                    'T. Upload': matched_player.bandwidth.total_upload,
                    'Upload': matched_player.bandwidth.upload,
                    'BPS': matched_player.bandwidth.bps.calculated_rate,
                    'BPM': matched_player.bandwidth.bpm.calculated_rate,
                }
                return bandwidth_mapping[sorted_column_name]

            combined.sort(
                key=lambda row: extract_bandwidth_for_ip(self.get_ip_from_data_safely(row[0])),
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
        elif sorted_column_name in {
            'Hostname', 'Continent', 'Country', 'Region', 'R. Code', 'City', 'District', 'ZIP Code',
            'Time Zone', 'Currency', 'Organization', 'ISP', 'ASN / ISP', 'AS', 'ASN',
        }:
            # Sort by string representation of the column value
            combined.sort(
                key=lambda row: str(row[0][column]).casefold(),
                reverse=sort_order_bool,
            )
        elif sorted_column_name in {'Mobile', 'VPN', 'Hosting', 'Pinging'}:
            # Sort by boolean representation of the column value
            combined.sort(
                key=lambda row: str(row[0][column]).casefold(),
                reverse=sort_order_bool,
            )
        else:
            raise UnsupportedSortColumnError(sorted_column_name)

        # Unpack the sorted data
        self._data, self._compiled_colors = map(list, zip(*combined, strict=True))

        self.layoutChanged.emit()

    # --------------------------------------------------------------------------
    # Custom / internal management methods
    # --------------------------------------------------------------------------

    def has_column(self, column_name: str, /) -> bool:
        """Check if a column is visible in the table.

        Args:
            column_name: The column name to check.

        Returns:
            Whether the column exists.
        """
        return column_name in self._headers

    def get_column_index(self, column_name: str, /) -> int:
        """Get the table index of a specified column.

        Args:
            column_name: The column name to look for.

        Returns:
            The column index.

        Raises:
            ValueError: If the column is not visible.
        """
        return self._headers.index(column_name)

    def get_row_index_by_ip(self, ip: str, /) -> int | None:
        """Find the row index for the given IP address.

        Args:
            ip: The IP address to search for.

        Returns:
            The index of the row containing the IP address, or None if not found.
        """
        for row_index, row_data in enumerate(self._data):
            if self.get_ip_from_data_safely(row_data) == ip:
                return row_index
        return None

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
            error_msg = f'IP column index {self.ip_column_index} is out of bounds for row data with {len(row_data)} columns'
            raise IndexError(error_msg)

        ip_data = row_data[self.ip_column_index]

        return self.remove_session_host_crown_from_ip(ip_data)

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
            return self.remove_session_host_crown_from_ip(display_data)

        return display_data

    def sort_current_column(self) -> None:
        """Call the sort method with the current column index and order.

        Ensures sorting reflects the current state of the header.
        """
        # Retrieve the current sort column and order
        horizontal_header = self.view.horizontalHeader()
        sort_column = horizontal_header.sortIndicatorSection()
        sort_order = horizontal_header.sortIndicatorOrder()

        # Call the sort function with the retrieved arguments
        self.sort(sort_column, sort_order)

    def add_row_without_refresh(self, row_data: list[str], row_colors: list[CellColor]) -> None:
        """Add a new row to the model without notifying the view in real time.

        Args:
            row_data: The data for the new row.
            row_colors: A list of `CellColor` objects corresponding to the row's colors.
        """
        # Only update internal data without triggering signals
        self._data.append(row_data)
        self._compiled_colors.append(row_colors)

    def update_row_without_refresh(self, row_index: int, row_data: list[str], row_colors: list[CellColor]) -> None:
        """Update an existing row in the model with new data and colors without notifying the view in real time.

        Args:
            row_index: The index of the row to update.
            row_data: The new data for the row.
            row_colors: A list of `CellColor` objects corresponding to the row's colors.
        """
        if 0 <= row_index < self.rowCount():
            self._data[row_index] = row_data
            self._compiled_colors[row_index] = row_colors

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
            for index in selection_model.selection().indexes():
                if index.row() == row_index:  # Row to be deleted
                    # Deselect the row because it's about to be deleted
                    # Select the row to be deleted
                    selection = QItemSelection(
                        self.index(index.row(), index.column()),
                        self.index(index.row(), index.column()),
                    )
                    selection_model.select(selection, QItemSelectionModel.SelectionFlag.Deselect)

            # Notify the view that rows are about to be removed
            self.beginRemoveRows(self.index(row_index, 0), row_index, row_index)

            # Remove the data and compiled colors at the specified index
            self._data.pop(row_index)
            self._compiled_colors.pop(row_index)

            # Adjust selection for rows below the deleted one
            for index in selection_model.selection().indexes():
                if index.row() > row_index:  # Items below the deleted row
                    # Deselect the original row
                    selection_to_deselect = QItemSelection(
                        self.index(index.row(), index.column()),  # Original row
                        self.index(index.row(), index.column()),
                    )
                    selection_model.select(selection_to_deselect, QItemSelectionModel.SelectionFlag.Deselect)

                    # Move the selection up by one row
                    selection_to_select = QItemSelection(
                        self.index(index.row() - 1, index.column()),  # New row after deletion
                        self.index(index.row() - 1, index.column()),
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
                # End reset and notify the view that the model has been reset
                self.endResetModel()

            # Ensure the view resizes properly after a row is removed
            # view.resizeRowsToContents()
            # view.viewport().update()

    def clear_all_data(self) -> None:
        """Clear all data from the table model."""
        self.beginResetModel()
        self._data = []
        self._compiled_colors = []
        self.endResetModel()

    def remove_player_by_ip(self, ip: str) -> None:
        """Remove a single player row from the table by IP address.

        Args:
            ip: The IP address of the player to remove.
        """
        # Find the row containing this IP address
        for row_idx, row_data in enumerate(self._data):
            row_ip = self.get_ip_from_data_safely(row_data)
            if row_ip == ip:
                # Remove the row
                self.beginRemoveRows(QModelIndex(), row_idx, row_idx)
                self._data.pop(row_idx)
                if row_idx < len(self._compiled_colors):
                    self._compiled_colors.pop(row_idx)
                self.endRemoveRows()
                break

    def refresh_view(self) -> None:
        """Notifies the view to refresh and reflect all changes made to the model."""
        self.layoutAboutToBeChanged.emit()
        self.layoutChanged.emit()
