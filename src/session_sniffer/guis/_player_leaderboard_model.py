"""Data and sorting models for the Most Seen Players leaderboard window."""

from datetime import datetime
from typing import TYPE_CHECKING, ClassVar, override

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QPersistentModelIndex,
    QSortFilterProxyModel,
    Qt,
)
from PySide6.QtGui import QColor, QIcon

from session_sniffer.constants.standard import LOCAL_TZ
from session_sniffer.guis.tables_player_actions._format import format_bool
from session_sniffer.guis.utils import load_country_flag_icon
from session_sniffer.text_utils import pluralize

if TYPE_CHECKING:
    from collections.abc import Callable

    from session_sniffer.player.seen_stats import LeaderboardEntry

SCOPE_TODAY = 'Today'
SCOPE_THIS_WEEK = 'This Week'
SCOPE_THIS_MONTH = 'This Month'
SCOPE_THIS_YEAR = 'This Year'
SCOPE_ALL_TIME = 'All Time'

SCOPES = (SCOPE_TODAY, SCOPE_THIS_WEEK, SCOPE_THIS_MONTH, SCOPE_THIS_YEAR, SCOPE_ALL_TIME)

MODE_DAYS = 'Unique Days'
MODE_SESSIONS = 'Sessions'
MODES = (MODE_DAYS, MODE_SESSIONS)

HEADERS = (
    'Rank',
    'Status',
    'Usernames',
    'IP Address',
    'Sessions',
    'First Seen',
    'Last Seen',
    'Country',
    'ISP',
    'Mobile',
    'VPN',
    'Hosting',
)

# Header tooltips, parallel to `HEADERS`. The Days/Sessions column (index 4) is described dynamically in `headerData`.
HEADER_TOOLTIPS = (
    'Leaderboard position (row number) for the current sort order, time period and count mode.',
    'Current session connection status (Connected, Disconnected, or not in the active session).',
    'In-game usernames seen for this player across all recorded sessions, ordered from most recent to oldest seen (left to right).',
    "The player's IP address.",
    'How often this player was seen within the selected time period.',
    'The earliest time this player was ever recorded across all session logs.',
    'The most recent time this player was recorded across all session logs.',
    'Country the IP address geolocates to.',
    'Internet Service Provider that owns the IP address.',
    'Whether the IP is a mobile/cellular connection.',
    'Whether the IP is flagged as a VPN or proxy.',
    'Whether the IP belongs to a hosting/datacenter provider.',
)

SEARCH_COLUMN_ALL = 'All Columns'
SEARCH_COLUMN_USERNAMES = 'Usernames'
SEARCH_COLUMN_IP = 'IP Address'
SEARCH_COLUMN_COUNTRY = 'Country'
SEARCH_COLUMN_ISP = 'ISP'

SEARCH_COLUMNS = (
    SEARCH_COLUMN_ALL,
    SEARCH_COLUMN_USERNAMES,
    SEARCH_COLUMN_IP,
    SEARCH_COLUMN_COUNTRY,
    SEARCH_COLUMN_ISP,
)

COLUMN_RANK = 0
COLUMN_STATUS = 1
COLUMN_USERNAMES = 2
COLUMN_IP = 3
COLUMN_SESSIONS = 4
COLUMN_FIRST_SEEN = 5
COLUMN_LAST_SEEN = 6
COLUMN_COUNTRY = 7
COLUMN_ISP = 8
COLUMN_MOBILE = 9
COLUMN_VPN = 10
COLUMN_HOSTING = 11

SEARCH_COLUMN_TO_INDEX: dict[str, int] = {
    SEARCH_COLUMN_ALL: -1,
    SEARCH_COLUMN_USERNAMES: COLUMN_USERNAMES,
    SEARCH_COLUMN_IP: COLUMN_IP,
    SEARCH_COLUMN_COUNTRY: COLUMN_COUNTRY,
    SEARCH_COLUMN_ISP: COLUMN_ISP,
}


def get_flag_icon(country_code: str) -> QIcon | None:
    """Return a cached QIcon for the given ISO country code, or None if unavailable."""
    return load_country_flag_icon(country_code) if country_code else None


def format_datetime(dt: datetime | None) -> str:
    """Format a datetime for display, returning empty string for None."""
    if dt is None:
        return ''
    return dt.strftime('%m/%d/%Y %H:%M')


_SECONDS_PER_MINUTE: int = 60
_SECONDS_PER_DAY: int = 86400
_SECONDS_PER_TWO_DAYS: int = 172800

_TIME_UNITS: tuple[tuple[int, str, int], ...] = (
    (31536000, 'year', 31536000),
    (2592000, 'month', 2592000),
    (604800, 'week', 604800),
    (_SECONDS_PER_DAY, 'day', _SECONDS_PER_DAY),
    (3600, 'hour', 3600),
    (_SECONDS_PER_MINUTE, 'min', _SECONDS_PER_MINUTE),
)


def format_relative_datetime(dt: datetime | None) -> str:
    """Format a datetime as a natural relative time string (e.g., '2 days ago', '3 months ago')."""
    if dt is None:
        return ''
    now = datetime.now(tz=dt.tzinfo if dt.tzinfo is not None else LOCAL_TZ)
    if dt.tzinfo is None:
        now = now.replace(tzinfo=None)
    seconds = int((now - dt).total_seconds())
    if seconds < _SECONDS_PER_MINUTE:
        return 'Just now'
    if _SECONDS_PER_DAY <= seconds < _SECONDS_PER_TWO_DAYS:
        return 'Yesterday'
    for threshold, unit, unit_seconds in _TIME_UNITS:
        if seconds >= threshold:
            unit_count = seconds // unit_seconds
            return f'{unit_count} {unit}{pluralize(unit_count)} ago'
    return 'Just now'


class LeaderboardTableModel(QAbstractTableModel):
    """Table model representing player leaderboard rows."""

    _SCOPE_ATTR_DAYS: ClassVar[dict[str, str]] = {
        SCOPE_TODAY: 'days_today',
        SCOPE_THIS_WEEK: 'days_week',
        SCOPE_THIS_MONTH: 'days_month',
        SCOPE_THIS_YEAR: 'days_year',
        SCOPE_ALL_TIME: 'days_total',
    }

    _SCOPE_ATTR_SESSIONS: ClassVar[dict[str, str]] = {
        SCOPE_TODAY: 'sessions_today',
        SCOPE_THIS_WEEK: 'sessions_week',
        SCOPE_THIS_MONTH: 'sessions_month',
        SCOPE_THIS_YEAR: 'sessions_year',
        SCOPE_ALL_TIME: 'sessions_total',
    }

    _CENTER_COLUMNS: ClassVar[frozenset[int]] = frozenset(
        {
            COLUMN_RANK,
            COLUMN_STATUS,
            COLUMN_SESSIONS,
            COLUMN_MOBILE,
            COLUMN_VPN,
            COLUMN_HOSTING,
        }
    )

    def __init__(self) -> None:
        super().__init__()
        self._entries: list[LeaderboardEntry] = []
        self._index_by_ip: dict[str, int] = {}
        self._connected_ips: frozenset[str] = frozenset()
        self._disconnected_ips: frozenset[str] = frozenset()
        self._scope: str = SCOPE_ALL_TIME
        self._mode: str = MODE_DAYS
        self._scope_attr: str = 'days_total'
        self._relative_dates: bool = True
        self._username_cache: dict[str, str] = {}
        # Bound method dispatch — avoids per-cell getattr() overhead
        self._display_dispatch: dict[int, Callable[[int, LeaderboardEntry], object]] = {
            COLUMN_RANK: self._display_rank,
            COLUMN_STATUS: self._display_status,
            COLUMN_USERNAMES: self._display_usernames,
            COLUMN_IP: self._display_ip,
            COLUMN_SESSIONS: self._display_sessions,
            COLUMN_FIRST_SEEN: self._display_first_seen,
            COLUMN_LAST_SEEN: self._display_last_seen,
            COLUMN_COUNTRY: self._display_country,
            COLUMN_ISP: self._display_isp,
            COLUMN_MOBILE: self._display_mobile,
            COLUMN_VPN: self._display_vpn,
            COLUMN_HOSTING: self._display_hosting,
        }

    @override
    def rowCount(self, parent: QModelIndex | QPersistentModelIndex | None = None) -> int:
        """Return the number of leaderboard entries."""
        if parent is None:
            parent = QModelIndex()
        return len(self._entries)

    @override
    def columnCount(self, parent: QModelIndex | QPersistentModelIndex | None = None) -> int:
        """Return the number of columns."""
        if parent is None:
            parent = QModelIndex()
        return len(HEADERS)

    @override
    def data(self, index: QModelIndex | QPersistentModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> object:
        """Return cell data for the given index and role."""
        if not index.isValid():
            return None

        entry = self._entries[index.row()]
        column = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            method = self._display_dispatch.get(column)
            return method(index.row(), entry) if method is not None else None

        return self._non_display_data(entry, column, role)

    def _non_display_data(self, entry: LeaderboardEntry, column: int, role: int) -> object:
        if role == Qt.ItemDataRole.TextAlignmentRole:
            return Qt.AlignmentFlag.AlignCenter if column in self._CENTER_COLUMNS else Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        if role == Qt.ItemDataRole.ForegroundRole and column == COLUMN_STATUS:
            return self._status_foreground_color(entry.ip)
        if role == Qt.ItemDataRole.UserRole and column == COLUMN_SESSIONS:
            return self.get_session_count(entry)
        if role == Qt.ItemDataRole.ToolTipRole:
            return self._tooltip_data(column, entry)
        if role == Qt.ItemDataRole.DecorationRole and column == COLUMN_COUNTRY:
            return get_flag_icon(entry.country_code)
        return None

    def _status_foreground_color(self, ip_address: str) -> QColor:
        if ip_address in self._connected_ips:
            return QColor('#22c55e')
        if ip_address in self._disconnected_ips:
            return QColor('#ef4444')
        return QColor('#6b7280')

    def _tooltip_data(self, column: int, entry: LeaderboardEntry) -> object:
        if column in (COLUMN_FIRST_SEEN, COLUMN_LAST_SEEN):
            dt_val = entry.first_seen if column == COLUMN_FIRST_SEEN else entry.last_seen
            if dt_val is None:
                return None
            return f'Exact time: {format_datetime(dt_val)}' if self._relative_dates else format_relative_datetime(dt_val)
        if column == COLUMN_SESSIONS:
            count = self.get_session_count(entry)
            return (
                f'{count} unique calendar day(s) this player was seen within the selected time period'
                if self._mode == MODE_DAYS
                else f'{count} sniffer session(s) in which this player was seen within the selected time period'
            )
        return None

    @override
    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> object:
        """Return column header labels and tooltips."""
        if orientation != Qt.Orientation.Horizontal:
            return None
        if role == Qt.ItemDataRole.DisplayRole:
            if section == COLUMN_SESSIONS:
                return 'Days' if self._mode == MODE_DAYS else 'Sessions'
            return HEADERS[section]
        if role == Qt.ItemDataRole.ToolTipRole:
            if section == COLUMN_SESSIONS:
                return (
                    'Number of unique calendar days this player was seen within the selected time period.'
                    if self._mode == MODE_DAYS
                    else 'Number of sniffer sessions in which this player was seen within the selected time period.'
                )
            return HEADER_TOOLTIPS[section]
        return None

    # Display helpers --------------------------------------------------------

    @staticmethod
    def _display_rank(row: int, _entry: LeaderboardEntry) -> int:
        return row + 1

    def _display_status(self, _row: int, entry: LeaderboardEntry) -> str:
        if entry.ip in self._connected_ips:
            return 'Connected'
        if entry.ip in self._disconnected_ips:
            return 'Disconnected'
        return '—'

    @staticmethod
    def _display_ip(_row: int, entry: LeaderboardEntry) -> str:
        return entry.ip

    @staticmethod
    def _display_usernames(_row: int, entry: LeaderboardEntry) -> str:
        return ', '.join(entry.usernames) if entry.usernames else ''

    def _display_sessions(self, _row: int, entry: LeaderboardEntry) -> int:
        return self.get_session_count(entry)

    def _display_first_seen(self, _row: int, entry: LeaderboardEntry) -> str:
        return format_relative_datetime(entry.first_seen) if self._relative_dates else format_datetime(entry.first_seen)

    def _display_last_seen(self, _row: int, entry: LeaderboardEntry) -> str:
        return format_relative_datetime(entry.last_seen) if self._relative_dates else format_datetime(entry.last_seen)

    @staticmethod
    def _display_country(_row: int, entry: LeaderboardEntry) -> str:
        return entry.country or 'N/A'

    @staticmethod
    def _display_isp(_row: int, entry: LeaderboardEntry) -> str:
        return entry.isp or 'N/A'

    @staticmethod
    def _display_mobile(_row: int, entry: LeaderboardEntry) -> str:
        return format_bool(entry.mobile)

    @staticmethod
    def _display_vpn(_row: int, entry: LeaderboardEntry) -> str:
        return format_bool(entry.vpn)

    @staticmethod
    def _display_hosting(_row: int, entry: LeaderboardEntry) -> str:
        return format_bool(entry.hosting)

    def get_session_count(self, entry: LeaderboardEntry) -> int:
        """Return the days or session count for the current mode and time scope."""
        return int(getattr(entry, self._scope_attr))

    @property
    def entries(self) -> list[LeaderboardEntry]:
        """Return the current entries list (read-only access for the sort proxy)."""
        return self._entries

    def load_data(self, entries: list[LeaderboardEntry]) -> None:
        """Replace the model data with new leaderboard entries."""
        self.beginResetModel()
        self._entries = entries
        self._index_by_ip = {entry.ip: i for i, entry in enumerate(entries)}
        self.endResetModel()

    def apply_live_update(self, entries: list[LeaderboardEntry]) -> None:
        """Refresh in place from a live overlay: update only changed rows and append newly-seen players.

        Row positions are kept stable so the sort proxy re-sorts and the user's selection and scroll
        position survive. Only rows whose values actually changed emit `dataChanged`, so identical
        ticks (the common case within a run) cost nothing and never trigger a full re-sort.
        """
        updated_by_ip = {entry.ip: entry for entry in entries}

        changed_rows: list[int] = []
        for ip, row in self._index_by_ip.items():
            updated = updated_by_ip.get(ip)
            if updated is not None and updated != self._entries[row]:
                self._entries[row] = updated
                changed_rows.append(row)

        new_entries = [entry for entry in entries if entry.ip not in self._index_by_ip]
        if new_entries:
            first_new_row = len(self._entries)
            self.beginInsertRows(QModelIndex(), first_new_row, first_new_row + len(new_entries) - 1)
            for entry in new_entries:
                self._index_by_ip[entry.ip] = len(self._entries)
                self._entries.append(entry)
            self.endInsertRows()

        for row in changed_rows:
            top_left = self.index(row, 0)
            bottom_right = self.index(row, self.columnCount() - 1)
            self.dataChanged.emit(top_left, bottom_right)

    def set_scope(self, scope: str) -> None:
        """Change the active time scope and refresh the model."""
        self._scope = scope
        self._refresh_scope_attr()
        self.beginResetModel()
        self.endResetModel()

    def set_mode(self, mode: str) -> None:
        """Switch between Unique Days and Sessions counting modes."""
        self._mode = mode
        self._refresh_scope_attr()
        self.beginResetModel()
        self.endResetModel()
        self.headerDataChanged.emit(Qt.Orientation.Horizontal, COLUMN_SESSIONS, COLUMN_SESSIONS)

    def set_relative_dates(self, relative: bool) -> None:  # noqa: FBT001
        """Toggle relative date formatting for First Seen and Last Seen columns."""
        if self._relative_dates == relative:
            return
        self._relative_dates = relative
        self.beginResetModel()
        self.endResetModel()

    def set_current_session_ips(self, connected_ips: frozenset[str], disconnected_ips: frozenset[str]) -> None:
        """Update active session connection status for players in the model."""
        if connected_ips == self._connected_ips and disconnected_ips == self._disconnected_ips:
            return
        self._connected_ips = connected_ips
        self._disconnected_ips = disconnected_ips
        if self._entries:
            top_left = self.index(0, COLUMN_STATUS)
            bottom_right = self.index(len(self._entries) - 1, COLUMN_STATUS)
            self.dataChanged.emit(top_left, bottom_right)

    def _refresh_scope_attr(self) -> None:
        scope_map = self._SCOPE_ATTR_DAYS if self._mode == MODE_DAYS else self._SCOPE_ATTR_SESSIONS
        default = 'days_total' if self._mode == MODE_DAYS else 'sessions_total'
        self._scope_attr = scope_map.get(self._scope, default)


class LeaderboardSortProxy(QSortFilterProxyModel):
    """Proxy that filters out zero-session entries and supports custom sorting."""

    def __init__(self) -> None:
        super().__init__()
        self._search_text: str = ''
        self._search_column: str = SEARCH_COLUMN_ALL
        self._hide_servers: bool = False
        self._server_ips: frozenset[str] = frozenset()
        self._hide_vpns: bool = False
        self._hide_hosting: bool = False
        self._current_session_only: bool = False
        self._connected_ips: frozenset[str] = frozenset()
        self._disconnected_ips: frozenset[str] = frozenset()

    @property
    def current_session_ips(self) -> frozenset[str]:
        """Return the combined set of connected and disconnected IPs in the active session."""
        return self._connected_ips | self._disconnected_ips

    @override
    def data(self, index: QModelIndex | QPersistentModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> object:
        """Render the Rank column as the current visible position; delegate everything else to the source model."""
        if role == Qt.ItemDataRole.DisplayRole and index.column() == COLUMN_RANK:
            return index.row() + 1
        return super().data(index, role)

    def set_search_text(self, text: str) -> None:
        """Update the search filter text and re-evaluate visible rows."""
        self._search_text = text.strip().lower()
        self.invalidateFilter()

    def set_search_column(self, column: str) -> None:
        """Update which column is searched and re-evaluate visible rows."""
        self._search_column = column
        self.invalidateFilter()

    def set_hide_servers(self, hide: bool) -> None:  # noqa: FBT001
        """Toggle hiding of known third-party game/relay server IPs."""
        self._hide_servers = hide
        self.invalidateFilter()

    def set_server_ips(self, server_ips: frozenset[str]) -> None:
        """Update the set of known server IPs; re-filter only if it changed while hiding is active."""
        if server_ips == self._server_ips:
            return
        self._server_ips = server_ips
        if self._hide_servers:
            self.invalidateFilter()

    def set_hide_vpns(self, hide: bool) -> None:  # noqa: FBT001
        """Toggle hiding of IPs flagged as VPNs/proxies."""
        self._hide_vpns = hide
        self.invalidateFilter()

    def set_hide_hosting(self, hide: bool) -> None:  # noqa: FBT001
        """Toggle hiding of IPs flagged as hosting/datacenter providers."""
        self._hide_hosting = hide
        self.invalidateFilter()

    def set_current_session_only(self, enabled: bool) -> None:  # noqa: FBT001
        """Toggle filtering to only players in the active session."""
        self._current_session_only = enabled
        self.invalidateFilter()

    def set_current_session_ips(self, connected_ips: frozenset[str], disconnected_ips: frozenset[str]) -> None:
        """Update active session IPs and invalidate filter if filtering is active."""
        if connected_ips == self._connected_ips and disconnected_ips == self._disconnected_ips:
            return
        self._connected_ips = connected_ips
        self._disconnected_ips = disconnected_ips
        if self._current_session_only:
            self.invalidateFilter()

    def _entry_matches_search(self, entry: LeaderboardEntry, text: str) -> bool:
        """Return True if *entry* contains *text* within the active search column."""
        if self._search_column == SEARCH_COLUMN_ALL:
            return text in entry.ip.lower() or any(text in username.lower() for username in entry.usernames) or text in entry.country.lower() or text in entry.isp.lower()
        if self._search_column == SEARCH_COLUMN_USERNAMES:
            return any(text in username.lower() for username in entry.usernames)
        targets: dict[str, str] = {
            SEARCH_COLUMN_IP: entry.ip,
            SEARCH_COLUMN_COUNTRY: entry.country,
            SEARCH_COLUMN_ISP: entry.isp,
        }
        return text in targets.get(self._search_column, '').lower()

    def _is_hidden(self, entry: LeaderboardEntry) -> bool:
        """Return True if any active filter (servers/VPNs/hosting) excludes *entry*."""
        if self._hide_servers and entry.ip in self._server_ips:
            return True
        if self._hide_vpns and entry.vpn is True:
            return True
        return self._hide_hosting and entry.hosting is True

    @override
    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex | QPersistentModelIndex) -> bool:
        """Reject rows with hidden servers/VPNs/hosting, outside active session, zero count, or search mismatch."""
        _ = source_parent
        model = self.sourceModel()
        if not isinstance(model, LeaderboardTableModel):
            return True
        entry = model.entries[source_row]
        if self._current_session_only and entry.ip not in self.current_session_ips:
            return False
        if not model.get_session_count(entry):
            return False
        if self._is_hidden(entry):
            return False
        if self._search_text:
            return self._entry_matches_search(entry, self._search_text)
        return True

    @override
    def lessThan(self, left: QModelIndex | QPersistentModelIndex, right: QModelIndex | QPersistentModelIndex) -> bool:
        """Sort integers numerically and status by priority instead of lexicographically."""
        model = self.sourceModel()
        if not model:
            return super().lessThan(left, right)
        left_data = model.data(left, Qt.ItemDataRole.DisplayRole)
        right_data = model.data(right, Qt.ItemDataRole.DisplayRole)

        if left.column() == COLUMN_STATUS:
            status_order: dict[str, int] = {'Connected': 0, 'Disconnected': 1, '—': 2}
            left_rank = status_order.get(str(left_data), 3)
            right_rank = status_order.get(str(right_data), 3)
            return left_rank < right_rank

        if isinstance(left_data, int) and isinstance(right_data, int):
            return left_data < right_data
        return super().lessThan(left, right)
