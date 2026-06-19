"""Private value-formatting helpers for player action dialogs."""

from typing import TYPE_CHECKING, cast

from session_sniffer.constants.local import USERIP_DATABASES_DIR_PATH

if TYPE_CHECKING:
    from session_sniffer.models.player import Player

_UNSET_SENTINEL = '...'


def _is_unset(value: object) -> bool:
    """Return True if a player lookup field has not yet been populated."""
    return value is None or value == _UNSET_SENTINEL


def fmt_text(value: object) -> str:
    """Format a generic lookup field, showing 'N/A' for unset values."""
    if _is_unset(value):
        return 'N/A'
    return str(value)


def fmt_bool(value: object) -> str:
    """Format a boolean-ish lookup field as Yes / No / N/A."""
    if _is_unset(value):
        return 'N/A'
    if isinstance(value, bool):
        return 'Yes' if value else 'No'
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {'true', 'yes', '1'}:
            return 'Yes'
        if lowered in {'false', 'no', '0'}:
            return 'No'
    return str(value)


def fmt_ms(value: object) -> str:
    """Format a millisecond RTT value with one decimal."""
    if _is_unset(value):
        return 'N/A'
    if isinstance(value, (int, float)):
        return f'{value:.1f} ms'
    return str(value)


def _fmt_int(value: object) -> str:
    """Format an integer count, falling back to N/A for unset values."""
    if _is_unset(value):
        return 'N/A'
    if isinstance(value, (int, float)):
        return f'{int(value)}'
    return str(value)


def fmt_loss_pct(value: object) -> str:
    """Format a packet-loss percentage with one decimal place."""
    if _is_unset(value):
        return 'N/A'
    if isinstance(value, (int, float)):
        return f'{value:.1f} %'
    return str(value)


def fmt_packets_and_stats(transmitted: object, received: object, loss: object, errors: object, duplicates: object) -> str:
    """Format sent/received counts, appending loss/errors/duplicates only when non-zero."""
    if _is_unset(transmitted) and _is_unset(received) and _is_unset(loss) and _is_unset(errors) and _is_unset(duplicates):
        return 'N/A'
    base = f'{_fmt_int(transmitted)} sent · {_fmt_int(received)} received'
    extras: list[str] = []
    if isinstance(loss, (int, float)) and loss:
        extras.append(f'{fmt_loss_pct(loss)} loss')
    if isinstance(errors, (int, float)) and errors:
        extras.append(f'{_fmt_int(errors)} errors')
    if isinstance(duplicates, (int, float)) and duplicates:
        extras.append(f'{_fmt_int(duplicates)} duplicates')
    return f'{base} · {" · ".join(extras)}' if extras else base


def fmt_rtt_summary(rtt_min: object, rtt_avg: object, rtt_max: object, rtt_mdev: object) -> str:
    """Format min / avg / max / mean deviation RTT on a single line."""
    if _is_unset(rtt_min) and _is_unset(rtt_avg) and _is_unset(rtt_max) and _is_unset(rtt_mdev):
        return 'N/A'
    return f'{fmt_ms(rtt_min)} / {fmt_ms(rtt_avg)} / {fmt_ms(rtt_max)} · {fmt_ms(rtt_mdev)} mean deviation'


def fmt_ping_times(value: object) -> str:
    """Format the per-packet RTT samples as a compact ms list."""
    if _is_unset(value):
        return 'N/A'
    if not isinstance(value, list):
        return str(value)
    times = cast('list[object]', value)
    if not times:
        return 'No samples yet'
    formatted = ', '.join(f'{t:.1f}' for t in times if isinstance(t, (int, float)))
    if not formatted:
        return 'N/A'
    return f'{formatted} ms'


def fmt_ping_status(value: object) -> str:
    """Format the is_pinging status field."""
    if _is_unset(value):
        return 'Pending…'
    if isinstance(value, bool):
        return 'Active' if value else 'Idle'
    return str(value)


def userip_database_text(player: Player) -> str:
    """Return the relative UserIP database path or 'No' when not present."""
    if player.userip_detection is None or player.userip is None:
        return 'No'
    relative = player.userip.db_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix('')
    return str(relative)
