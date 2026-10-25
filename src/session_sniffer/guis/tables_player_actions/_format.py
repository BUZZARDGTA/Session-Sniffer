"""Private value-formatting helpers for player action dialogs."""

from datetime import UTC
from typing import TYPE_CHECKING, cast

from session_sniffer.constants.local import USERIP_DATABASES_DIR_PATH
from session_sniffer.networking.looky_system import LookyState
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings.settings import Settings

if TYPE_CHECKING:
    from session_sniffer.models.player import Player
    from session_sniffer.models.player_lookup import PlayerLooky
    from session_sniffer.player.userip import UserIP

_UNSET_SENTINEL = '...'


def _is_unset(value: object) -> bool:
    """Return True if a player lookup field has not yet been populated."""
    return value is None or value == _UNSET_SENTINEL


def format_text(value: object) -> str:
    """Format a generic lookup field, showing 'N/A' for unset values."""
    if _is_unset(value):
        return 'N/A'
    return str(value)


def format_with_code(primary: object, code: object) -> str:
    """Format a primary lookup value with an optional parenthesized code when both are set."""
    primary_text = format_text(primary)
    code_text = format_text(code)
    if primary_text != 'N/A' and code_text != 'N/A':
        return f'{primary_text} ({code_text})'
    return primary_text


def format_bool(value: object) -> str:
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


def format_ms(value: object) -> str:
    """Format a millisecond RTT value with one decimal."""
    if _is_unset(value):
        return 'N/A'
    if isinstance(value, (int, float)):
        return f'{value:.1f} ms'
    return str(value)


def _format_int(value: object) -> str:
    """Format an integer count, falling back to N/A for unset values."""
    if _is_unset(value):
        return 'N/A'
    if isinstance(value, (int, float)):
        return f'{int(value)}'
    return str(value)


def format_loss_pct(value: object) -> str:
    """Format a packet-loss percentage with one decimal place."""
    if _is_unset(value):
        return 'N/A'
    if isinstance(value, (int, float)):
        return f'{value:.1f} %'
    return str(value)


def format_packets_and_stats(transmitted: object, received: object, loss: object, errors: object, duplicates: object) -> str:
    """Format sent/received counts, appending loss/errors/duplicates only when non-zero."""
    if _is_unset(transmitted) and _is_unset(received) and _is_unset(loss) and _is_unset(errors) and _is_unset(duplicates):
        return 'N/A'
    base = f'{_format_int(transmitted)} sent · {_format_int(received)} received'
    extras: list[str] = []
    if isinstance(loss, (int, float)) and loss:
        extras.append(f'{format_loss_pct(loss)} loss')
    if isinstance(errors, (int, float)) and errors:
        extras.append(f'{_format_int(errors)} errors')
    if isinstance(duplicates, (int, float)) and duplicates:
        extras.append(f'{_format_int(duplicates)} duplicates')
    return f'{base} · {" · ".join(extras)}' if extras else base


def format_rtt_summary(rtt_min: object, rtt_avg: object, rtt_max: object, rtt_mdev: object) -> str:
    """Format min / avg / max / mean deviation RTT on a single line."""
    if _is_unset(rtt_min) and _is_unset(rtt_avg) and _is_unset(rtt_max) and _is_unset(rtt_mdev):
        return 'N/A'
    return f'{format_ms(rtt_min)} / {format_ms(rtt_avg)} / {format_ms(rtt_max)} · {format_ms(rtt_mdev)} mean deviation'


def format_ping_times(value: object) -> str:
    """Format the per-packet RTT samples as a compact ms list."""
    if _is_unset(value):
        return 'N/A'
    if not isinstance(value, list):
        return str(value)
    times = cast('list[object]', value)
    if not times:
        return 'No samples yet'
    formatted = ', '.join(f'{sample_time:.1f}' for sample_time in times if isinstance(sample_time, (int, float)))
    if not formatted:
        return 'N/A'
    return f'{formatted} ms'


def format_ping_status(value: object) -> str:
    """Format the is_pinging status field."""
    if _is_unset(value):
        return 'Pending…'
    if isinstance(value, bool):
        return 'Active' if value else 'Idle'
    return str(value)


def format_userip_database(userip: UserIP | None) -> str:
    """Return the relative UserIP database path or 'No' when not present."""
    if userip is None:
        return 'No'
    relative_path = userip.db_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix('')
    return str(relative_path)


def userip_database_text(player: Player) -> str:
    """Return the relative UserIP database path or 'No' for a Player."""
    if player.userip_detection is None or player.userip is None:
        return 'No'
    return format_userip_database(player.userip)


def _looky_fallback_text(looky: PlayerLooky) -> str:
    """Return '...' when Looky is enabled and pending initialization, otherwise 'N/A'."""
    if (
        not Settings.is_gta5_feature_set()
        or not Settings.looky_enabled
        or not bool(Settings.looky_api_key)
        or not LookyState.api_access
        or not CaptureState.is_local_capture()
    ):
        return 'N/A'
    return '...' if not looky.is_initialized else 'N/A'


def format_looky_usernames(looky: PlayerLooky) -> str:
    """Format Looky System usernames for display."""
    with looky.lock:
        if looky.usernames:
            return ', '.join(looky.usernames)
        return _looky_fallback_text(looky)


def format_looky_rockstarids(looky: PlayerLooky) -> str:
    """Format Looky System Rockstar IDs for display."""
    with looky.lock:
        if looky.rockstarids:
            return ', '.join(map(str, looky.rockstarids))
        return _looky_fallback_text(looky)


def format_looky_last_seens(looky: PlayerLooky) -> str:
    """Format Looky System last seen timestamps for display."""
    with looky.lock:
        if not looky.last_seens:
            return _looky_fallback_text(looky)
        if len(looky.last_seens) == 1:
            last_seen = looky.last_seens[0]
            last_seen_dt = last_seen if last_seen.tzinfo is None else last_seen.astimezone(UTC)
            return last_seen_dt.strftime('%Y-%m-%d %H:%M:%S UTC')
        lines: list[str] = []
        for i, last_seen in enumerate(looky.last_seens):
            last_seen_dt = last_seen if last_seen.tzinfo is None else last_seen.astimezone(UTC)
            formatted_dt = last_seen_dt.strftime('%Y-%m-%d %H:%M:%S UTC')
            name = looky.usernames[i] if i < len(looky.usernames) else ''
            rid = str(looky.rockstarids[i]) if i < len(looky.rockstarids) else ''
            identifier = name or rid
            if identifier:
                lines.append(f'{identifier}: {formatted_dt}')
            else:
                lines.append(formatted_dt)
        return '\n'.join(lines)
