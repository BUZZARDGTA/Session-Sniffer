"""Private value-formatting helpers for player action dialogs."""

from datetime import UTC
from typing import TYPE_CHECKING, cast

from session_sniffer.guis.userip_manager_helpers import format_userip_db_display_name
from session_sniffer.i18n import tr, tr_plural
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
    return value is None or (isinstance(value, str) and value in {'', _UNSET_SENTINEL})


def has_lookup_value(value: object) -> bool:
    """Return True if a player lookup field contains a meaningful populated value."""
    return not _is_unset(value)


def format_text(value: object) -> str:
    """Format a generic lookup field, showing 'N/A' for unset values."""
    if _is_unset(value):
        return tr('N/A')
    return str(value)


def format_with_code(primary: object, code: object) -> str:
    """Format a primary lookup value with an optional parenthesized code when both are set."""
    primary_text = format_text(primary)
    if has_lookup_value(primary) and has_lookup_value(code):
        return f'{primary_text} ({format_text(code)})'
    return primary_text


def format_bool(value: object) -> str:
    """Format a boolean-ish lookup field as Yes / No / N/A."""
    if _is_unset(value):
        return tr('N/A')
    if isinstance(value, bool):
        return tr('Yes') if value else tr('No')
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {'true', 'yes', '1'}:
            return tr('Yes')
        if lowered in {'false', 'no', '0'}:
            return tr('No')
    return str(value)


def format_ms(value: object) -> str:
    """Format a millisecond RTT value with one decimal."""
    if _is_unset(value):
        return tr('N/A')
    if isinstance(value, (int, float)):
        return f'{value:.1f} ms'
    return str(value)


def _format_int(value: object) -> str:
    """Format an integer count, falling back to N/A for unset values."""
    if _is_unset(value):
        return tr('N/A')
    if isinstance(value, (int, float)):
        return f'{int(value)}'
    return str(value)


def format_loss_pct(value: object) -> str:
    """Format a packet-loss percentage with one decimal place."""
    if _is_unset(value):
        return tr('N/A')
    if isinstance(value, (int, float)):
        return f'{value:.1f} %'
    return str(value)


def format_packets_and_stats(transmitted: object, received: object, loss: object, errors: object, duplicates: object) -> str:
    """Format sent/received counts, appending loss/errors/duplicates only when non-zero."""
    if _is_unset(transmitted) and _is_unset(received) and _is_unset(loss) and _is_unset(errors) and _is_unset(duplicates):
        return tr('N/A')
    base = tr('{transmitted} sent · {received} received', transmitted=_format_int(transmitted), received=_format_int(received))
    extras: list[str] = []
    if isinstance(loss, (int, float)) and loss:
        extras.append(tr('{loss} loss', loss=format_loss_pct(loss)))
    if isinstance(errors, (int, float)) and errors:
        extras.append(tr_plural('{count} error', '{count} errors', int(errors)))
    if isinstance(duplicates, (int, float)) and duplicates:
        extras.append(tr_plural('{count} duplicate', '{count} duplicates', int(duplicates)))
    return f'{base} · {" · ".join(extras)}' if extras else base


def format_rtt_summary(rtt_min: object, rtt_avg: object, rtt_max: object, rtt_mdev: object) -> str:
    """Format min / avg / max / mean deviation RTT on a single line."""
    if _is_unset(rtt_min) and _is_unset(rtt_avg) and _is_unset(rtt_max) and _is_unset(rtt_mdev):
        return tr('N/A')
    return tr(
        '{min} / {avg} / {max} · {mdev} mean deviation',
        min=format_ms(rtt_min),
        avg=format_ms(rtt_avg),
        max=format_ms(rtt_max),
        mdev=format_ms(rtt_mdev),
    )


def format_ping_times(value: object) -> str:
    """Format the per-packet RTT samples as a compact ms list."""
    if _is_unset(value):
        return tr('N/A')
    if not isinstance(value, list):
        return str(value)
    times = cast('list[object]', value)
    if not times:
        return tr('No samples yet')
    formatted = ', '.join(f'{sample_time:.1f}' for sample_time in times if isinstance(sample_time, (int, float)))
    if not formatted:
        return tr('N/A')
    return f'{formatted} ms'


def format_ping_status(value: object) -> str:
    """Format the is_pinging status field."""
    if _is_unset(value):
        return tr('Pending…')
    if isinstance(value, bool):
        return tr('Active') if value else tr('Idle')
    return str(value)


def format_userip_database(userip: UserIP | None) -> str:
    """Return the relative UserIP database path or translated 'No' when not present."""
    if userip is None:
        return tr('No')
    return format_userip_db_display_name(userip.db_path)


def userip_database_text(player: Player) -> str:
    """Return the relative UserIP database path or translated 'No' for a Player."""
    if player.userip_detection is None or player.userip is None:
        return tr('No')
    return format_userip_database(player.userip)


def _looky_fallback_text(looky: PlayerLooky, *, is_restricted: bool = False) -> str:
    """Return '...' when Looky is enabled and pending initialization, otherwise 'N/A'."""
    if is_restricted or looky.is_initialized:
        return tr('N/A')
    if (
        not Settings.is_gta5_feature_set()
        or not Settings.looky_enabled
        or not bool(Settings.looky_api_key)
        or not LookyState.api_access
        or not CaptureState.is_local_capture()
    ):
        return tr('N/A')
    return '...'


def format_looky_usernames(looky: PlayerLooky, *, is_restricted: bool = False) -> str:
    """Format Looky System usernames for display."""
    with looky.lock:
        if looky.usernames:
            return ', '.join(looky.usernames)
        return _looky_fallback_text(looky, is_restricted=is_restricted)


def format_looky_rockstarids(looky: PlayerLooky, *, is_restricted: bool = False) -> str:
    """Format Looky System Rockstar IDs for display."""
    with looky.lock:
        if looky.rockstarids:
            return ', '.join(map(str, looky.rockstarids))
        return _looky_fallback_text(looky, is_restricted=is_restricted)


def format_looky_last_seens(looky: PlayerLooky, *, is_restricted: bool = False) -> str:
    """Format Looky System last seen timestamps for display."""
    with looky.lock:
        if not looky.last_seens:
            return _looky_fallback_text(looky, is_restricted=is_restricted)
        if len(looky.last_seens) == 1:
            last_seen = looky.last_seens[0]
            last_seen_dt = last_seen if last_seen.tzinfo is None else last_seen.astimezone(UTC)
            return last_seen_dt.strftime('%Y-%m-%d %H:%M:%S UTC')
        lines: list[str] = []
        for i, last_seen in enumerate(looky.last_seens):
            last_seen_dt = last_seen if last_seen.tzinfo is None else last_seen.astimezone(UTC)
            formatted_dt = last_seen_dt.strftime('%Y-%m-%d %H:%M:%S UTC')
            name = looky.entry_names[i] if i < len(looky.entry_names) else (looky.usernames[i] if i < len(looky.usernames) else '')
            rid = str(looky.rockstarids[i]) if i < len(looky.rockstarids) else ''
            identifier = name or rid
            if identifier:
                lines.append(f'{identifier}: {formatted_dt}')
            else:
                lines.append(formatted_dt)
        return '\n'.join(lines)
