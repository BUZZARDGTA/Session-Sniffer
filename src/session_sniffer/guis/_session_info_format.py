"""Shared formatting helpers for session tooltips and section-bar summaries."""

from datetime import date, datetime

from session_sniffer.constants.standard import LOCAL_TZ
from session_sniffer.guis.utils import format_duration, format_menu_usernames
from session_sniffer.i18n import tr, tr_plural
from session_sniffer.player.registry import PlayersRegistry, SessionTracker
from session_sniffer.player.session_host import SessionHost
from session_sniffer.settings import Settings


def format_session_time_component(target_dt: datetime, current_date: date) -> str:
    """Format a session timestamp with a month/day prefix if it is not from today."""
    prefix = f'{target_dt.strftime("%m/%d")} ' if target_dt.date() != current_date else ''
    return f'{prefix}{target_dt.strftime("%H:%M:%S")}'


def format_session_label(session_id: int) -> str:
    """Return the localized label for *session_id* (including custom name if set)."""
    normalized_id = max(1, session_id)
    session_name = SessionTracker.get_session_name(normalized_id)
    if session_name is not None:
        return tr('Session #{id} ({name})', id=normalized_id, name=session_name)
    return tr('Session #{id}', id=normalized_id)


def _get_session_player_counts(session_id: int) -> tuple[int, int, int]:
    """Return `(total_count, connected_count, disconnected_count)` for *session_id*."""
    normalized_id = max(1, session_id)
    if normalized_id == SessionTracker.get_current_session_id():
        connected_count = sum(
            1
            for player in PlayersRegistry.get_connected_players()
            if player.session_id in (0, normalized_id) and not player.is_third_party_server
        )
        disconnected_count = sum(
            1
            for player in PlayersRegistry.get_disconnected_players()
            if player.session_id == normalized_id and not player.is_third_party_server
        )
        return connected_count + disconnected_count, connected_count, disconnected_count
    past_count = SessionTracker.get_session_player_count(normalized_id)
    return past_count, 0, past_count


def format_session_bar_summary(session_id: int) -> str:
    """Return a compact localized session summary for the table section header bar."""
    normalized_id = max(1, session_id)
    total_count, _, _ = _get_session_player_counts(normalized_id)
    session_label = format_session_label(normalized_id)
    players_text = tr_plural('{count} player', '{count} players', total_count)
    return tr('{session}: {players}', session=session_label, players=players_text)


def format_session_tooltip_lines(session_id: int) -> list[str]:
    """Return localized multi-line session details (header, player counts, time/duration, and host)."""
    normalized_id = max(1, session_id)
    current_session_id = SessionTracker.get_current_session_id()
    is_current = normalized_id == current_session_id
    session_label = format_session_label(normalized_id)

    lines: list[str] = [
        tr('Current Session ({label})', label=session_label)
        if is_current
        else tr('Past Session ({label})', label=session_label),
    ]

    total_count, connected_count, disconnected_count = _get_session_player_counts(normalized_id)
    players_line = tr_plural('Players: {count} player', 'Players: {count} players', total_count)
    if is_current:
        connected_summary = tr_plural('{count} connected player', '{count} connected players', connected_count)
        disconnected_summary = tr_plural('{count} disconnected player', '{count} disconnected players', disconnected_count)
        breakdown = tr('{connected}, {disconnected}', connected=connected_summary, disconnected=disconnected_summary)
        lines.append(f'{players_line} ({breakdown})')
    else:
        lines.append(players_line)

    now_dt = datetime.now(tz=LOCAL_TZ)
    now_date = now_dt.date()
    start_dt = SessionTracker.get_session_start_time(normalized_id)
    end_dt = SessionTracker.get_session_end_time(normalized_id)

    if is_current:
        if start_dt is not None:
            elapsed_seconds = max(0.0, (now_dt - start_dt).total_seconds())
            duration_label = format_duration(elapsed_seconds)
            formatted_start = format_session_time_component(start_dt, now_date)
            lines.append(tr('Time: Started at {time} ({duration})', time=formatted_start, duration=duration_label))
    elif start_dt is not None and end_dt is not None:
        duration_seconds = max(0.0, (end_dt - start_dt).total_seconds())
        duration_label = format_duration(duration_seconds)
        formatted_start = format_session_time_component(start_dt, now_date)
        formatted_end = format_session_time_component(end_dt, now_date)
        if formatted_start == formatted_end:
            lines.append(tr('Time: {time}', time=formatted_start))
        else:
            lines.append(tr('Time: {start} - {end} ({duration})', start=formatted_start, end=formatted_end, duration=duration_label))
    elif start_dt is not None:
        lines.append(tr('Time: Started at {time}', time=format_session_time_component(start_dt, now_date)))
    elif end_dt is not None:
        lines.append(tr('Time: Ended at {time}', time=format_session_time_component(end_dt, now_date)))

    if Settings.is_session_host_feature_set():
        session_history = SessionHost.get_history(session_id=normalized_id)
        if session_history:
            last_host = session_history[-1]
            matched_host = (
                SessionTracker.get_session_snapshot_player(normalized_id, last_host.ip)
                or PlayersRegistry.get_player_by_ip(last_host.ip)
            )
            fallback_names = last_host.diagnostics.detected_host_usernames if last_host.diagnostics is not None else ()
            host_usernames = matched_host.usernames if matched_host is not None and matched_host.usernames else fallback_names
            formatted_usernames = format_menu_usernames(host_usernames)
            lines.append(
                tr('Host: {ip}  |  {usernames}', ip=last_host.ip, usernames=formatted_usernames)
                if formatted_usernames
                else tr('Host: {ip}', ip=last_host.ip),
            )

    return lines
