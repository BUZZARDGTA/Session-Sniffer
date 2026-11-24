"""Global OS hotkeys and window-scoped keyboard shortcuts mixin for `MainWindow`."""

import logging
import sys
import time
from threading import Event, Thread
from typing import TYPE_CHECKING, Final, Literal

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtGui import QAction, QKeySequence, QShortcut
from PySide6.QtWidgets import QMainWindow
from shiboken6 import isValid

from session_sniffer.background.cores import trigger_looky_rescan_all_players
from session_sniffer.background.events import gui_closed__event
from session_sniffer.ctypes_windows import (
    WIN32_MOD_ALT,
    WIN32_MOD_CONTROL,
    WIN32_MOD_SHIFT,
    WIN32_MOD_WIN,
    get_win32_active_modifiers,
    is_win32_vk_down,
    run_win32_raw_keyboard_message_loop,
    stop_win32_message_window,
    vk_key_scan_win32,
)
from session_sniffer.guis.interface_selection_dialog import InterfaceSelectionDialog
from session_sniffer.i18n import tr
from session_sniffer.notifications_state import notifications_state
from session_sniffer.player.registry import SessionTracker
from session_sniffer.rendering_core.events import wake_rendering_core
from session_sniffer.rendering_core.types import CaptureState, SessionFilterState, TableMergeState
from session_sniffer.settings import Settings
from session_sniffer.text_utils import is_bare_typing_hotkey

if TYPE_CHECKING:
    from collections.abc import Callable

    from session_sniffer.guis._main_header import SessionHeader
    from session_sniffer.guis._session_table_section import SessionTableSection
    from session_sniffer.guis.loading_overlay import LoadingOverlay
    from session_sniffer.guis.main_window import MainMenuActions
    from session_sniffer.guis.settings_dialog import SettingsDialog

logger = logging.getLogger(__name__)

_MAX_F_KEY_NUMBER: Final[int] = 24
_HELD_REPEAT_STALE_SECONDS: Final[float] = 1.5
_WIN32_POLL_INTERVAL_MS: Final[int] = 20
_WIN32_LISTENER_READY_TIMEOUT_SECONDS: Final[float] = 2.0
_WIN32_LISTENER_JOIN_TIMEOUT_SECONDS: Final[float] = 1.0

_WIN32_MODIFIER_VKS: Final[frozenset[int]] = frozenset({
    0x10, 0x11, 0x12, 0x5B, 0x5C,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
})
_NAVIGATION_CLUSTER_VKS: Final[dict[str, int]] = {
    'pgup': 0x21, 'pgdown': 0x22, 'end': 0x23, 'home': 0x24,
    'left': 0x25, 'up': 0x26, 'right': 0x27, 'down': 0x28,
    'ins': 0x2D, 'del': 0x2E,
}
_NAMED_NON_CHAR_VKS: Final[dict[str, int]] = {
    'backspace': 0x08, 'tab': 0x09, 'clear': 0x0C, 'capslock': 0x14,
    'space': 0x20, 'print': 0x2C, 'numlock': 0x90, 'scrolllock': 0x91,
}
_NUMPAD_OPERATOR_VKS: Final[dict[str, int]] = {
    '*': 0x6A, '+': 0x6B, '-': 0x6D, '.': 0x6E, ',': 0x6E, '/': 0x6F,
}
_FALLBACK_MAIN_OEM_VKS: Final[dict[str, int]] = {
    '!': 0x31, '@': 0x32, '#': 0x33, '$': 0x34, '%': 0x35, '^': 0x36, '&': 0x37, '*': 0x38, '(': 0x39, ')': 0x30,
    ';': 0xBA, ':': 0xBA, '=': 0xBB, '+': 0xBB, ',': 0xBC, '<': 0xBC, '-': 0xBD, '_': 0xBD,
    '.': 0xBE, '>': 0xBE, '/': 0xBF, '?': 0xBF, '`': 0xC0, '~': 0xC0,
    '[': 0xDB, '{': 0xDB, '\\': 0xDC, '|': 0xDC, ']': 0xDD, '}': 0xDD, "'": 0xDE, '"': 0xDE,
}


def _resolve_numpad_triggers(portable_key: str, *, mod_flags: int) -> tuple[int, tuple[tuple[int, bool | None], ...]] | None:
    if len(portable_key) == 1 and '0' <= portable_key <= '9':
        return mod_flags, ((0x60 + ord(portable_key) - ord('0'), None),)
    if (op_vk := _NUMPAD_OPERATOR_VKS.get(portable_key)) is not None:
        return mod_flags, ((op_vk, None),)
    if portable_key in ('enter', 'return'):
        return mod_flags, ((0x0D, True),)
    if portable_key == 'clear':
        return mod_flags, ((0x0C, False),)
    if (nav_vk := _NAVIGATION_CLUSTER_VKS.get(portable_key)) is not None:
        return mod_flags, ((nav_vk, False),)
    return None


def _resolve_single_char_triggers(portable_key: str, *, mod_flags: int) -> tuple[int, tuple[tuple[int, bool | None], ...]] | None:
    if (scanned := vk_key_scan_win32(portable_key)) is not None:
        vk_code, shift_state = scanned
        extra_mods = (
            (WIN32_MOD_SHIFT if (shift_state & 1) else 0)
            | (WIN32_MOD_CONTROL if (shift_state & 2) else 0)
            | (WIN32_MOD_ALT if (shift_state & 4) else 0)
        )
        return mod_flags | extra_mods, ((vk_code, None),)
    if 'a' <= portable_key <= 'z':
        return mod_flags, ((ord(portable_key.upper()), None),)
    if '0' <= portable_key <= '9':
        return mod_flags, ((ord(portable_key), None),)
    if (oem_vk := _FALLBACK_MAIN_OEM_VKS.get(portable_key)) is not None:
        return mod_flags, ((oem_vk, None),)
    return None


def _resolve_portable_key_triggers(
    portable_key: str,
    *,
    mod_flags: int = 0,
    is_numpad: bool = False,
) -> tuple[int, tuple[tuple[int, bool | None], ...]] | None:
    """Resolve a lowercase portable key string to `(effective_mod_flags, ((vk_code, extended_req), ...))`."""
    if is_numpad:
        return _resolve_numpad_triggers(portable_key, mod_flags=mod_flags)
    if len(portable_key) == 1:
        return _resolve_single_char_triggers(portable_key, mod_flags=mod_flags)

    triggers: tuple[tuple[int, bool | None], ...] | None = None
    if portable_key.startswith('f') and portable_key[1:].isdigit() and 1 <= (fn_num := int(portable_key[1:])) <= _MAX_F_KEY_NUMBER:
        triggers = ((0x70 + fn_num - 1, None),)
    elif portable_key == 'pause':
        triggers = ((0x13, None), (0x03, None)) if (mod_flags & WIN32_MOD_CONTROL) else ((0x13, None),)
    elif portable_key in ('return', 'enter'):
        triggers = ((0x0D, False),)
    elif (nav_vk := _NAVIGATION_CLUSTER_VKS.get(portable_key)) is not None:
        triggers = ((nav_vk, True),)
    elif (named_vk := _NAMED_NON_CHAR_VKS.get(portable_key)) is not None:
        triggers = ((named_vk, None),)
    return (mod_flags, triggers) if triggers is not None else None


def parse_win32_hotkey_spec(hotkey: str | None) -> tuple[int, tuple[tuple[int, bool | None], ...]] | None:
    """Translate a portable `QKeySequence` string into `(win32_modifier_flags, ((vk_code, extended_req), ...))`."""
    if hotkey is None or not hotkey:
        return None
    seq = QKeySequence.fromString(hotkey, QKeySequence.SequenceFormat.PortableText)
    portable = seq.toString(QKeySequence.SequenceFormat.PortableText).split(', ', 1)[0].strip().lower()
    if not portable:
        return None

    mod_flags, is_numpad = 0, False
    for _ in range(5):
        if portable.startswith('num+'):
            is_numpad, portable = True, portable[4:]
            continue
        matched_mod = False
        for mod_prefix, flag in (('ctrl+', WIN32_MOD_CONTROL), ('shift+', WIN32_MOD_SHIFT), ('alt+', WIN32_MOD_ALT), ('meta+', WIN32_MOD_WIN)):
            if portable.startswith(mod_prefix):
                mod_flags |= flag
                portable = portable[len(mod_prefix) :]
                matched_mod = True
                break
        if not matched_mod:
            break

    return _resolve_portable_key_triggers(portable, mod_flags=mod_flags, is_numpad=is_numpad)


def append_shortcut_tooltip(tooltip: str, shortcut: str | None, *, is_global: bool = False) -> str:
    """Append a localized shortcut or global hotkey hint line to *tooltip* when *shortcut* is configured."""
    if shortcut is None or not shortcut:
        return tooltip
    suffix = tr('Global Hotkey: {hotkey}', hotkey=shortcut) if is_global else tr('Shortcut: {shortcut}', shortcut=shortcut)
    return f'{tooltip}\n\n{suffix}' if tooltip else suffix


class _Win32HotkeySignalBridge(QObject):
    """Thread-safe Qt signal bridge forwarding Win32 global key triggers to the GUI thread."""

    hotkey_triggered: Signal = Signal(int, int, object)  # (vk_code, mod_flags, is_extended: bool | None)


class ShortcutsMixin(QMainWindow):
    """Manage system-wide global hotkeys and main-window keyboard shortcuts on `MainWindow`."""

    _shortcuts_initialized: bool = False
    _win32_hotkey_bindings: dict[tuple[int, int], list[tuple[bool | None, Callable[[], None]]]]
    _win32_hotkey_bridge: _Win32HotkeySignalBridge
    _win32_listener_thread: Thread | None
    _win32_listener_hwnd: int | None
    _global_fallback_shortcuts: dict[str, QShortcut]
    _window_shortcuts: dict[str, QShortcut]

    if TYPE_CHECKING:
        _actions: MainMenuActions
        _open_settings_action: QAction
        _header: SessionHeader
        _connected: SessionTableSection
        _disconnected: SessionTableSection
        _settings_dialog_window: SettingsDialog | None
        _interface_switching_overlay: LoadingOverlay | None
        _looky_crawler_join_own_session_action: QAction
        _looky_rescan_all_action: QAction
        _last_game_process_button_key: tuple[object, ...]

        def _toggle_capture(self) -> None: ...
        def _sync_capture_toggle_action(self) -> None: ...

        def _toggle_notifications(self, mode: Literal['visual', 'voice', 'all']) -> None:
            del mode

        def _toggle_tables_merged(self) -> None: ...
        def _open_settings_dialog(self) -> None: ...
        def _clear_connected_players(self) -> None: ...
        def _clear_disconnected_players(self) -> None: ...
        def _can_trigger_solo_session(self) -> bool: ...
        def _can_toggle_manual_game_suspend(self) -> bool: ...
        def _sync_game_process_button(self) -> None: ...
        def _refresh_player_resolver_action_texts(self) -> None: ...

        def game_solo_session(self) -> None:
            """Trigger a solo public session on the active game process."""

        def toggle_manual_game_suspend(self) -> None:
            """Toggle manual process suspend on or off for the active game."""

        def _open_player_resolver(self) -> None: ...
        def _redetect_session_host_from_hotkey(self) -> bool: ...
        def _update_looky_actions(self) -> None: ...
        def _refresh_looky_language_texts(self) -> None: ...
        def _request_crawler_own_session(self) -> None: ...
        def _rescan_all_looky_players(self) -> None: ...

    def _global_hotkey_specs(self) -> tuple[tuple[str, Callable[[], bool], Callable[[], None]], ...]:
        """Return `(setting_key, is_applicable, handler)` entries for all OS-level global hotkeys."""
        return (
            ('toggle_capture_hotkey', lambda: True, self._trigger_toggle_capture_from_hotkey),
            ('toggle_visual_notifications_hotkey', lambda: True, self._trigger_visual_notifications_from_hotkey),
            ('toggle_voice_notifications_hotkey', lambda: True, self._trigger_voice_notifications_from_hotkey),
            ('toggle_all_notifications_hotkey', lambda: True, self._trigger_all_notifications_from_hotkey),
            ('solo_session_hotkey', lambda: Settings.is_rockstar_feature_set() and CaptureState.is_local_capture(), self._trigger_solo_session_from_hotkey),
            ('suspend_process_hotkey', lambda: Settings.is_rockstar_feature_set() and CaptureState.is_local_capture(), self._trigger_suspend_process_from_hotkey),
            ('player_resolver_hotkey', Settings.is_rockstar_feature_set, self._trigger_player_resolver_from_hotkey),
            ('redetect_host_hotkey', Settings.is_session_host_feature_set, self._trigger_redetect_host_from_hotkey),
            ('looky_crawler_hotkey', lambda: Settings.is_gta5_feature_set() and CaptureState.is_local_capture(), self._trigger_looky_crawler_from_hotkey),
            ('looky_rescan_hotkey', lambda: Settings.is_gta5_feature_set() and CaptureState.is_local_capture(), self._trigger_looky_rescan_from_hotkey),
        )

    def _window_shortcut_specs(self) -> tuple[tuple[str, Callable[[], None]], ...]:
        """Return `(setting_key, handler)` entries for main-window-scoped keyboard shortcuts."""
        return (
            ('shortcut_focus_search', self._trigger_focus_search_shortcut),
            ('shortcut_merge_tables', self._trigger_merge_tables_shortcut),
            ('shortcut_open_settings', self._trigger_open_settings_shortcut),
            ('shortcut_clear_connected', self._trigger_clear_connected_shortcut),
            ('shortcut_clear_disconnected', self._trigger_clear_disconnected_shortcut),
        )

    def _init_shortcuts(self) -> None:
        """Create `QShortcut` instances and synchronize initial hotkey registrations."""
        self._win32_hotkey_bindings = {}
        self._win32_listener_thread = None
        self._win32_listener_hwnd = None
        self._win32_hotkey_bridge = _Win32HotkeySignalBridge(self)
        self._win32_hotkey_bridge.hotkey_triggered.connect(
            self._on_win32_hotkey_triggered,
            Qt.ConnectionType.QueuedConnection,
        )
        self._global_fallback_shortcuts = {}
        self._window_shortcuts = {}

        for setting_key, _is_applicable, handler in self._global_hotkey_specs():
            shortcut = QShortcut(self)
            shortcut.setContext(Qt.ShortcutContext.ApplicationShortcut)
            shortcut.setEnabled(False)
            shortcut.activated.connect(handler)
            self._global_fallback_shortcuts[setting_key] = shortcut

        for setting_key, handler in self._window_shortcut_specs():
            shortcut = QShortcut(self)
            shortcut.setContext(Qt.ShortcutContext.WindowShortcut)
            shortcut.setEnabled(False)
            shortcut.activated.connect(handler)
            self._window_shortcuts[setting_key] = shortcut

        self._shortcuts_initialized = True
        self._sync_shortcuts()

    def _stop_win32_hotkey_listener(self) -> None:
        """Stop the dedicated Win32 Raw Input / polling background listener, if running."""
        listener_hwnd, self._win32_listener_hwnd = self._win32_listener_hwnd, None
        listener_thread, self._win32_listener_thread = self._win32_listener_thread, None
        if listener_hwnd is not None:
            stop_win32_message_window(listener_hwnd)
        if listener_thread is not None and listener_thread.is_alive():
            listener_thread.join(timeout=_WIN32_LISTENER_JOIN_TIMEOUT_SECONDS)

    def _unregister_global_hotkeys(self) -> None:
        """Unregister all active OS-level global hotkeys and disable fallback `QShortcut`s."""
        if not self._shortcuts_initialized:
            return
        if sys.platform == 'win32':
            self._stop_win32_hotkey_listener()
        self._win32_hotkey_bindings.clear()
        for shortcut in self._global_fallback_shortcuts.values():
            shortcut.setEnabled(False)
            shortcut.setKey(QKeySequence())

    def _sync_shortcuts(self) -> None:
        """Synchronize all global hotkeys, window shortcuts, and shortcut UI hints from `Settings`."""
        if not self._shortcuts_initialized or gui_closed__event.is_set() or not isValid(self):
            return

        self._unregister_global_hotkeys()

        for setting_key, _handler in self._window_shortcut_specs():
            shortcut = self._window_shortcuts[setting_key]
            chord = Settings.get_active_shortcut(setting_key)
            if chord is not None:
                shortcut.setKey(QKeySequence.fromString(chord, QKeySequence.SequenceFormat.PortableText))
                shortcut.setEnabled(True)
            else:
                shortcut.setEnabled(False)
                shortcut.setKey(QKeySequence())

        self._sync_shortcut_action_labels()

        if self._settings_dialog_window is not None and isValid(self._settings_dialog_window) and self._settings_dialog_window.isVisible():
            return

        win32_fallbacks: list[tuple[str, str, QShortcut]] = []
        for setting_key, is_applicable, handler in self._global_hotkey_specs():
            fallback_shortcut = self._global_fallback_shortcuts[setting_key]
            chord = Settings.get_active_shortcut(setting_key) if is_applicable() else None
            if chord is None or is_bare_typing_hotkey(chord):
                continue
            if sys.platform == 'win32':
                spec = parse_win32_hotkey_spec(chord)
                if spec is None:
                    logger.warning('Failed to parse global OS hotkey %r for %s; falling back to window shortcut.', chord, setting_key)
                    fallback_shortcut.setKey(QKeySequence.fromString(chord, QKeySequence.SequenceFormat.PortableText))
                    fallback_shortcut.setEnabled(True)
                else:
                    mod_flags, triggers = spec
                    for vk_code, extended_req in triggers:
                        self._win32_hotkey_bindings.setdefault((mod_flags, vk_code), []).append((extended_req, handler))
                    win32_fallbacks.append((setting_key, chord, fallback_shortcut))
            else:
                fallback_shortcut.setKey(QKeySequence.fromString(chord, QKeySequence.SequenceFormat.PortableText))
                fallback_shortcut.setEnabled(True)

        if sys.platform == 'win32' and self._win32_hotkey_bindings and not self._start_win32_hotkey_listener():
            self._win32_hotkey_bindings.clear()
            for setting_key, chord, fallback_shortcut in win32_fallbacks:
                logger.warning('Failed to start Win32 global hotkey listener for %s (%r); falling back to window shortcut.', setting_key, chord)
                fallback_shortcut.setKey(QKeySequence.fromString(chord, QKeySequence.SequenceFormat.PortableText))
                fallback_shortcut.setEnabled(True)

    def _start_win32_hotkey_listener(self) -> bool:
        """Start a dedicated background Win32 Raw Input (`RIDEV_INPUTSINK`) and `GetAsyncKeyState` listener thread."""
        self._stop_win32_hotkey_listener()
        watched_vks = frozenset(vk_code for _mods, vk_code in self._win32_hotkey_bindings)
        bridge = self._win32_hotkey_bridge
        initial_time = time.monotonic()
        pressed_vks: dict[int, float] = {vk_code: initial_time for vk_code in watched_vks if is_win32_vk_down(vk_code)}
        pending_poll_vks: set[int] = set()
        raw_input_active = False
        listener_hwnd: int | None = None
        ready_event = Event()

        def _on_ready(ready_state: tuple[int | None, bool]) -> None:
            nonlocal listener_hwnd, raw_input_active
            hwnd, raw_input_ok = ready_state
            listener_hwnd = hwnd
            raw_input_active = raw_input_ok
            if hwnd is not None and not raw_input_ok:
                logger.warning('Win32 Raw Input keyboard registration failed; using GetAsyncKeyState polling for global hotkeys.')
            ready_event.set()

        def _on_raw_key(key_event: tuple[int, bool, bool]) -> None:
            vk_code, is_key_down, is_extended = key_event
            if vk_code in _WIN32_MODIFIER_VKS or vk_code not in watched_vks:
                return
            if not is_key_down:
                pressed_vks.pop(vk_code, None)
                pending_poll_vks.discard(vk_code)
                return

            now = time.monotonic()
            previous_down = pressed_vks.get(vk_code)
            pressed_vks[vk_code] = now
            pending_poll_vks.discard(vk_code)
            if previous_down is not None and now - previous_down < _HELD_REPEAT_STALE_SECONDS:
                return
            if isValid(bridge):
                bridge.hotkey_triggered.emit(vk_code, get_win32_active_modifiers(), is_extended)

        def _on_poll_tick() -> None:
            now = time.monotonic()
            for vk_code in watched_vks:
                if not is_win32_vk_down(vk_code):
                    pressed_vks.pop(vk_code, None)
                    pending_poll_vks.discard(vk_code)
                    continue
                if vk_code in pressed_vks:
                    pressed_vks[vk_code] = now
                    continue
                if raw_input_active and vk_code not in pending_poll_vks:
                    pending_poll_vks.add(vk_code)
                    continue
                pending_poll_vks.discard(vk_code)
                pressed_vks[vk_code] = now
                if isValid(bridge):
                    bridge.hotkey_triggered.emit(vk_code, get_win32_active_modifiers(), None)

        listener_thread = Thread(
            target=run_win32_raw_keyboard_message_loop,
            args=(_on_raw_key, _on_poll_tick, _on_ready),
            kwargs={'poll_interval_ms': _WIN32_POLL_INTERVAL_MS},
            name='Win32GlobalHotkeys',
            daemon=True,
        )
        listener_thread.start()
        ready_event.wait(timeout=_WIN32_LISTENER_READY_TIMEOUT_SECONDS)
        if listener_hwnd is None:
            listener_thread.join(timeout=_WIN32_LISTENER_JOIN_TIMEOUT_SECONDS)
            return False
        self._win32_listener_hwnd = listener_hwnd
        self._win32_listener_thread = listener_thread
        return True

    def _on_win32_hotkey_triggered(self, vk_code: int, mod_flags: int, is_extended: object) -> None:
        """Dispatch a Win32 global key trigger on the Qt GUI thread."""
        if not self._shortcuts_initialized or gui_closed__event.is_set() or not isValid(self):
            return
        candidates = self._win32_hotkey_bindings.get((mod_flags, vk_code))
        if candidates is None:
            return
        extended_flag = is_extended if isinstance(is_extended, bool) else None
        for extended_req, handler in candidates:
            if extended_req is None or extended_flag is None or extended_req == extended_flag:
                handler()
                break

    def _sync_shortcut_action_labels(self) -> None:
        """Refresh menu action and widget tooltips that display configured shortcuts."""
        if not self._shortcuts_initialized:
            return
        self._sync_capture_toggle_action()
        open_settings_shortcut = Settings.get_active_shortcut('shortcut_open_settings')
        self._open_settings_action.setToolTip(append_shortcut_tooltip(tr('View and edit all application settings'), open_settings_shortcut))
        self._refresh_player_resolver_action_texts()
        self._refresh_looky_language_texts()
        self._last_game_process_button_key = ()
        self._sync_game_process_button()
        selected_session = SessionFilterState.get_selected_session()
        is_past_session = 0 < selected_session < SessionTracker.get_current_session_id()
        self._header.set_search_placeholder_merged(is_merged=TableMergeState.is_merged() or is_past_session)
        self._header.sync_notification_buttons(visual_enabled=notifications_state.visual_enabled, voice_enabled=notifications_state.voice_enabled)
        self._connected.refresh_shortcut_tooltips()
        self._disconnected.refresh_shortcut_tooltips()

    def _can_trigger_shortcut(self) -> bool:
        """Return `True` when the main window is in an interactive state eligible to handle shortcuts."""
        if not Settings.shortcuts_enabled or gui_closed__event.is_set() or not isValid(self):
            return False
        if self._settings_dialog_window is not None and isValid(self._settings_dialog_window) and self._settings_dialog_window.isVisible():
            return False
        return self._interface_switching_overlay is None and InterfaceSelectionDialog.get_active_instance() is None

    def _trigger_toggle_capture_from_hotkey(self) -> None:
        if not self._can_trigger_shortcut() or not self._actions.toggle_capture.isEnabled():
            return
        logger.info('Capture toggle triggered via hotkey (%s)', Settings.toggle_capture_hotkey)
        self._toggle_capture()

    def _trigger_visual_notifications_from_hotkey(self) -> None:
        if not self._can_trigger_shortcut():
            return
        logger.info('Visual notifications toggle triggered via hotkey (%s)', Settings.toggle_visual_notifications_hotkey)
        self._toggle_notifications('visual')

    def _trigger_voice_notifications_from_hotkey(self) -> None:
        if not self._can_trigger_shortcut():
            return
        logger.info('Voice notifications toggle triggered via hotkey (%s)', Settings.toggle_voice_notifications_hotkey)
        self._toggle_notifications('voice')

    def _trigger_all_notifications_from_hotkey(self) -> None:
        if not self._can_trigger_shortcut():
            return
        logger.info('All notifications toggle triggered via hotkey (%s)', Settings.toggle_all_notifications_hotkey)
        self._toggle_notifications('all')

    def _trigger_solo_session_from_hotkey(self) -> None:
        if not self._can_trigger_shortcut() or not Settings.is_rockstar_feature_set() or not CaptureState.is_local_capture():
            return
        if not self._can_trigger_solo_session():
            return
        logger.info('Solo Public Session triggered via hotkey (%s)', Settings.solo_session_hotkey)
        self.game_solo_session()

    def _trigger_suspend_process_from_hotkey(self) -> None:
        if not self._can_trigger_shortcut() or not Settings.is_rockstar_feature_set() or not CaptureState.is_local_capture():
            return
        if not self._can_toggle_manual_game_suspend():
            return
        logger.info('Manual game process suspend/resume triggered via hotkey (%s)', Settings.suspend_process_hotkey)
        self.toggle_manual_game_suspend()

    def _trigger_player_resolver_from_hotkey(self) -> None:
        if not self._can_trigger_shortcut() or not Settings.is_rockstar_feature_set():
            return
        logger.info('Player Resolver opened via hotkey (%s)', Settings.player_resolver_hotkey)
        self._open_player_resolver()

    def _trigger_redetect_host_from_hotkey(self) -> None:
        if not self._can_trigger_shortcut() or not Settings.is_session_host_feature_set() or not Settings.gui_session_host_detection:
            return
        logger.info('Session host re-detection triggered via hotkey (%s)', Settings.redetect_host_hotkey)
        if self._redetect_session_host_from_hotkey():
            wake_rendering_core()

    def _trigger_looky_crawler_from_hotkey(self) -> None:
        if not self._can_trigger_shortcut() or not Settings.is_gta5_feature_set() or not CaptureState.is_local_capture():
            return
        self._update_looky_actions()
        if not self._looky_crawler_join_own_session_action.isEnabled():
            return
        logger.info('Looky crawler request triggered via hotkey (%s)', Settings.looky_crawler_hotkey)
        self._request_crawler_own_session()

    def _trigger_looky_rescan_from_hotkey(self) -> None:
        if not self._can_trigger_shortcut() or not Settings.is_gta5_feature_set() or not CaptureState.is_local_capture():
            return
        self._update_looky_actions()
        if not self._looky_rescan_all_action.isEnabled():
            return
        logger.info('Looky rescan all players triggered via hotkey (%s)', Settings.looky_rescan_hotkey)
        if self.isActiveWindow():
            self._rescan_all_looky_players()
        else:
            trigger_looky_rescan_all_players()

    def _trigger_focus_search_shortcut(self) -> None:
        if not self._can_trigger_shortcut():
            return
        self._header.focus_search()

    def _trigger_merge_tables_shortcut(self) -> None:
        if not self._can_trigger_shortcut() or not Settings.gui_disconnected_players_enabled:
            return
        self._toggle_tables_merged()

    def _trigger_open_settings_shortcut(self) -> None:
        if not self._can_trigger_shortcut():
            return
        self._open_settings_dialog()

    def _trigger_clear_connected_shortcut(self) -> None:
        if not self._can_trigger_shortcut() or not self._connected.is_clear_enabled:
            return
        self._clear_connected_players()

    def _trigger_clear_disconnected_shortcut(self) -> None:
        if not self._can_trigger_shortcut() or not Settings.gui_disconnected_players_enabled or TableMergeState.is_merged() or not self._disconnected.is_clear_enabled:
            return
        self._clear_disconnected_players()
