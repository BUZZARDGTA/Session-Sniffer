"""Global OS hotkeys and window-scoped keyboard shortcuts mixin for `MainWindow`."""

import logging
import sys
from typing import TYPE_CHECKING, Literal, override

from PySide6.QtCore import QByteArray, Qt
from PySide6.QtGui import QAction, QKeySequence, QShortcut
from PySide6.QtWidgets import QMainWindow
from shiboken6 import isValid

from session_sniffer.background import trigger_looky_rescan_all_players
from session_sniffer.background.events import gui_closed__event
from session_sniffer.ctypes_windows import parse_win32_hotkey_message, register_win32_hotkey, unregister_win32_hotkey
from session_sniffer.guis.interface_selection_dialog import InterfaceSelectionDialog
from session_sniffer.i18n import tr
from session_sniffer.notifications_state import notifications_state
from session_sniffer.player.registry import SessionTracker
from session_sniffer.rendering_core.events import wake_rendering_core
from session_sniffer.rendering_core.types import CaptureState, SessionFilterState, TableMergeState
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    from collections.abc import Callable

    from session_sniffer.guis._main_header import SessionHeader
    from session_sniffer.guis._session_table_section import SessionTableSection
    from session_sniffer.guis.loading_overlay import LoadingOverlay
    from session_sniffer.guis.main_window import MainMenuActions
    from session_sniffer.guis.settings_dialog import SettingsDialog

logger = logging.getLogger(__name__)

_HOTKEY_BASE_ID = 0x5350
_MOD_ALT = 0x0001
_MOD_CONTROL = 0x0002
_MOD_SHIFT = 0x0004
_MOD_WIN = 0x0008
_MAX_F_KEY_NUMBER = 24

_PORTABLE_KEY_TO_WIN32_VKS: dict[str, tuple[int, ...]] = {
    'backspace': (0x08,), 'tab': (0x09,), 'clear': (0x0C,), 'return': (0x0D,), 'enter': (0x0D,), 'pause': (0x13,), 'capslock': (0x14,),
    'space': (0x20,), 'pgup': (0x21,), 'pgdown': (0x22,), 'end': (0x23,), 'home': (0x24,), 'left': (0x25,),
    'up': (0x26,), 'right': (0x27,), 'down': (0x28,), 'print': (0x2C,), 'ins': (0x2D,), 'del': (0x2E,),
    '!': (0x31,), '@': (0x32,), '#': (0x33,), '$': (0x34,), '%': (0x35,), '^': (0x36,), '&': (0x37,), '(': (0x39,), ')': (0x30,),
    '-': (0x6D, 0xBD), '_': (0xBD,), '.': (0x6E, 0xBE), '/': (0x6F, 0xBF), '?': (0xBF,),
    'numlock': (0x90,), 'scrolllock': (0x91,), ';': (0xBA,), ':': (0xBA,), '=': (0xBB,), ',': (0xBC,), '<': (0xBC,), '>': (0xBE,),
    '`': (0xC0,), '~': (0xC0,), '[': (0xDB,), '{': (0xDB,), '\\': (0xDC,), '|': (0xDC,), ']': (0xDD,), '}': (0xDD,), "'": (0xDE,), '"': (0xDE,),
}


def _resolve_portable_key_vks(portable_key: str, *, mod_flags: int = 0, is_numpad: bool = False) -> tuple[int, ...] | None:
    """Resolve a lowercase portable key string to one or more Win32 virtual-key codes."""
    if portable_key == '*':
        return (0x38, 0x6A) if (mod_flags & _MOD_SHIFT) and not is_numpad else (0x6A,)
    if portable_key == '+':
        return (0x6B, 0xBB) if (mod_flags & _MOD_SHIFT) and not is_numpad else (0x6B,)
    if (mapped := _PORTABLE_KEY_TO_WIN32_VKS.get(portable_key)) is not None:
        return mapped
    if len(portable_key) == 1 and ('a' <= portable_key <= 'z' or '0' <= portable_key <= '9'):
        return (ord(portable_key.upper()),) if 'a' <= portable_key <= 'z' else (ord(portable_key), 0x60 + ord(portable_key) - ord('0'))
    if portable_key.startswith('f') and portable_key[1:].isdigit() and 1 <= (fn_num := int(portable_key[1:])) <= _MAX_F_KEY_NUMBER:
        return (0x70 + fn_num - 1,)
    return None


def parse_win32_hotkey_spec(hotkey: str | None) -> tuple[int, tuple[int, ...]] | None:
    """Translate a portable `QKeySequence` string into `(win32_modifier_flags, primary_vks)`."""
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
        for mod_prefix, flag in (('ctrl+', _MOD_CONTROL), ('shift+', _MOD_SHIFT), ('alt+', _MOD_ALT), ('meta+', _MOD_WIN)):
            if portable.startswith(mod_prefix):
                mod_flags |= flag
                portable = portable[len(mod_prefix) :]
                break

    primary_vks = _resolve_portable_key_vks(portable, mod_flags=mod_flags, is_numpad=is_numpad)
    return (mod_flags, primary_vks) if primary_vks is not None else None


def format_action_with_shortcut(text: str, shortcut: str | None) -> str:
    """Return *text* suffixed with `[shortcut]` when *shortcut* is configured."""
    return f'{text} [{shortcut}]' if bool(shortcut) else text


def append_shortcut_tooltip(tooltip: str, shortcut: str | None, *, is_global: bool = False) -> str:
    """Append a localized shortcut or global hotkey hint line to *tooltip* when *shortcut* is configured."""
    if shortcut is None or not shortcut:
        return tooltip
    suffix = tr('Global Hotkey: {hotkey}', hotkey=shortcut) if is_global else tr('Shortcut: {shortcut}', shortcut=shortcut)
    return f'{tooltip}\n\n{suffix}' if tooltip else suffix


class ShortcutsMixin(QMainWindow):
    """Manage system-wide global hotkeys and main-window keyboard shortcuts on `MainWindow`."""

    _shortcuts_initialized: bool = False
    _registered_win32_hotkeys: list[tuple[int, int]]
    _hotkey_id_to_handler: dict[int, Callable[[], None]]
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
        self._registered_win32_hotkeys = []
        self._hotkey_id_to_handler = {}
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

    def _unregister_global_hotkeys(self) -> None:
        """Unregister all active OS-level global hotkeys and disable fallback `QShortcut`s."""
        if not self._shortcuts_initialized:
            return
        if sys.platform == 'win32' and self._registered_win32_hotkeys:
            for hwnd, hotkey_id in self._registered_win32_hotkeys:
                unregister_win32_hotkey(hwnd, hotkey_id)
            self._registered_win32_hotkeys.clear()
        self._hotkey_id_to_handler.clear()
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

        next_hotkey_id = _HOTKEY_BASE_ID
        hwnd = self.winId() if sys.platform == 'win32' else 0
        for setting_key, is_applicable, handler in self._global_hotkey_specs():
            fallback_shortcut = self._global_fallback_shortcuts[setting_key]
            chord = Settings.get_active_shortcut(setting_key) if is_applicable() else None
            if chord is None:
                continue
            if sys.platform == 'win32':
                spec = parse_win32_hotkey_spec(chord)
                registered_any = False
                if spec is not None:
                    mod_flags, primary_vks = spec
                    for vk_code in primary_vks:
                        hotkey_id = next_hotkey_id
                        next_hotkey_id += 1
                        if register_win32_hotkey(hwnd, hotkey_id, mod_flags, vk_code):
                            self._registered_win32_hotkeys.append((hwnd, hotkey_id))
                            self._hotkey_id_to_handler[hotkey_id] = handler
                            registered_any = True
                if not registered_any:
                    logger.warning('Failed to register global OS hotkey %r for %s; falling back to window shortcut.', chord, setting_key)
                    fallback_shortcut.setKey(QKeySequence.fromString(chord, QKeySequence.SequenceFormat.PortableText))
                    fallback_shortcut.setEnabled(True)
            else:
                fallback_shortcut.setKey(QKeySequence.fromString(chord, QKeySequence.SequenceFormat.PortableText))
                fallback_shortcut.setEnabled(True)

    def _sync_shortcut_action_labels(self) -> None:
        """Refresh menu action texts and widget tooltips that display configured shortcuts."""
        if not self._shortcuts_initialized:
            return
        self._sync_capture_toggle_action()
        open_settings_shortcut = Settings.get_active_shortcut('shortcut_open_settings')
        self._open_settings_action.setText(format_action_with_shortcut(tr('Open Settings'), open_settings_shortcut))
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

    @override
    def nativeEvent(self, eventType: QByteArray | bytes | bytearray | memoryview, message: int) -> object:
        """Handle native OS window messages such as Win32 `WM_HOTKEY` events."""
        if sys.platform == 'win32' and self._shortcuts_initialized and self._hotkey_id_to_handler:
            hotkey_id = parse_win32_hotkey_message(message)
            if hotkey_id is not None and (handler := self._hotkey_id_to_handler.get(hotkey_id)) is not None:
                handler()
                return True, 0
        return super().nativeEvent(eventType, message)

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
