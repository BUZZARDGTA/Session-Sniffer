"""Reusable themed loading overlay and background task runner for blocking GUI operations."""

import time
import weakref
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, cast, override

from PySide6.QtCore import QCoreApplication, QEvent, QEventLoop, QObject, QRectF, Qt, QThread, QTimer, Signal
from PySide6.QtGui import QColor, QFont, QMouseEvent, QPainter, QPaintEvent, QPen, QShowEvent
from PySide6.QtWidgets import QApplication, QFrame, QHBoxLayout, QLabel, QVBoxLayout, QWidget
from shiboken6 import isValid

from session_sniffer.guis._crashing_qthread import CrashingQThread
from session_sniffer.guis.fonts import get_ui_font
from session_sniffer.guis.theming import themed_qcolor, themed_qss
from session_sniffer.guis.utils import scale_by_ui

if TYPE_CHECKING:
    from collections.abc import Callable, Generator

_SPINNER_TICK_MS: Final = 16
_PUMP_INTERVAL_SEC: Final = 0.016
_SPINNER_DEG_PER_SEC: Final = 450.0
_SPINNER_SPAN_SIXTEENTHS: Final = 110 * 16
_FULL_CIRCLE_DEG: Final = 360.0
_BLOCKED_KEY_EVENTS: Final = frozenset({
    QEvent.Type.KeyPress,
    QEvent.Type.KeyRelease,
    QEvent.Type.ShortcutOverride,
})


@dataclass(slots=True)
class _OverlayPumpState:
    last_pump_at: float = 0.0


_PUMP_STATE = _OverlayPumpState()
_ACTIVE_OVERLAYS: weakref.WeakSet[LoadingOverlay] = weakref.WeakSet()


class _SpinnerArcWidget(QWidget):
    """Smooth wall-clock anti-aliased rotating arc indicator."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        diameter = scale_by_ui(34)
        self.setFixedSize(diameter, diameter)
        self._origin_perf = time.perf_counter()
        self._angle_deg = 0.0

    def reset_origin(self) -> None:
        """Reset wall-clock rotation reference when shown."""
        self._origin_perf = time.perf_counter()
        self._angle_deg = 0.0

    def advance(self, *, immediate: bool = False) -> None:
        """Sync rotation angle to wall-clock elapsed time and trigger a repaint."""
        self._angle_deg = ((time.perf_counter() - self._origin_perf) * _SPINNER_DEG_PER_SEC) % _FULL_CIRCLE_DEG
        if immediate:
            self.repaint()
        else:
            self.update()

    @override
    def paintEvent(self, event: QPaintEvent) -> None:
        del event
        self._angle_deg = ((time.perf_counter() - self._origin_perf) * _SPINNER_DEG_PER_SEC) % _FULL_CIRCLE_DEG
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        pen_width = max(2.5, float(scale_by_ui(3)))
        inset = pen_width / 2.0 + 1.5
        arc_rect = QRectF(inset, inset, self.width() - inset * 2.0, self.height() - inset * 2.0)

        track_pen = QPen(themed_qcolor('@border'), pen_width)
        painter.setPen(track_pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawEllipse(arc_rect)

        sweep_pen = QPen(themed_qcolor('@accent'), pen_width, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)
        painter.setPen(sweep_pen)
        painter.drawArc(arc_rect, round(-self._angle_deg * 16.0), -_SPINNER_SPAN_SIXTEENTHS)
        painter.end()


class LoadingOverlay(QWidget):
    """Semi-transparent modal-like busy overlay anchored to a parent window or widget."""

    def __init__(self, parent: QWidget, title: str, status: str = '') -> None:
        """Initialize the overlay covering *parent* with *title* and optional *status* subtitle."""
        super().__init__(parent)
        self._host = parent
        self._closed = False
        self._app_filter_installed = False
        self.setObjectName('loadingOverlayBackdrop')
        self.setAttribute(Qt.WidgetAttribute.WA_NoMousePropagation, on=True)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.setCursor(Qt.CursorShape.WaitCursor)
        self.setGeometry(parent.rect())

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(scale_by_ui(24), scale_by_ui(24), scale_by_ui(24), scale_by_ui(24))
        outer_layout.addStretch()

        center_row = QHBoxLayout()
        center_row.addStretch()

        self._card = QFrame(self)
        self._card.setObjectName('loadingOverlayCard')
        self._card.setMinimumWidth(scale_by_ui(300))
        self._card.setMaximumWidth(scale_by_ui(440))
        self._card.setStyleSheet(
            themed_qss(
                'QFrame#loadingOverlayCard {'
                ' background-color: @popup;'
                ' border: 1px solid @border;'
                ' border-radius: 10px;'
                '}',
            ),
        )

        card_layout = QHBoxLayout(self._card)
        card_layout.setContentsMargins(scale_by_ui(20), scale_by_ui(16), scale_by_ui(22), scale_by_ui(16))
        card_layout.setSpacing(scale_by_ui(16))

        self._spinner = _SpinnerArcWidget(self._card)
        card_layout.addWidget(self._spinner, 0, Qt.AlignmentFlag.AlignVCenter)

        text_col = QVBoxLayout()
        text_col.setContentsMargins(0, 0, 0, 0)
        text_col.setSpacing(scale_by_ui(4))

        self._title_label = QLabel(title, self._card)
        self._title_label.setFont(get_ui_font(11, QFont.Weight.Bold))
        self._title_label.setStyleSheet(themed_qss('color: @accent; background: transparent; border: none;'))
        text_col.addWidget(self._title_label)

        self._status_label = QLabel(status, self._card)
        self._status_label.setFont(get_ui_font(9))
        self._status_label.setStyleSheet(themed_qss('color: @text_muted; background: transparent; border: none;'))
        self._status_label.setWordWrap(True)
        self._status_label.setVisible(bool(status))
        text_col.addWidget(self._status_label)

        card_layout.addLayout(text_col, 1)
        center_row.addWidget(self._card)
        center_row.addStretch()

        outer_layout.addLayout(center_row)
        outer_layout.addStretch()

        self._timer = QTimer(self)
        self._timer.setInterval(_SPINNER_TICK_MS)
        self._timer.timeout.connect(self._spinner.advance)

        parent.installEventFilter(self)
        self.installEventFilter(self)

    @property
    def is_closed(self) -> bool:
        """Return `True` once `close_overlay()` has been called."""
        return self._closed

    def set_status(self, status: str) -> None:
        """Update the secondary status message displayed beneath the title."""
        if not isValid(self) or self._closed:
            return
        self._status_label.setText(status)
        self._status_label.setVisible(bool(status))

    def tick_frame(self) -> None:
        """Immediately advance and paint one spinner frame on this overlay."""
        if not isValid(self) or self._closed or not self.isVisible():
            return
        self.raise_()
        self._spinner.advance(immediate=True)

    def _set_app_key_filter(self, *, enabled: bool) -> None:
        """Install or remove the application-wide keyboard blocker for descendants of `self._host`."""
        app_inst = QCoreApplication.instance()
        if app_inst is None:
            return
        if enabled and not self._app_filter_installed:
            app_inst.installEventFilter(self)
            self._app_filter_installed = True
        elif not enabled and self._app_filter_installed:
            app_inst.removeEventFilter(self)
            self._app_filter_installed = False

    def present_immediately(self) -> None:
        """Show, raise, and synchronously flush one painted frame before main-thread Qt work."""
        if not isValid(self) or self._closed or not isValid(self._host):
            return
        self.setGeometry(self._host.rect())
        self._spinner.reset_origin()
        _ACTIVE_OVERLAYS.add(self)
        self._set_app_key_filter(enabled=True)
        self.show()
        self.raise_()
        self.repaint()
        _PUMP_STATE.last_pump_at = time.perf_counter()
        QApplication.processEvents(QEventLoop.ProcessEventsFlag.ExcludeUserInputEvents)

    @contextmanager
    def suspended(self) -> Generator[None]:
        """Temporarily hide this overlay while displaying an interactive modal prompt."""
        was_visible = isValid(self) and not self._closed and self.isVisible()
        if was_visible:
            self.hide()
        try:
            yield
        finally:
            if was_visible:
                self.present_immediately()

    def run_with_spinner[**P, T](self, fn: Callable[P, T], /, *args: P.args, **kwargs: P.kwargs) -> T:
        """Run *fn* on a background thread while continuously animating this overlay's spinner."""
        return run_with_active_loading(fn, *args, **kwargs)

    def close_overlay(self) -> None:
        """Stop animation, detach filters, and schedule the overlay widget for deletion."""
        if self._closed:
            return
        self._closed = True
        _ACTIVE_OVERLAYS.discard(self)
        self._set_app_key_filter(enabled=False)
        if isValid(self):
            self._timer.stop()
            if isValid(self._host):
                self._host.removeEventFilter(self)
            self.removeEventFilter(self)
            self.hide()
            self.deleteLater()

    @override
    def showEvent(self, event: QShowEvent) -> None:
        super().showEvent(event)
        _ACTIVE_OVERLAYS.add(self)
        self._set_app_key_filter(enabled=True)
        if isValid(self._host):
            self.setGeometry(self._host.rect())
        if not self._timer.isActive():
            self._timer.start()

    def _should_block_key_event(self, watched: QObject, event_type: QEvent.Type) -> bool:
        """Return `True` when *event_type* is a key event targeting this overlay's active host window."""
        if event_type not in _BLOCKED_KEY_EVENTS or self._closed or not isValid(self) or not self.isVisible():
            return False
        if not isValid(self._host) or not isinstance(watched, QWidget):
            return False
        return (watched is self._host or self._host.isAncestorOf(watched)) and watched.window() is self._host.window()

    @override
    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        event_type = event.type()
        if self._should_block_key_event(watched, event_type):
            return True
        if watched is self._host:
            if event_type == QEvent.Type.Resize and isValid(self) and isValid(self._host):
                self.setGeometry(self._host.rect())
        elif watched is self:
            if event_type == QEvent.Type.Hide and isValid(self):
                _ACTIVE_OVERLAYS.discard(self)
                self._set_app_key_filter(enabled=False)
                self._timer.stop()
            elif event_type in (QEvent.Type.MouseButtonDblClick, QEvent.Type.Wheel):
                return True
        return super().eventFilter(watched, event)

    @override
    def mousePressEvent(self, event: QMouseEvent) -> None:
        event.accept()

    @override
    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        event.accept()

    @override
    def paintEvent(self, event: QPaintEvent) -> None:
        del event
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.fillRect(self.rect(), QColor(0, 0, 0, 125))

        if self._card.isVisible():
            card_rect = QRectF(self._card.geometry())
            painter.setPen(Qt.PenStyle.NoPen)
            radius = float(scale_by_ui(12))
            painter.setBrush(QColor(0, 0, 0, 45))
            painter.drawRoundedRect(card_rect.adjusted(-6.0, -3.0, 6.0, 9.0), radius + 3.0, radius + 3.0)
            painter.setBrush(QColor(0, 0, 0, 85))
            painter.drawRoundedRect(card_rect.adjusted(-2.0, 0.0, 2.0, 4.0), radius, radius)
        painter.end()


def has_active_loading_overlay() -> bool:
    """Return `True` when at least one `LoadingOverlay` is currently visible."""
    return any(isValid(ov) and not ov.is_closed and ov.isVisible() for ov in list(_ACTIVE_OVERLAYS))


def pump_active_loading_overlays(*, force: bool = False) -> None:
    """Advance and flush any visible `LoadingOverlay` spinners at ~60 FPS during GUI-thread loops."""
    if not _ACTIVE_OVERLAYS:
        return
    now = time.perf_counter()
    if not force and (now - _PUMP_STATE.last_pump_at) < _PUMP_INTERVAL_SEC:
        return
    app_inst = QCoreApplication.instance()
    if app_inst is None or QThread.currentThread() != app_inst.thread():
        return
    _PUMP_STATE.last_pump_at = now
    any_visible = False
    for overlay in list(_ACTIVE_OVERLAYS):
        if isValid(overlay) and not overlay.is_closed and overlay.isVisible():
            overlay.tick_frame()
            any_visible = True
    if any_visible:
        QApplication.processEvents(QEventLoop.ProcessEventsFlag.ExcludeUserInputEvents)


def run_with_active_loading[**P, T](fn: Callable[P, T], /, *args: P.args, **kwargs: P.kwargs) -> T:
    """Run *fn* on a worker thread while pumping active `LoadingOverlay` spinners every 16 ms."""
    app_inst = QCoreApplication.instance()
    if app_inst is None or QThread.currentThread() != app_inst.thread():
        return fn(*args, **kwargs)
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix='LoadingSpinner') as pool:
        future = pool.submit(fn, *args, **kwargs)
        while not future.done():
            pump_active_loading_overlays(force=True)
            QApplication.processEvents(QEventLoop.ProcessEventsFlag.ExcludeUserInputEvents)
            time.sleep(_PUMP_INTERVAL_SEC)
        return future.result()


def run_blocking_with_loading[T](
    parent: QWidget,
    title: str,
    status: str,
    work_fn: Callable[[], T],
) -> T:
    """Show a `LoadingOverlay` on *parent* and run *work_fn* off-thread while keeping the spinner animated."""
    with loading_overlay_scope(parent, title, status):
        return run_with_active_loading(work_fn)


class _AsyncOverlayWorker(CrashingQThread):
    """Background `CrashingQThread` executing a single callable for `run_async_with_loading`."""

    result_ready: Signal = Signal(object)

    def __init__(self, work_fn: Callable[[], object], *, name: str = 'GuiAsyncTask') -> None:
        super().__init__(name=name)
        self._work_fn = work_fn

    @override
    def _run(self) -> None:
        result = self._work_fn()
        if not self.isInterruptionRequested():
            self.result_ready.emit(result)


@contextmanager
def loading_overlay_scope(parent: QWidget, title: str, status: str = '') -> Generator[LoadingOverlay]:
    """Display an immediate `LoadingOverlay` on *parent* for the duration of a block."""
    overlay = LoadingOverlay(parent, title, status)
    overlay.present_immediately()
    try:
        yield overlay
    finally:
        overlay.close_overlay()


def run_async_with_loading[T](
    parent: QWidget,
    title: str,
    status: str,
    work_fn: Callable[[], T],
    on_done: Callable[[T], None],
) -> None:
    """Run *work_fn* on a background `CrashingQThread` while showing an animated `LoadingOverlay` on *parent*."""
    overlay = LoadingOverlay(parent, title, status)
    overlay.present_immediately()

    worker = _AsyncOverlayWorker(work_fn)

    def _handle_result(raw_result: object) -> None:
        overlay.close_overlay()
        if isValid(parent) and not gui_is_closing():
            on_done(cast('T', raw_result))

    worker.result_ready.connect(_handle_result)
    worker.finished.connect(overlay.close_overlay)
    worker.start()


def gui_is_closing() -> bool:
    """Return `True` when the QApplication instance is absent or shutting down."""
    return QApplication.instance() is None or QApplication.closingDown()
