"""
Observer / callback system for emulat3rai.

Any component can register callbacks for emulation events (INSTRUCTION, MEM_WRITE, etc).
Refactored for thread-safety and robust error handling.
"""
from __future__ import annotations

import logging
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Event Names
# ---------------------------------------------------------------------------
EVT_INSTRUCTION   = "on_instruction"
EVT_MEM_WRITE     = "on_memory_write"
EVT_MEM_READ      = "on_memory_read"
EVT_EXCEPTION     = "on_exception"
EVT_CALL          = "on_call"
EVT_RETURN        = "on_return"
EVT_HOOK_FIRED    = "on_hook_fired"
EVT_SESSION_START = "on_session_start"
EVT_SESSION_END   = "on_session_end"

ALL_EVENTS = (
    EVT_INSTRUCTION, EVT_MEM_WRITE, EVT_MEM_READ,
    EVT_EXCEPTION, EVT_CALL, EVT_RETURN,
    EVT_HOOK_FIRED, EVT_SESSION_START, EVT_SESSION_END
)

# Callback signature: fn(event: str, **kwargs) -> None
Callback = Callable[..., None]

# ---------------------------------------------------------------------------
# EventManager
# ---------------------------------------------------------------------------
class EventManager:
    """
    Central event dispatcher. Thread-safe and robust.
    """
    def __init__(self):
        self._lock = threading.Lock()
        self._listeners: Dict[str, List[Callback]] = {evt: [] for evt in ALL_EVENTS}

    def on(self, event: str, callback: Callback) -> None:
        """Register a callback for an event."""
        with self._lock:
            if event not in self._listeners:
                self._listeners[event] = []
            self._listeners[event].append(callback)

    def off(self, event: str, callback: Callback) -> None:
        """Unregister a callback."""
        with self._lock:
            try:
                self._listeners[event].remove(callback)
            except (KeyError, ValueError):
                pass

    def emit(self, event: str, **kwargs: Any) -> None:
        """
        Dispatches an event to all listeners.
        Safe against listener crashes.
        """
        # Snapshot listeners to avoid holding lock during execution
        with self._lock:
            listeners = list(self._listeners.get(event, []))

        for cb in listeners:
            try:
                cb(event=event, **kwargs)
            except Exception as exc:
                logger.error("Observer Error [%s]: %s", event, exc)
                # Observers MUST NOT crash the main emulation loop

    def attach_observer(self, observer: BaseObserver) -> None:
        """Convenience: register all matching methods of an observer instance."""
        for evt in ALL_EVENTS:
            method_name = f"on_{evt.split('_', 1)[1]}" # e.g. on_instruction
            if hasattr(observer, method_name):
                self.on(evt, getattr(observer, method_name))

# ---------------------------------------------------------------------------
# BaseObserver
# ---------------------------------------------------------------------------
class BaseObserver:
    """
    Interface for structured observers.
    Subclass and override methods.
    """
    def on_instruction(self, *, event: str, step: int, va: int, insn: str, emu: Any, **kw): pass
    def on_memory_write(self, *, event: str, va: int, data: bytes, emu: Any, **kw): pass
    def on_memory_read(self, *, event: str, va: int, size: int, emu: Any, **kw): pass
    def on_exception(self, *, event: str, exc: Exception, va: int, emu: Any, **kw): pass
    def on_call(self, *, event: str, from_va: int, target: int, depth: int, emu: Any, **kw): pass
    def on_return(self, *, event: str, from_va: int, ret_va: int, depth: int, emu: Any, **kw): pass
    def on_hook_fired(self, *, event: str, hook_name: str, args: tuple, ret_val: Any, emu: Any, **kw): pass
    def on_session_start(self, *, event: str, va: int, config: Any, **kw): pass
    def on_session_end(self, *, event: str, steps: int, va: int, config: Any, **kw): pass

# ---------------------------------------------------------------------------
# Backward Compatibility Shim
# ---------------------------------------------------------------------------
class ObserverMixin:
    """Shim for older code expecting ObserverMixin."""
    def __init__(self):
        # This will be initialized by the class using the mixin
        if not hasattr(self, '_event_mgr'):
            self._event_mgr = EventManager()
    
    def on(self, event: str, callback: Callback):
        self._event_mgr.on(event, callback)
    
    def off(self, event: str, callback: Callback):
        self._event_mgr.off(event, callback)
    
    def emit(self, event: str, **kwargs):
        self._event_mgr.emit(event, **kwargs)
    
    def set_observer(self, observer: BaseObserver):
        self._event_mgr.attach_observer(observer)
