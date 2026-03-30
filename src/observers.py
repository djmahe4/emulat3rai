"""
Observer / callback system for emulat3rai.

Any component (CLI printer, JSON exporter, agent hook …) can register
callbacks that fire at well-defined emulation events without touching the
core emulator logic.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional


# ---------------------------------------------------------------------------
# Event names (string constants so external code can reference them safely)
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
    EVT_INSTRUCTION,
    EVT_MEM_WRITE,
    EVT_MEM_READ,
    EVT_EXCEPTION,
    EVT_CALL,
    EVT_RETURN,
    EVT_HOOK_FIRED,
    EVT_SESSION_START,
    EVT_SESSION_END,
)

# Callback type alias: fn(event_name, **kwargs) -> None
Callback = Callable[..., None]


# ---------------------------------------------------------------------------
# ObserverMixin – lightweight publish/subscribe
# ---------------------------------------------------------------------------
class ObserverMixin:
    """
    Mix-in that adds publish/subscribe capabilities to any class.

    Usage::

        class MySession(ObserverMixin):
            ...

        session.on(EVT_INSTRUCTION, my_handler)
        session.emit(EVT_INSTRUCTION, step=1, va=0x1000, insn="nop")
    """

    def __init__(self) -> None:
        self._listeners: Dict[str, List[Callback]] = {evt: [] for evt in ALL_EVENTS}

    # ------------------------------------------------------------------
    def on(self, event: str, callback: Callback) -> None:
        """Register *callback* for *event*."""
        if event not in self._listeners:
            self._listeners[event] = []
        self._listeners[event].append(callback)

    def off(self, event: str, callback: Callback) -> None:
        """Unregister *callback* for *event* (silently ignores if not found)."""
        try:
            self._listeners[event].remove(callback)
        except (KeyError, ValueError):
            pass

    def emit(self, event: str, **kwargs: Any) -> None:
        """Fire all callbacks registered for *event*, passing **kwargs**."""
        for cb in list(self._listeners.get(event, [])):
            try:
                cb(event=event, **kwargs)
            except Exception:
                # observers must not crash the emulator
                pass

    def set_observer(self, observer: "BaseObserver") -> None:
        """Convenience: register all methods of a BaseObserver instance."""
        observer._attach(self)


# ---------------------------------------------------------------------------
# BaseObserver – subclass this for structured observers
# ---------------------------------------------------------------------------
class BaseObserver:
    """
    Subclass and override the on_* methods you care about.

    Example::

        class MyObserver(BaseObserver):
            def on_instruction(self, *, event, step, va, insn, emu, **kw):
                print(f"[{step}] 0x{va:x}: {insn}")
    """

    def on_instruction(self, *, event: str, step: int, va: int, insn: str,
                       emu: Any, **kwargs: Any) -> None:
        pass

    def on_memory_write(self, *, event: str, va: int, data: bytes,
                        emu: Any, **kwargs: Any) -> None:
        pass

    def on_memory_read(self, *, event: str, va: int, size: int,
                       emu: Any, **kwargs: Any) -> None:
        pass

    def on_exception(self, *, event: str, exc: Exception, va: int,
                     emu: Any, **kwargs: Any) -> None:
        pass

    def on_call(self, *, event: str, from_va: int, target: int,
                depth: int, emu: Any, **kwargs: Any) -> None:
        pass

    def on_return(self, *, event: str, from_va: int, ret_va: int,
                  depth: int, emu: Any, **kwargs: Any) -> None:
        pass

    def on_hook_fired(self, *, event: str, hook_name: str, args: tuple,
                      ret_val: Any, emu: Any, **kwargs: Any) -> None:
        pass

    def on_session_start(self, *, event: str, va: int, config: Any,
                         **kwargs: Any) -> None:
        pass

    def on_session_end(self, *, event: str, steps: int, va: int,
                       config: Any, **kwargs: Any) -> None:
        pass

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    _METHOD_MAP = {
        EVT_INSTRUCTION:   "on_instruction",
        EVT_MEM_WRITE:     "on_memory_write",
        EVT_MEM_READ:      "on_memory_read",
        EVT_EXCEPTION:     "on_exception",
        EVT_CALL:          "on_call",
        EVT_RETURN:        "on_return",
        EVT_HOOK_FIRED:    "on_hook_fired",
        EVT_SESSION_START: "on_session_start",
        EVT_SESSION_END:   "on_session_end",
    }

    def _attach(self, mixin: ObserverMixin) -> None:
        for evt, method in self._METHOD_MAP.items():
            mixin.on(evt, getattr(self, method))
