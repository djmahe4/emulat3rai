"""
emulat3rai – modular x64 instruction-level emulator.

Public API::

    from src.session import EmulatorSession
    from src.config  import EmulatorConfig
    from src.observers import BaseObserver, EVT_INSTRUCTION
    from src.hooks   import HookRegistry, build_default_registry
"""
from .config    import EmulatorConfig
from .session   import EmulatorSession
from .observers import BaseObserver, ObserverMixin
from .hooks     import HookRegistry, build_default_registry
from .analyzer  import resolve_function_name, list_functions, hexdump

__all__ = [
    "EmulatorConfig",
    "EmulatorSession",
    "BaseObserver",
    "ObserverMixin",
    "HookRegistry",
    "build_default_registry",
    "resolve_function_name",
    "list_functions",
    "hexdump",
]