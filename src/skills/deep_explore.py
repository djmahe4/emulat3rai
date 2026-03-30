"""
Skill: Deep Explore Observer

Logs and analyses the full call tree encountered during emulation,
including call depth, targets, and return values.

Usage::

    from src.skills import DeepExploreObserver

    explorer = DeepExploreObserver()
    session.set_observer(explorer)
    session.run()

    explorer.print_tree()
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..observers import BaseObserver, EVT_CALL, EVT_RETURN, EVT_HOOK_FIRED


class _CallNode:
    def __init__(self, from_va: int, target: int, depth: int) -> None:
        self.from_va  = from_va
        self.target   = target
        self.depth    = depth
        self.children: List["_CallNode"] = []
        self.ret_va: Optional[int] = None
        self.hook_name: Optional[str] = None


class DeepExploreObserver(BaseObserver):
    """
    Observer that builds a call tree from EVT_CALL / EVT_RETURN events.

    Attributes:
        call_log:    flat list of call event dicts
        return_log:  flat list of return event dicts
        hook_log:    flat list of hook-fired event dicts
    """

    def __init__(self) -> None:
        self.call_log:   List[Dict] = []
        self.return_log: List[Dict] = []
        self.hook_log:   List[Dict] = []
        self._stack:  List[_CallNode] = []
        self._root_calls: List[_CallNode] = []

    # ------------------------------------------------------------------
    def on_call(self, *, event: str, from_va: int, target: int,
                depth: int, emu: Any, **kwargs: Any) -> None:
        entry = {"from_va": f"0x{from_va:x}", "target": f"0x{target:x}",
                 "depth": depth}
        self.call_log.append(entry)

        node = _CallNode(from_va, target, depth)
        if self._stack:
            self._stack[-1].children.append(node)
        else:
            self._root_calls.append(node)
        self._stack.append(node)

    def on_return(self, *, event: str, from_va: int, ret_va: int,
                  depth: int, emu: Any, **kwargs: Any) -> None:
        entry = {"from_va": f"0x{from_va:x}", "ret_va": f"0x{ret_va:x}",
                 "depth": depth}
        self.return_log.append(entry)

        if self._stack:
            node = self._stack.pop()
            node.ret_va = ret_va

    def on_hook_fired(self, *, event: str, hook_name: str, args: tuple,
                      ret_val: Any, emu: Any, **kwargs: Any) -> None:
        entry = {
            "hook":    hook_name,
            "args":    [f"0x{a:x}" if isinstance(a, int) else str(a) for a in args],
            "ret_val": f"0x{ret_val:x}" if isinstance(ret_val, int) else str(ret_val),
        }
        self.hook_log.append(entry)

        # annotate the topmost call node with the hook name
        if self._stack:
            self._stack[-1].hook_name = hook_name

    # ------------------------------------------------------------------
    def print_tree(self) -> None:
        print("Call tree:")
        for node in self._root_calls:
            self._print_node(node, indent=2)
        if self.hook_log:
            print("\nAPI hooks fired:")
            for item in self.hook_log:
                args_str = ", ".join(item["args"])
                print(f"  {item['hook']}({args_str}) -> {item['ret_val']}")

    def _print_node(self, node: _CallNode, indent: int) -> None:
        ret_str = f" -> ret=0x{node.ret_va:x}" if node.ret_va else ""
        hook_str = f" [{node.hook_name}]" if node.hook_name else ""
        print(" " * indent + f"0x{node.from_va:x} → 0x{node.target:x}{hook_str}{ret_str}")
        for child in node.children:
            self._print_node(child, indent + 2)

    def summary(self) -> Dict:
        return {
            "total_calls":    len(self.call_log),
            "total_returns":  len(self.return_log),
            "hooks_fired":    len(self.hook_log),
            "max_depth":      max((e["depth"] for e in self.call_log), default=0),
        }
