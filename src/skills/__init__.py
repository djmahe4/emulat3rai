"""
emulat3rai skills package.

Skills are small, focused extensions that integrate with the observer /
hook system to add specialised analysis capabilities.

Available skills:
- anti_loophole_detector  – detect REP/loop instructions that may spin
- deep_explore            – automatically follow and log call trees
"""
from .anti_loophole_detector import AntiLoopholeDetector
from .deep_explore import DeepExploreObserver

__all__ = ["AntiLoopholeDetector", "DeepExploreObserver"]
