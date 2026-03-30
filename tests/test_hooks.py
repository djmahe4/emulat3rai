import unittest
from unittest.mock import MagicMock
from src.hooks import HookManager, hook, StopEmulation, _GLOBAL_HOOKS, HookRegistry

class TestHookSystem(unittest.TestCase):
    def setUp(self):
        _GLOBAL_HOOKS.clear()
        self.emu = MagicMock()
        self.emu.getArchName.return_value = "amd64"
        self.emu.getRegisterByName.side_effect = lambda x: 0

    def test_hook_decorator(self):
        @hook("NtCreateFile")
        def my_hook(emu, args): pass
        self.assertIn("NtCreateFile", _GLOBAL_HOOKS)

    def test_maybe_fire_manager(self):
        called = False
        @hook("NtTerminateProcess")
        def exit_hook(emu, args):
            nonlocal called
            called = True
            return 0
            
        mgr = HookManager(self.emu)
        mgr.maybe_fire("NtTerminateProcess")
        self.assertTrue(called)

    def test_hook_registry_local(self):
        registry = HookRegistry()
        called = False

        @registry.hook("Local.Func")
        def local_hook(emu, args):
            nonlocal called
            called = True
            return 1

        registry.maybe_fire("Local.Func", self.emu)
        self.assertTrue(called)

    def test_stop_emulation_exception(self):
        @hook("ExitProcess")
        def exit_now(emu, args):
            raise StopEmulation(0x1337)
            
        mgr = HookManager(self.emu)
        with self.assertRaises(StopEmulation) as cm:
            mgr.maybe_fire("ExitProcess")
        self.assertEqual(cm.exception.exit_code, 0x1337)

if __name__ == '__main__':
    unittest.main()
