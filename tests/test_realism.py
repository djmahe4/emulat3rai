import unittest
from unittest.mock import MagicMock, patch
from src.environment import EnvironmentManager
from src.config import EmulatorConfig

class TestRealismSystem(unittest.TestCase):
    def setUp(self):
        self.emu = MagicMock()
        self.emu.getArchName.return_value = "amd64"
        self.emu.getStackCounter.return_value = 0xdeadbeef
        self.emu.getMemorySnap.return_value = []
        self.cfg = EmulatorConfig()

    def test_environment_manager_init(self):
        mgr = EnvironmentManager(self.emu, self.cfg)
        self.assertEqual(mgr.emu, self.emu)
        self.assertEqual(mgr.cfg, self.cfg)

    def test_x64_realism_setup(self):
        self.cfg.realism_level = 1  # MODERATE
        self.emu.stack_map_base = 0x1000
        self.emu.getStackCounter.return_value = 0x2000

        mgr = EnvironmentManager(self.emu, self.cfg)
        mgr.setup()
        
        # Verify peb/teb setup (via addMemoryMap)
        self.assertTrue(self.emu.addMemoryMap.called)

    def test_guest_memory_sanitization(self):
        mgr = EnvironmentManager(self.emu, self.cfg)
        
        # Mock memory map with Writable permission (perm=7 has 2)
        self.emu.getMemoryMaps.return_value = [(0x1000, 0x100, 7, "test")]
        # Mock memory read with a known sensitive string
        self.emu.readMemory.return_value = b"AAA EMULAT3RAI_trace BBB"
        
        mgr.sanitise_guest_env()
        
        # Verify memory write was attempted to overwrite the sensitive string
        self.assertTrue(self.emu.writeMemory.called)

if __name__ == '__main__':
    unittest.main()
