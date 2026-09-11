from pathlib import Path
import tempfile
import unittest
from unittest import mock

from mirage.topology import TopologyError, run_selective_tcp_topology


class TopologyTests(unittest.TestCase):
    def test_topology_fails_closed_off_linux(self):
        with mock.patch("mirage.topology.sys.platform", "darwin"):
            with self.assertRaisesRegex(TopologyError, "root on Linux"):
                run_selective_tcp_topology()


if __name__ == "__main__":
    unittest.main()
