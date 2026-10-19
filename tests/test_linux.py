from pathlib import Path
import tempfile
import unittest
from unittest import mock

from mirage.linux import LinuxExperimentError, _arm_witness, run_linux_experiment


class LinuxTests(unittest.TestCase):
    def test_witness_wait_mismatch_fails_before_topology(self):
        class Stream:
            def __init__(self):
                self.written = b""
            def write(self, value):
                self.written += value
            def readline(self, _):
                return b"ARMED 1\n"
        stream = Stream()
        with self.assertRaisesRegex(LinuxExperimentError, "SIGN wait differs"):
            _arm_witness(stream, 5)
        self.assertEqual(stream.written, b"ARM LIVE\n")

    def test_linux_experiment_rejects_invalid_trial_count(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises((ValueError, LinuxExperimentError)):
                run_linux_experiment(Path(temporary) / "out", trials=0)

    def test_linux_experiment_fails_closed_off_linux(self):
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch("mirage.linux.sys.platform", "darwin"):
                with self.assertRaisesRegex(LinuxExperimentError, "root on Linux"):
                    run_linux_experiment(Path(temporary) / "out")

    def test_incident_profile_requires_pretrusted_remote_witness(self):
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch("mirage.linux.sys.platform", "linux"), mock.patch("mirage.linux.os.geteuid", return_value=0):
                with self.assertRaisesRegex(LinuxExperimentError, "pre-trusted remote witness"):
                    run_linux_experiment(Path(temporary) / "out", incident_profile=True)

    def test_assured_profile_requires_offline_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch("mirage.linux.sys.platform", "linux"), mock.patch("mirage.linux.os.geteuid", return_value=0):
                with self.assertRaisesRegex(LinuxExperimentError, "signed assurance bundle"):
                    run_linux_experiment(Path(temporary) / "out", assured_egress=True)


if __name__ == "__main__":
    unittest.main()
