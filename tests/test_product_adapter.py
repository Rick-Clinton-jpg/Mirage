from pathlib import Path
import tempfile
import unittest
from unittest import mock

from mirage.product_adapter import ProductAdapterError, _validate_process_identity, probe_apt_cacher_ng


class ProductAdapterTests(unittest.TestCase):
    def test_absent_product_fails_closed(self):
        with mock.patch("mirage.product_adapter.shutil.which", return_value=None):
            with self.assertRaisesRegex(ProductAdapterError, "not installed"):
                probe_apt_cacher_ng(pid=123, configuration="/tmp/acng.conf", host="10.77.1.1", port=18080)

    def test_unreachable_tested_endpoint_fails_closed(self):
        with tempfile.NamedTemporaryFile() as executable, tempfile.NamedTemporaryFile() as configuration:
            with mock.patch("mirage.product_adapter.shutil.which", return_value=executable.name), mock.patch("mirage.product_adapter._process_identity", return_value={"pid": 123}), mock.patch("mirage.product_adapter.subprocess.run") as run, mock.patch("mirage.product_adapter.socket.create_connection", side_effect=OSError):
                run.return_value.returncode = 0
                run.return_value.stdout = "3.7.5"
                with self.assertRaisesRegex(ProductAdapterError, "tested apt-cacher-ng"):
                    probe_apt_cacher_ng(pid=123, configuration=configuration.name, host="10.77.1.1", port=18080)

    def test_process_must_match_executable_config_namespace_and_privileges(self):
        executable = Path("/bin/sh")
        config = Path("/tmp/acng")
        command = [b"/bin/sh", b"-c", b"/tmp/acng"]
        status = "Uid:\t65534\t65534\t65534\t65534\nCapEff:\t0000000000000000\n"
        _validate_process_identity(executable.resolve(), executable, command, status, 1234, 1234, config)
        with self.assertRaisesRegex(ProductAdapterError, "configuration differs"):
            _validate_process_identity(executable.resolve(), executable, command[:-1], status, 1234, 1234, config)
        with self.assertRaisesRegex(ProductAdapterError, "capabilities"):
            _validate_process_identity(executable.resolve(), executable, command, status.replace("0000000000000000", "0000000000001000"), 1234, 1234, config)
        with self.assertRaisesRegex(ProductAdapterError, "namespaces"):
            _validate_process_identity(executable.resolve(), executable, command, status, 1234, 5678, config)


if __name__ == "__main__":
    unittest.main()
