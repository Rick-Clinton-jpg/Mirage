from pathlib import Path
import tempfile
import unittest
from unittest import mock

from mirage.product_adapter import ProductAdapterError, probe_apt_cacher_ng


class ProductAdapterTests(unittest.TestCase):
    def test_absent_product_fails_closed(self):
        with mock.patch("mirage.product_adapter.shutil.which", return_value=None):
            with self.assertRaisesRegex(ProductAdapterError, "not installed"):
                probe_apt_cacher_ng()

    def test_unreachable_product_fails_closed(self):
        with tempfile.NamedTemporaryFile() as executable, mock.patch("mirage.product_adapter.shutil.which", return_value=executable.name), mock.patch("mirage.product_adapter.subprocess.run") as run, mock.patch("mirage.product_adapter.Path.is_file", return_value=True), mock.patch("mirage.product_adapter.socket.create_connection", side_effect=OSError):
            run.return_value.returncode = 0
            run.return_value.stdout = "3.7.5"
            with self.assertRaisesRegex(ProductAdapterError, "live endpoint"):
                probe_apt_cacher_ng()


if __name__ == "__main__":
    unittest.main()
