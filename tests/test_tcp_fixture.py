import errno
import unittest
from unittest import mock

from mirage.tcp_fixture import request


class TcpFixtureTests(unittest.TestCase):
    def test_connect_errno_is_distinct_from_later_socket_failure(self):
        with mock.patch("mirage.tcp_fixture.socket.socket") as factory:
            client = factory.return_value
            client.connect.side_effect = OSError(errno.ENETUNREACH, "Network is unreachable")
            result = request("10.77.2.2", 18082)
            self.assertEqual((result["error_stage"], result["errno_name"]), ("connect", "ENETUNREACH"))
            self.assertFalse(result["connected"])

            client.connect.side_effect = None
            client.recv.side_effect = OSError(errno.ECONNRESET, "Connection reset")
            result = request("10.77.2.2", 18082)
            self.assertEqual((result["error_stage"], result["errno_name"]), ("recv", "ECONNRESET"))


if __name__ == "__main__":
    unittest.main()
