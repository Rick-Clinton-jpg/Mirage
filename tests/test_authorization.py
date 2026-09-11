import threading
import unittest

from mirage.authorization import AuthorizationGate


class AuthorizationTests(unittest.TestCase):
    def test_one_token_produces_one_effect_under_contention(self):
        gate = AuthorizationGate()
        token = gate.issue("agent", "write")
        barrier = threading.Barrier(50)
        effects = []
        results = []

        def worker():
            barrier.wait()
            results.append(gate.execute_once(token, "agent", "write", lambda: effects.append(1)))

        threads = [threading.Thread(target=worker) for _ in range(50)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sum(results), 1)
        self.assertEqual(len(effects), 1)

    def test_token_is_bound_to_subject_and_action(self):
        gate = AuthorizationGate()
        token = gate.issue("agent-a", "write")
        self.assertFalse(gate.execute_once(token, "agent-b", "write", lambda: None))
        self.assertFalse(gate.execute_once(token, "agent-a", "delegate", lambda: None))
        self.assertTrue(gate.execute_once(token, "agent-a", "write", lambda: None))


if __name__ == "__main__":
    unittest.main()

