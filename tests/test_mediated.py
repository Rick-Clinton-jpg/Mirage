import unittest

from mirage.mediated import (
    Destination,
    ExternalNetworkGuard,
    FixedUpstreamMediator,
    Principal,
    run_mediated_experiment,
)


class MediatedTests(unittest.TestCase):
    def test_permitted_mediator_reaches_only_fixed_upstream(self):
        guard = ExternalNetworkGuard()
        mediator = FixedUpstreamMediator(guard)
        self.assertTrue(mediator.request("/artifact/a.whl"))
        self.assertFalse(mediator.request("/?target=https://example.invalid"))

    def test_total_mediator_compromise_still_cannot_escape(self):
        guard = ExternalNetworkGuard()
        mediator = FixedUpstreamMediator(guard)
        self.assertFalse(mediator.compromised_forward(Destination.PROHIBITED_EXTERNAL))

    def test_workload_cannot_reach_management_plane(self):
        guard = ExternalNetworkGuard()
        self.assertFalse(guard.connect(Principal.WORKLOAD, Destination.MEDIATOR_MANAGEMENT))

    def test_full_semantic_experiment(self):
        result = run_mediated_experiment(latency_bound_ms=100.0)
        self.assertTrue(result.destination_confined)
        self.assertTrue(result.request_confined)
        self.assertTrue(result.compromise_contained)
        self.assertTrue(result.identity_separated)
        self.assertTrue(result.management_isolated)
        self.assertTrue(result.detected_within_bound)


if __name__ == "__main__":
    unittest.main()
