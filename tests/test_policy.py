import copy
import json
import unittest

from mirage.policy import PolicyError, measured_policy


def sample_ruleset(interface="p123w"):
    entries = [
        {"metainfo": {"version": "1.0"}},
        {"table": {"family": "inet", "name": "mirage", "handle": 1}},
        {"chain": {"family": "inet", "table": "mirage", "name": "output", "policy": "drop", "handle": 2}},
        {"chain": {"family": "inet", "table": "mirage", "name": "input", "policy": "drop", "handle": 3}},
    ]
    for number in range(7):
        expression = [{"match": {"left": {"meta": {"key": "iifname"}}, "right": interface if number == 4 else "10.77.2.2", "op": "=="}}, {"accept": None}]
        entries.append({"rule": {"family": "inet", "table": "mirage", "chain": "input" if number == 4 else "output", "expr": expression, "handle": 10 + number}})
    return {"nftables": entries}


class PolicyTests(unittest.TestCase):
    def test_digest_comes_from_measured_rules_and_normalizes_ephemeral_fields(self):
        first, digest = measured_policy(json.dumps(sample_ruleset()), "p123w")
        other = sample_ruleset("p456w")
        other["nftables"][1]["table"]["handle"] = 999
        _, other_digest = measured_policy(json.dumps(other), "p456w")
        self.assertEqual(digest, other_digest)
        self.assertIn("MIRAGE_WORKLOAD_INTERFACE", json.dumps(first))
        changed = copy.deepcopy(other)
        changed["nftables"][-1]["rule"]["expr"][-1] = {"drop": None}
        self.assertNotEqual(digest, measured_policy(json.dumps(changed), "p456w")[1])

    def test_missing_rule_or_default_accept_fails_closed(self):
        missing = sample_ruleset()
        missing["nftables"].pop()
        with self.assertRaisesRegex(PolicyError, "count"):
            measured_policy(json.dumps(missing), "p123w")
        open_chain = sample_ruleset()
        open_chain["nftables"][2]["chain"]["policy"] = "accept"
        with self.assertRaisesRegex(PolicyError, "default to drop"):
            measured_policy(json.dumps(open_chain), "p123w")


if __name__ == "__main__":
    unittest.main()
