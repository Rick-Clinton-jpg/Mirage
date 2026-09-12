import json
from pathlib import Path
import tempfile
import unittest

from mirage.demo import write_demo
from mirage.evidence import EvidenceError, load_records


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "evidence.jsonl"

    def tearDown(self):
        self.temporary.cleanup()

    def test_demo_chain_loads(self):
        write_demo(self.path)
        records = load_records(self.path)
        self.assertEqual(records[0]["type"], "run_start")
        self.assertEqual(records[-1]["type"], "run_end")

    def test_modified_record_is_rejected(self):
        write_demo(self.path)
        lines = self.path.read_text().splitlines()
        record = json.loads(lines[2])
        record["outcome"] = "allowed"
        lines[2] = json.dumps(record, sort_keys=True, separators=(",", ":"))
        self.path.write_text("\n".join(lines) + "\n")
        with self.assertRaisesRegex(EvidenceError, "invalid record hash"):
            load_records(self.path)

    def test_deleted_middle_record_is_rejected(self):
        write_demo(self.path)
        lines = self.path.read_bytes().splitlines(keepends=True)
        self.path.write_bytes(b"".join(lines[:2] + lines[3:]))
        with self.assertRaisesRegex(EvidenceError, "non-sequential evidence id|broken hash link"):
            load_records(self.path)

    def test_incomplete_final_line_is_rejected(self):
        write_demo(self.path)
        self.path.write_bytes(self.path.read_bytes().rstrip(b"\n"))
        with self.assertRaisesRegex(EvidenceError, "incomplete record"):
            load_records(self.path)


if __name__ == "__main__":
    unittest.main()
