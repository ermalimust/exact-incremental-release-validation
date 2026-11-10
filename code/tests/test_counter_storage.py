"""Hot mutation counters must not update the immutable workload metadata row."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from adaptive_gateway import AdaptiveGateway,POLICIES


class CounterStorageTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
    def test_all_policies_change_only_the_separate_counter_row(self):
        for policy in POLICIES:
            with self.subTest(policy=policy):
                with AdaptiveGateway(Path(self.temp.name)/(policy+".sqlite"),policy,clock=lambda:1.0) as gate:
                    gate.put_subject("evidence",1000)
                    payload=json.dumps({"large_registry":"x"*(2*1024*1024)})
                    gate.db.execute("UPDATE network_meta SET workload=?",(payload,))
                    statements=[]
                    gate.db.set_trace_callback(statements.append)
                    gate.refresh("evidence",2000)
                    gate.refresh("evidence",3000)
                    gate.db.set_trace_callback(None)
                    self.assertEqual(gate._global(),2)
                    self.assertFalse(any("UPDATE NETWORK_META" in s.upper() for s in statements))
                    row=gate.db.execute("SELECT global_epoch,workload FROM network_meta").fetchone()
                    self.assertEqual(tuple(row),(0,payload))
                    history=[r[0] for r in gate.db.execute("SELECT seq FROM mutation_history ORDER BY seq")]
                    self.assertEqual(history,[1,2] if policy=="adaptive_delta" else [])
                    self.assertEqual(gate.inspect()["metadata"]["global_epoch"],2)
    def test_closed_legacy_database_counter_is_seeded_once(self):
        db=Path(self.temp.name)/"legacy.sqlite"
        with AdaptiveGateway(db,clock=lambda:1.0) as gate:
            gate.put_subject("evidence",1000)
            gate.db.execute("DROP TABLE adaptive_clock")
            gate.db.execute("UPDATE network_meta SET global_epoch=7")
        with AdaptiveGateway(db,clock=lambda:2.0) as gate:
            self.assertEqual(gate._global(),7)
            gate.refresh("evidence",2000)
            self.assertEqual(gate._global(),8)
        with AdaptiveGateway(db,clock=lambda:3.0) as gate:
            self.assertEqual(gate._global(),8)


if __name__=="__main__":unittest.main()
