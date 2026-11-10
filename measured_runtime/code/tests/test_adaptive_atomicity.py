"""Process-death checks for the new exact validators, not only the old gateway."""
from pathlib import Path
import json
import os
import subprocess
import sys
import unittest
import uuid

CODE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(CODE))
from adaptive_gateway import AdaptiveGateway,POLICIES


class AdaptiveAtomicityTests(unittest.TestCase):
    def setUp(self):
        self.root=CODE.parent/"results"/"adaptive_atomicity_tests"/uuid.uuid4().hex
        self.root.mkdir(parents=True)
    def prepare(self,policy,name):
        path=self.root/(name+".sqlite")
        with AdaptiveGateway(path,policy,clock=lambda:10.0) as g:
            g.create_account("payer",10);g.create_account("sink",0)
            g.put_subject("root",1000)
            g.create_effect("effect","payer","sink",1,["root"])
            g.stage("effect",{"value":42})
            nonce=g.issue("effect",ttl=100)
        return path,nonce
    def test_real_process_death_at_three_settlement_boundaries(self):
        child=r'''
import os,sys
sys.path.insert(0,sys.argv[1])
from adaptive_gateway import AdaptiveGateway
def fault(phase):
    if phase==sys.argv[5]:os._exit(91)
with AdaptiveGateway(sys.argv[2],sys.argv[3],clock=lambda:11.0,fault_hook=fault) as g:
    g.settle(sys.argv[4])
'''
        for policy in POLICIES:
            for phase in ("after_debit","before_commit","after_commit"):
                with self.subTest(policy=policy,phase=phase):
                    path,nonce=self.prepare(policy,policy+"_"+phase)
                    done=subprocess.run([sys.executable,"-c",child,str(CODE),str(path),policy,nonce,phase],
                                        capture_output=True,text=True,timeout=20)
                    self.assertEqual(done.returncode,91,done.stderr)
                    with AdaptiveGateway(path,policy,clock=lambda:12.0) as g:
                        before=g.db.execute("SELECT COUNT(*) FROM ledger").fetchone()[0]
                        self.assertEqual(before,int(phase=="after_commit"))
                        first=g.settle(nonce);second=g.settle(nonce)
                        self.assertEqual(first,second)
                        self.assertEqual(g.balance("payer"),9)
                        self.assertEqual(g.balance("sink"),1)
                        self.assertEqual(g.db.execute("SELECT COUNT(*) FROM ledger").fetchone()[0],1)
    def test_process_death_rolls_back_subject_log_and_queue_together(self):
        child=r'''
import os,sys
sys.path.insert(0,sys.argv[1])
from adaptive_gateway import AdaptiveGateway
class Faulting(AdaptiveGateway):
    def _audit(self,kind,*args,**kwargs):
        super()._audit(kind,*args,**kwargs)
        if kind=="invalidate":os._exit(93)
with Faulting(sys.argv[2],"adaptive_delta",clock=lambda:11.0) as g:
    g.invalidate("root")
'''
        path,nonce=self.prepare("adaptive_delta","mutation")
        done=subprocess.run([sys.executable,"-c",child,str(CODE),str(path)],
                            capture_output=True,text=True,timeout=20)
        self.assertEqual(done.returncode,93,done.stderr)
        with AdaptiveGateway(path,"adaptive_delta",clock=lambda:12.0) as g:
            self.assertEqual(g._global(),0)
            self.assertEqual(g.db.execute("SELECT valid FROM subjects WHERE subject_id='root'").fetchone()[0],1)
            self.assertEqual(g.db.execute("SELECT COUNT(*) FROM mutation_history").fetchone()[0],0)
            self.assertEqual(g.db.execute("SELECT COUNT(*) FROM cleanup_queue").fetchone()[0],0)
            g.settle(nonce)


if __name__=="__main__":unittest.main()

