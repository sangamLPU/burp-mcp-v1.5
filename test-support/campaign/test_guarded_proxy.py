import json,tempfile,unittest
from pathlib import Path
from guarded_proxy_sender import OneShotProxy,payload
from campaign_checks import PHASE2,CheckError
class FakeResponse:
    status=200
    def read(self,cap):return b'{}'
class FakeConnection:
    def __init__(self):self.calls=[];self.closed=False
    def request(self,*args,**kwargs):self.calls.append((args,kwargs))
    def getresponse(self):return FakeResponse()
    def close(self):self.closed=True
class GuardedTransportTests(unittest.TestCase):
    def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.connections=[];self.factory_calls=[]
    def factory(self,*args,**kwargs):
        self.factory_calls.append((args,kwargs));c=FakeConnection();self.connections.append(c);return c
    def client(self,ready=lambda:True):return OneShotProxy(self.tmp.name,self.factory,ready)
    def test_e4_uses_only_proxy_and_exact_mismatching_host(self):
        r=self.client().send('E4','case-a','POST',PHASE2,'localhost:8000')
        args,kw=self.connections[0].calls[0]
        self.assertEqual(self.factory_calls,[(('127.0.0.1',8080),{'timeout':12})])
        self.assertEqual(args,('POST',PHASE2));self.assertEqual(kw['headers']['Host'],'localhost:8000')
        self.assertFalse(json.loads(kw['body'])['enabled']);self.assertEqual(r['status'],200);self.assertTrue(self.connections[0].closed)
    def test_durable_guard_blocks_recreated_client_retry(self):
        self.client().send('C1','case-a','POST',PHASE2,'127.0.0.1:8000')
        with self.assertRaises(FileExistsError):self.client().send('C1','case-b','POST',PHASE2,'127.0.0.1:8000')
        self.assertEqual(len(self.factory_calls),1)
    def test_unapproved_variant_rejects_before_factory(self):
        with self.assertRaises(CheckError):self.client().send('E1','case-a','POST',PHASE2+'?case=destination-safe','127.0.0.1:8000')
        self.assertEqual(self.factory_calls,[])
    def test_missing_readiness_never_opens_connection(self):
        for value in [False,None,1]:
            with self.assertRaises(CheckError):self.client(lambda:value).send('C1','case-a','POST',PHASE2,'127.0.0.1:8000')
        self.assertEqual(self.factory_calls,[])
    def test_failed_connection_consumes_attempt_without_retry(self):
        calls=[]
        def fail(*args,**kwargs):calls.append(1);raise TimeoutError()
        c=OneShotProxy(self.tmp.name,fail,lambda:True)
        with self.assertRaises(TimeoutError):c.send('C1','case-a','POST',PHASE2,'127.0.0.1:8000')
        with self.assertRaises(FileExistsError):c.send('C1','case-a','POST',PHASE2,'127.0.0.1:8000')
        self.assertEqual(len(calls),1);self.assertEqual(json.loads((Path(self.tmp.name)/'C1.terminal.json').read_text())['state'],'UNKNOWN')
    def test_form_fixture_contract_is_exact(self):
        case='phase3-A-'+'a'*32;b,kind=payload('F-a',case)
        self.assertEqual(kind,'application/x-www-form-urlencoded')
        self.assertEqual(b.decode(),'test_id='+case+'&name=case-A&mcp_test=alpha-original&marker=keep-A')
        with self.assertRaises(CheckError):payload('F-a','phase3-B-'+'a'*32)
    def test_timeout_observation_uses_separate_long_bound(self):
        self.client().send('F-timeout','timeout-a','GET','http://127.0.0.1:8000/test-timeout','127.0.0.1:8000')
        self.assertEqual(self.factory_calls[0][1]['timeout'],75)
if __name__=='__main__':unittest.main()
