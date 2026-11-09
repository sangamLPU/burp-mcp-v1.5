import copy,json,unittest
import campaign_checks as c
def result(data,legacy=False):
    text=('\n\n'.join(json.dumps(x) for x in data) if data else 'Reached end of items') if legacy else json.dumps(data)
    return {'content':[{'type':'text','text':text}],'isError':False}
def issue(marker):return {'name':marker+' password=[REDACTED]','baseUrl':c.POST,
 'httpService':{'host':'127.0.0.1','port':8000,'secure':False},'requestResponses':[{'request':'GET /test-post '+c.PREFIX+'-ALLOW-ATTACH','response':'Content-Type: text/plain; password=[REDACTED]'}],
 'collaboratorInteractions':[],'definition':{'id':'[REDACTED]'}}
class BatchBSecurityOracle(unittest.TestCase):
    def setUp(self):self.items=[issue(m) for m in sorted(c.ALLOWED)]
    def test_both_real_encoding_shapes_and_pages(self):
        for tool,legacy in [('burp_get_scanner_issues',False),('get_scanner_issues',True)]:
            self.assertTrue(c.verify_pages(tool,result(self.items,legacy),result(self.items[:1],legacy),result(self.items[1:],legacy),result([],legacy)))
    def test_empty_is_blocked(self):
        for tool,legacy in [('burp_get_scanner_issues',False),('get_scanner_issues',True)]:
            with self.assertRaises(c.CheckError) as error:c.verify_nonempty(tool,result([],legacy))
            self.assertEqual(error.exception.state,'BLOCKED')
    def test_each_forbidden_secondary_field_is_detected(self):
        for marker in c.FORBIDDEN:
            for field in ['name','detail','remediation','baseUrl','definition','requestResponses','collaboratorInteractions','unknownMetadata']:
                with self.subTest(marker=marker,field=field):
                    data=copy.deepcopy(self.items);data[0][field]=marker
                    with self.assertRaises(c.CheckError) as error:c.verify_nonempty('burp_get_scanner_issues',result(data))
                    self.assertTrue(error.exception.critical)
    def test_error_payload_cannot_hide_canary(self):
        payload={'isError':True,'content':[{'type':'text','text':c.FORBIDDEN[0]}]}
        with self.assertRaises(c.CheckError) as error:c.verify_nonempty('burp_get_scanner_issues',payload)
        self.assertTrue(error.exception.critical)
    def test_encoded_json_canary_is_decoded(self):
        data=copy.deepcopy(self.items);data[0]['detail']=c.FORBIDDEN[0]
        r=result(data);r['content'][0]['text']=r['content'][0]['text'].replace('MCPB','\\u004dCPB')
        with self.assertRaises(c.CheckError):c.verify_nonempty('burp_get_scanner_issues',r)
    def test_excluded_root_without_known_marker_fails(self):
        data=copy.deepcopy(self.items);data[0]['baseUrl']='http://127.0.0.1:8000/'
        with self.assertRaises(c.CheckError) as error:c.verify_nonempty('burp_get_scanner_issues',result(data))
        self.assertTrue(error.exception.critical)
    def test_root_service_and_protocol_mismatches(self):
        for mutation in [lambda x:x.update(baseUrl='https://127.0.0.1:8000/test-post'),lambda x:x['httpService'].update(port=8001),lambda x:x['httpService'].update(secure=True),lambda x:x['httpService'].update(port=True)]:
            data=copy.deepcopy(self.items);mutation(data[0])
            with self.assertRaises(c.CheckError):c.verify_nonempty('burp_get_scanner_issues',result(data))
    def test_missing_attachment_or_positive_cannot_pass(self):
        data=copy.deepcopy(self.items);data[0]['requestResponses']=[]
        for payload in [data,self.items[:1],self.items[:1]*2]:
            with self.assertRaises(c.CheckError):c.verify_nonempty('burp_get_scanner_issues',result(payload))
    def test_unowned_provenance_blocks(self):
        data=copy.deepcopy(self.items);data[0]['name']='Unrelated finding'
        with self.assertRaises(c.CheckError) as error:c.verify_nonempty('burp_get_scanner_issues',result(data))
        self.assertEqual(error.exception.state,'BLOCKED')
    def test_malformed_or_denied_cannot_pass(self):
        for payload in [{},{'content':[]},{'content':[{'type':'text','text':'Denied'}]}, {'content':[{'type':'text','text':'[]'}],'isError':True}, {'content':[{'type':'text','text':'[]'}],'structuredContent':{}}]:
            with self.assertRaises(c.CheckError):c.verify_nonempty('burp_get_scanner_issues',payload)
    def test_duplicate_page_and_false_end_fail(self):
        for p1,end in [(self.items[:1],[]),(self.items[1:],self.items[:1])]:
            with self.assertRaises(c.CheckError):c.verify_pages('burp_get_scanner_issues',result(self.items),result(self.items[:1]),result(p1),result(end))
    def test_summary_cannot_leak_excluded_count(self):
        good={'scannerSupported':True,'scannerIssueCount':2}
        self.assertTrue(c.verify_summary(result(good)))
        for value in [3,0,True,2.0,None]:
            with self.assertRaises(c.CheckError):c.verify_summary(result({**good,'scannerIssueCount':value}))
    def test_summary_ambiguous_or_alternate_evidence_rejects(self):
        for mutation in [lambda r:r.update(structuredContent={}),lambda r:r['content'].append({'type':'text','text':'extra'}),lambda r:r['content'][0].update(type='image')]:
            r=result({'scannerSupported':True,'scannerIssueCount':2});mutation(r)
            with self.assertRaises(c.CheckError):c.verify_summary(r)
class RemainingCampaignGuards(unittest.TestCase):
    def test_only_exact_reviewed_variants_allowed(self):
        for window,(method,url,host,*_) in c.WINDOWS.items():self.assertTrue(c.validate_attempt(window,method,url,host,1))
    def test_no_second_attempt_or_noninteger_count(self):
        for value in [2,0,-1,True,1.0]:
            with self.assertRaises(c.CheckError):c.validate_attempt('C1','POST',c.PHASE2,'127.0.0.1:8000',value)
    def test_route_host_method_and_query_changes_reject(self):
        for method,url,host in [('GET',c.PHASE2,'127.0.0.1:8000'),('POST',c.PHASE2+'?extra=1','127.0.0.1:8000'),('POST',c.PHASE2,'localhost:8000'),('POST','http://127.0.0.1:8001/test-post-phase2','127.0.0.1:8001')]:
            with self.assertRaises(c.CheckError):c.validate_attempt('C1',method,url,host,1)
    def test_host_mismatch_is_allowed_only_in_e4(self):
        self.assertTrue(c.validate_attempt('E4','POST',c.PHASE2,'localhost:8000',1))
        with self.assertRaises(c.CheckError):c.validate_attempt('E1','POST',c.PHASE2,'localhost:8000',1)
    def test_delivery_count_identity_and_duplicate_fail(self):
        self.assertTrue(c.verify_delivery(['a','b'],['a','b'],['a','b'],2))
        self.assertTrue(c.verify_delivery(['a'],[],['a'],0))
        for args in [(['a'],['a','a'],['a'],1),(['a'],['b'],['a'],1),(['a','a'],['a'],['a','b'],1)]:
            with self.assertRaises(c.CheckError):c.verify_delivery(*args)
        for count in [True,1.0,-1]:
            with self.assertRaises(c.CheckError):c.verify_delivery(['a'],['a'],['a'],count)
    def test_timeout_requires_independent_termination(self):
        self.assertEqual(c.terminal_outcome('TIMEOUT',0,None),'UNKNOWN')
        self.assertEqual(c.terminal_outcome('TIMEOUT',1,'DROPPED'),'UNKNOWN')
        self.assertEqual(c.terminal_outcome('TIMEOUT',0,'MESSAGE_EXPIRED'),'VERIFIED_NOT_DELIVERED')
if __name__=='__main__':unittest.main(verbosity=2)
