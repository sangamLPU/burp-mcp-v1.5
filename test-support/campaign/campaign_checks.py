"""Pure preparation contracts. No network, MCP, native activation or live runner."""
import json
from urllib.parse import urlsplit

PREFIX='MCPB-20261107-155141'
ALLOWED={PREFIX+'-ALLOW-A',PREFIX+'-ALLOW-B'}
FORBIDDEN=[PREFIX+s for s in ['-EXCLUDED-ROOT','-EXCLUDED-ATTACH','-CRED-URL','-CRED-NAME',
    '-CRED-DETAIL','-CRED-REMEDIATION','-CRED-BACKGROUND','-CRED-REMEDIATION-BG','-CRED-REASON','-CRED-META']]
class CheckError(Exception):
    def __init__(self,code,state='FAIL',critical=False):
        super().__init__(code);self.code=code;self.state=state;self.critical=critical

def no_leak(value):
    # Evaluate entire decoded output, including error text/extra secondary fields.
    text=json.dumps(value,ensure_ascii=False)
    if any(marker in text for marker in FORBIDDEN):raise CheckError('CONTROLLED_DISCLOSURE',critical=True)

def decode_list(tool,result):
    no_leak(result)
    if not isinstance(result,dict) or result.get('isError',False) is not False or 'structuredContent' in result:
        raise CheckError('INVALID_OR_ERROR_ENVELOPE')
    blocks=result.get('content')
    if not isinstance(blocks,list) or not blocks or any(not isinstance(x,dict) or x.get('type')!='text' or not isinstance(x.get('text'),str) for x in blocks):
        raise CheckError('INVALID_CONTENT')
    if len(blocks)!=1:raise CheckError('AMBIGUOUS_BLOCKS')
    text=blocks[0]['text'].strip()
    try:
        if tool=='burp_get_scanner_issues':
            data=json.loads(text)
            if not isinstance(data,list):raise ValueError()
        elif tool=='get_scanner_issues':
            if text=='Reached end of items':return []
            decoder=json.JSONDecoder();data=[]
            while text:
                item,end=decoder.raw_decode(text)
                if not isinstance(item,dict):raise ValueError()
                data.append(item);text=text[end:].lstrip()
        else:raise ValueError()
    except (ValueError,TypeError):raise CheckError('INVALID_LIST_ENCODING') from None
    no_leak(data)
    if any(not isinstance(x,dict) for x in data):raise CheckError('INVALID_ISSUE')
    for item in data:
        if not isinstance(item.get('definition'),dict) or not isinstance(item['definition'].get('id'),str) or not item['definition']['id']:
            raise CheckError('DEFINITION_MISSING')
        raw=item.get('baseUrl','').split('\n')[-1]
        try:
            u=urlsplit(raw);service=item['httpService']
            valid=u.scheme=='http' and u.hostname=='127.0.0.1' and u.port==8000 and u.path.startswith('/test-post')
            valid=valid and service['host']=='127.0.0.1' and type(service['port']) is int and service['port']==8000 and service['secure'] is False
        except (ValueError,TypeError,KeyError,AttributeError):valid=False
        if not valid:raise CheckError('UNAUTHORIZED_ROOT_OR_SERVICE',critical=True)
    return data

def owned_markers(items):
    found=[]
    for item in items:
        markers=[marker for marker in ALLOWED if marker in item.get('name','')]
        if len(markers)!=1:raise CheckError('UNCONTROLLED_PROVENANCE',state='BLOCKED')
        found.extend(markers)
    return found

def verify_nonempty(tool,result):
    data=decode_list(tool,result)
    if not data:raise CheckError('EMPTY_IS_NOT_SECURITY_PASS',state='BLOCKED')
    markers=owned_markers(data)
    if len(data)!=2 or set(markers)!=ALLOWED:raise CheckError('MISSING_OR_DUPLICATE_POSITIVE')
    for item in data:
        pairs=item.get('requestResponses')
        if not isinstance(pairs,list) or not pairs:raise CheckError('AUTHORIZED_ATTACHMENT_MISSING')
        if not any(PREFIX+'-ALLOW-' in json.dumps(pair) for pair in pairs):raise CheckError('AUTHORIZED_ATTACHMENT_MISSING')
        if item.get('collaboratorInteractions')!=[]:raise CheckError('UNPLANNED_INTERACTIONS',state='BLOCKED')
    return True

def verify_pages(tool,full,page0,page1,end):
    verify_nonempty(tool,full)
    pages=[decode_list(tool,x) for x in [page0,page1,end]]
    if list(map(len,pages))!=[1,1,0]:raise CheckError('WRONG_PAGE_LENGTHS')
    if set(owned_markers(pages[0]+pages[1]))!=ALLOWED:raise CheckError('PAGINATION_BYPASS_OR_DUPLICATE')
    return True

def verify_summary(result):
    no_leak(result)
    if not isinstance(result,dict) or result.get('isError',False) is not False or 'structuredContent' in result:raise CheckError('INVALID_SUMMARY')
    blocks=result.get('content')
    if not isinstance(blocks,list) or len(blocks)!=1 or not isinstance(blocks[0],dict) or blocks[0].get('type')!='text':raise CheckError('INVALID_SUMMARY')
    try:d=json.loads(result['content'][0]['text'])
    except (ValueError,TypeError,KeyError,IndexError):raise CheckError('INVALID_SUMMARY') from None
    no_leak(d)
    if d.get('scannerSupported') is not True or type(d.get('scannerIssueCount')) is not int:raise CheckError('INVALID_SUMMARY_COUNT')
    if d['scannerIssueCount']!=2:raise CheckError('SUMMARY_COUNT_NOT_AUTHORIZED_ONLY',critical=d['scannerIssueCount']>2)
    return True

PHASE2='http://127.0.0.1:8000/test-post-phase2'
POST='http://127.0.0.1:8000/test-post'
# Only a contract table; it never opens a socket or authorizes a listed operation.
WINDOWS={
 'C1':('POST',PHASE2,'127.0.0.1:8000',1,300,120), 'C2':('POST',PHASE2,'127.0.0.1:8000',1,300,120),
 'D1':('POST',PHASE2,'127.0.0.1:8000',1,300,60), 'D2':('POST',PHASE2,'127.0.0.1:8000',1,300,60),
 'E1':('POST',PHASE2,'127.0.0.1:8000',1,300,120),
 'E2':('POST',PHASE2+'?case=destination-safe','127.0.0.1:8000',1,300,120),
 'E3':('POST',POST,'127.0.0.1:8000',1,300,120),
 'E4':('POST',PHASE2,'localhost:8000',1,300,120),
 'F-cancel':('GET','http://127.0.0.1:8000/test-cancel','127.0.0.1:8000',1,0,300),
 'F-a':('POST','http://127.0.0.1:8000/test-concurrent-a','127.0.0.1:8000',1,0,300),
 'F-b':('POST','http://127.0.0.1:8000/test-concurrent-b','127.0.0.1:8000',1,0,300),
 'F-timeout':('GET','http://127.0.0.1:8000/test-timeout','127.0.0.1:8000',1,0,300),
 'F-expiry':('GET','http://127.0.0.1:8000/test-session-expiry','127.0.0.1:8000',1,0,60),
 'G1':('POST',PHASE2,'127.0.0.1:8000',1,300,120),
 'G2':('GET','http://127.0.0.1:8000/test-cancel','127.0.0.1:8000',1,0,60),
 'H2a':('POST',POST,'127.0.0.1:8000',1,0,0)}

def validate_attempt(window,method,url,host,attempt_number):
    if window not in WINDOWS:raise CheckError('UNKNOWN_WINDOW')
    expected_method,expected_url,expected_host,cap,_,_=WINDOWS[window]
    if type(attempt_number) is not int or attempt_number<1 or attempt_number>cap:raise CheckError('ATTEMPT_CAP')
    if (method,url,host)!=(expected_method,expected_url,expected_host):raise CheckError('UNAPPROVED_VARIANT')
    return True

def verify_delivery(attempts,origin_cases,expected_case_ids,expected_delivered):
    if type(expected_delivered) is not int or expected_delivered<0:raise CheckError('INVALID_DELIVERY_COUNT')
    if len(attempts)!=len(expected_case_ids) or len(set(attempts))!=len(attempts) or set(attempts)!=set(expected_case_ids):raise CheckError('ATTEMPT_IDENTITY_MISMATCH')
    if len(origin_cases)!=expected_delivered or len(set(origin_cases))!=len(origin_cases) or set(origin_cases)-set(expected_case_ids):raise CheckError('ORIGIN_COUNT_OR_ASSOCIATION')
    return True

def terminal_outcome(client,origins,queue_terminal):
    if client=='TIMEOUT' and not (origins==0 and queue_terminal in ('DROPPED','SESSION_EXPIRED','MESSAGE_EXPIRED')):return 'UNKNOWN'
    if client=='TIMEOUT':return 'VERIFIED_NOT_DELIVERED'
    return 'REQUIRES_BATCH_ASSERTIONS'
