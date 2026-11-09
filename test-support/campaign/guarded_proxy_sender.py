"""Test-only one-shot adapter. No default network factory, CLI, retry or activation.

Preparation tests supply in-memory fakes. A future authorized supervisor must
provide a real Proxy connection factory and actual current native readiness.
"""
import hashlib,json,re
from pathlib import Path
from urllib.parse import urlencode
from campaign_checks import WINDOWS,CheckError,validate_attempt

def payload(window,case):
    if not isinstance(case,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',case):raise CheckError('INVALID_CASE')
    if window in ('F-cancel','G2') and not re.fullmatch(r'phase4a-[0-9a-f]{32}',case):raise CheckError('INVALID_CANCEL_CASE')
    if window in ('F-a','F-b'):
        letter='A' if window=='F-a' else 'B'
        if not re.fullmatch('phase3-'+letter+r'-[0-9a-f]{32}',case):raise CheckError('INVALID_FORM_CASE')
        data={'test_id':case,'name':'case-'+letter,'mcp_test':('alpha' if letter=='A' else 'beta')+'-original','marker':'keep-'+letter}
        return urlencode(data).encode(),'application/x-www-form-urlencoded'
    method=WINDOWS[window][0]
    if method=='GET':return b'',None
    data={'enabled':False,'name':'original','mcp_test':'after','marker':'preserve','case':case,'nested':{'keep':17}}
    return json.dumps(data,separators=(',',':')).encode(),'application/json'

class OneShotProxy:
    def __init__(self,journal_directory,connection_factory,readiness):
        self.directory=Path(journal_directory);self.factory=connection_factory;self.readiness=readiness
    def send(self,window,case,method,url,host):
        validate_attempt(window,method,url,host,1)
        body,content_type=payload(window,case)
        if self.readiness() is not True:raise CheckError('READINESS_NOT_CONFIRMED')
        self.directory.mkdir(parents=True,exist_ok=True)
        # Fixed reviewed window names form filenames; x refuses repeat even after failure.
        with (self.directory/(window+'.started.json')).open('x',encoding='utf-8') as f:
            json.dump({'window':window,'case':case,'method':method,'url':url,'host':host,
                'requestBytes':len(body),'requestSha256':hashlib.sha256(body).hexdigest()},f)
            f.flush()
            import os
            os.fsync(f.fileno())
        connection=None
        try:
            timeout=75 if window.startswith('F-') or window=='G2' else 12
            connection=self.factory('127.0.0.1',8080,timeout=timeout)
            headers={'Host':host,'Accept':'application/json','Connection':'close','X-MCP-Test-ID':case}
            if content_type:headers['Content-Type']=content_type
            connection.request(method,url,body=body,headers=headers)
            response=connection.getresponse();data=response.read(65537)
            if len(data)>65536:raise CheckError('RESPONSE_TOO_LARGE')
            result={'case':case,'status':response.status,'requestSha256':hashlib.sha256(body).hexdigest(),
                'responseBytes':len(data),'responseSha256':hashlib.sha256(data).hexdigest()}
            with (self.directory/(window+'.terminal.json')).open('x',encoding='utf-8') as f:json.dump(result,f)
            return {**result,'bodyBytes':data}
        except Exception as e:
            with (self.directory/(window+'.terminal.json')).open('x',encoding='utf-8') as f:
                json.dump({'case':case,'state':'UNKNOWN','errorType':type(e).__name__,'retry':False},f)
            raise
        finally:
            if connection is not None:connection.close()
