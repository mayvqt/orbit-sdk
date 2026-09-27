#!/usr/bin/env python3
"""Emit fixed C contexts for the language-neutral signed session/file corpora."""
import argparse
import json
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--source',required=True);p.add_argument('--output',required=True);a=p.parse_args()
root=Path(a.source)
q=lambda s:json.dumps(s or '',ensure_ascii=True)
slice_=lambda s:('{NULL,0}' if s is None else '{(const uint8_t *)'+q(s)+','+str(len(s.encode()))+'}')
rows=[]
for purpose,file in [(1,'session-grants.json'),(2,'offline-files.json')]:
    obj=json.loads((root/file).read_text())
    for case in obj['cases']:
        e={**obj['expected'],**case.get('expected',{})}
        if purpose==2:
            e.update(issuer='https://orbit.example.test',application='app',environment='test',activation='offline',installation=e['installation_id'],sequence=e['minimum_sequence'])
        fields=['issuer','application','environment','licence','activation','installation','fingerprint','fingerprint_provider']
        ctx='{'+','.join(slice_(e.get(x)) for x in fields)+','
        ctx+=','.join(str(int(e.get(x) or 0)) for x in ['now','now','credential_expires_at','licence_expires_at'])+','
        ctx+=','.join(str(int(e.get(x) is not None)) for x in ['licence','fingerprint','fingerprint_provider','credential_expires_at','licence_expires_at'])+'}'
        extra='{'+ctx+','+slice_(e.get('session_id'))+','+str(e.get('sequence',0))+','+str(purpose)+','+str(2 if e.get('key_environment')=='live' else 1)+','+str(int(e.get('allow_unbound_fingerprint',False)))+'}'
        invalid_type=any(type(e[x]) is not int for x in ['now','sequence'] if x in e)
        rows.append('{'+','.join([q(case['name']),q(case['token']),q(json.dumps(case.get('jwks',obj['jwks']),separators=(',',':'))),extra,str(int(case['valid'])),str(int(invalid_type))])+'}')
Path(a.output).write_text('/* Generated from shared signed corpora. */\ntypedef struct signed_case { const char *name,*token,*jwks; orbit_signed_expected_t expected; int valid,invalid_type; } signed_case_t;\nstatic const signed_case_t signed_cases[]={\n'+',\n'.join(rows)+'\n};\n')
