#!/usr/bin/env python3
"""Direct HTTP account/activation walkthrough; does not authorize protected work."""
import argparse
import getpass
import http.client
import ipaddress
import json
import ssl
import uuid
from urllib.parse import urlencode, urlsplit


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('origin'); parser.add_argument('application'); parser.add_argument('environment')
    parser.add_argument('--local',action='store_true',help='Allow HTTP only to a literal loopback IP')
    args=parser.parse_args()
    origin=urlsplit(args.origin)
    if origin.username or origin.password or origin.path not in ('','/') or origin.query or origin.fragment or not origin.hostname:
        parser.error('Use a bare HTTPS origin')
    if origin.scheme!='https':
        try:
            local=args.local and origin.scheme=='http' and ipaddress.ip_address(origin.hostname).is_loopback
        except ValueError:
            local=False
        if not local:
            parser.error('HTTPS is required; --local accepts literal loopback HTTP only')
    scope={'application_id':args.application,'environment_id':args.environment}
    if not all(0<len(value)<=128 and value.isascii() and all(c.isalnum() or c in '_-' for c in value) for value in scope.values()):
        parser.error('Invalid public scope IDs')

    def request(path,body=None,token=None,method=None):
        if origin.scheme=='https':
            connection=http.client.HTTPSConnection(origin.hostname,origin.port,timeout=10,context=ssl.create_default_context())
        else:
            connection=http.client.HTTPConnection(origin.hostname,origin.port,timeout=10)
        headers={'Accept':'application/json'}
        if body is not None:
            headers['Content-Type']='application/json'
        if token:
            headers['Authorization']='Bearer '+token
        try:
            encoded=None if body is None else json.dumps(body).encode()
            if encoded is not None and len(encoded)>65536:
                raise RuntimeError('Request too large')
            connection.request(method or ('POST' if body is not None else 'GET'),path,encoded,headers)
            response=connection.getresponse()
            data=response.read(65537)
            if len(data)>65536 or not 200<=response.status<300:
                raise RuntimeError(f'Orbit request failed (HTTP {response.status})')
            return json.loads(data) if data else None
        finally:
            connection.close()

    username=input('Customer username: ')
    password=getpass.getpass('Customer password: ')
    signed=request('/api/client/v1/sessions',{**scope,'username':username,'password':password})
    del password
    token=signed['session']
    try:
        page=request('/api/client/v1/licences?'+urlencode(scope),token=token)
        for licence in page['items']:
            print(licence['id'],licence['policy_name'],licence['state'])
        if page['next_cursor']:
            print('More licences exist; this walkthrough shows the first page.')
        licence=input('Licence ID to activate: ')
        installation=input('Stable installation ID (16–128 characters): ')
        activated=request('/api/client/v1/activations',{**scope,'customer_session':token,'licence_id':licence,'installation_id':installation,'idempotency_key':str(uuid.uuid4())})
        request('/api/client/v1/activations/'+activated['activation_id']+'/validate',{**scope,'credential':activated['credential'],'installation_id':installation})
        print('Account activation and online validation completed. No protected operation was authorized by this walkthrough.')
    finally:
        request('/api/client/v1/sessions/current?'+urlencode(scope),token=token,method='DELETE')
        print('Customer session and its activation credentials revoked. The device slot remains registered.')


if __name__=='__main__':
    try:
        main()
    except (RuntimeError,ValueError,KeyError,OSError,http.client.HTTPException):
        raise SystemExit('The walkthrough did not complete. Check the scope, account, licence and connection.')
