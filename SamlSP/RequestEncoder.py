
from copy import deepcopy
from datetime import datetime, timedelta
from secrets import token_hex

import xmltodict

# Generate a random id
newid = lambda: '_' + token_hex(16)   # Azure and SimpleSaml require a leading character

# Time stamps in UTC time, ISO format
TIMEFORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
issue_instant_now = lambda: datetime.utcnow().strftime(TIMEFORMAT)
expire_time = lambda minutes: (datetime.utcnow() + timedelta(minutes=minutes)).strftime(TIMEFORMAT)


class RequestEncoder:
    """ Encode a SAML Request """

    def __init__(self, sp_id, idp_url, acsURL, reqid=None):

        self.root = deepcopy(_saml_request_template)

        self.req = req = self.root['samlp:AuthnRequest']
        req['@ID'] = reqid or newid()
        req['@IssueInstant'] = issue_instant_now()
        req['@Destination'] = idp_url
        req['@AssertionConsumerServiceURL'] = acsURL
        req['saml:Issuer'] = sp_id


    def toxml(self):

        xml = xmltodict.unparse(self.root, full_document=False)
        return xml.encode('utf-8')      
    

    @property
    def forceAuthn(self):
        return self.req('@ForceAuthn','false') 


    @forceAuthn.setter
    def forceAuthn(self, v):
        self.req['@ForceAuthn'] = 'true' if v else 'false'


    @property
    def isPassive(self):
        return self.req.get('@IsPassive','false')


    @isPassive.setter
    def isPassive(self, v):
        self.req['@IsPassive'] = 'true' if v else 'false'


_saml_request_template = {
    'samlp:AuthnRequest': {
        '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        '@ID': '_ID',
        '@Version': '2.0',
        '@IssueInstant': 't_instant',
        '@Destination': '_Identity Provider Entity ID',
        '@AssertionConsumerServiceURL': '_Assertion Consumer Service',
        '@ProtocolBinding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        'saml:Issuer': '_Service Provider Entity ID',
        'samlp:NameIDPolicy': {
            '@Format': 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
            '@AllowCreate': 'true'
        }
    }
}
