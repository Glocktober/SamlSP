from base64 import b64decode

import xmltodict

from .constants import *

class   ResponseDecoder:
    """ Decode SAMLResponse data for convenient access """

    def __init__(self, response_data, sp, israw=True):

        if israw:
            # Must be b64decoded
            if type(response_data) is str:
                response_data.encode('utf-8')
            response_data = b64decode(response_data)
            
        self.response_data = response_data
        
        self.root = xmltodict.parse(
            response_data,
            process_namespaces=True,
            namespaces=SamlNS,
            )

        self.sp = sp

        self.resp = self.root['samlp:Response']
        self.status = self.resp['samlp:Status']

        if self.version  != '2.0':
            mess = f'SAML version error: {self.version} != v2.0'
            raise Exception(f'Incorrect response: version "{self.version}" - expected "2.0"')

        if self.status_ok:
            # Only valid for a Success Response
            self._assertion = self.resp['saml:Assertion']
            self._subject = self._assertion['saml:Subject']
            self._subjectConfData = self._subject['saml:SubjectConfirmation']['saml:SubjectConfirmationData']
            self._conditions = self._assertion['saml:Conditions']
            self._attributeStatement = self._assertion.get('saml:AttributeStatement')


    def assertion_error(self):

        short_status = self.statusCode.split(':')[-1]
        raise Exception(f'Method invalid for Error Response: {short_status} - {self.statusMessage}')

    @property 
    def version(self):
        return self.resp['@Version']

    @property
    def responseId(self):
        return self.resp['@ID']

    @property
    def status_ok(self):
        return self.statusCode == SamlStatusSuccess

    @property
    def signed_ok(self):
        return self.validate_saml_signing(noexcept=True)

    @property
    def statusCode(self):
        return self.status['samlp:StatusCode']['@Value']

    @property
    def statusMessage(self):
        element = self.status.get('samlp:StatusMessage')
        return element if type(element) is str or element is None else element['#text']

    #
    # The following are only availiale for successful responses
    #

    @property
    def inResponseTo(self):
        return self._subjectConfData['@InResponseTo']

    @property
    def recipient(self):
        return self._subjectConfData['@Recipient']

    @property
    def audience(self):
        return self._conditions['saml:AudienceRestriction']['saml:Audience'] 
        
    @property
    def issuer(self):
        return self._assertion['saml:Issuer']
        
    @property
    def instanceIssued(self):
        return self._assertion['@IssueInstant']
    
    @property
    def notBefore(self):
        return self._conditions['@NotBefore']

    @property
    def notOnOrAfter(self):
        return self._conditions['@NotOnOrAfter']
        
    @property
    def nameID(self):
        return self._subject['saml:NameID']['#text']
        
    @property
    def nameID_format(self):
        return self._subject['saml:NameID']['@Format']

    @property
    def attributeStatement(self):
        # Attributes are optional (i.e. nameid alone could be used for auth)
        data = {}
        if self._attributeStatement is None:
            return data

        attr_elements = self._attributeStatement.get('saml:Attribute',[])
        
        if type(attr_elements) is not list:
            attr_elements = [attr_elements]
        
        for element in attr_elements: 
            attr = element['@Name']
            vals = element['saml:AttributeValue']
            
            if isinstance(vals,dict) and '#text' in vals:
                vals = vals['#text']

            data[attr] = vals
            
        return data 


    def validate_saml_signing(self, noexcept=False):
        
        return self.sp.validateSignedResponse(self.response_data, noexcept)
        