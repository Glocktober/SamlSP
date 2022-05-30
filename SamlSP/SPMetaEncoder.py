from copy import deepcopy

import xmltodict

from .SamlSerializer import serialize_cert


def encodeSpMetaData(spbp, acsURL):
    """ Create XML Service Provider Metadata """

    spmeta = deepcopy(_template_SpMetaData)
    print('in sp encoder')

    spmeta['EntityDescriptor']['@entityID'] = spbp.sp_id
    spssodescr = spmeta['EntityDescriptor']['SPSSODescriptor']
    
    if spbp.sp_cert:
        spssodescr['@AuthnRequestsSigned'] = 'true'
        spssodescr['KeyDescriptor']['ds:KeyInfo']['ds:X509Data']['ds:X509Certificate'] = serialize_cert(spbp.sp_cert)
 
    else:
        spssodescr['@AuthnRequestsSigned'] = 'false'
        del spssodescr['KeyDescriptor']
    
    acslist = spssodescr['AssertionConsumerService']

    acslist.append(                {
        '@index': '0',
        '@isDefault': 'true',
        '@Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        '@Location': acsURL
    })

    return xmltodict.unparse(spmeta)


_template_SpMetaData = {
    'EntityDescriptor': {
        '@entityID': '_SP Entity ID**',
        '@xmlns': 'urn:oasis:names:tc:SAML:2.0:metadata',
        'SPSSODescriptor': {
            '@AuthnRequestsSigned': 'true',
            '@WantAssertionsSigned': 'true',
            '@protocolSupportEnumeration': 'urn:oasis:names:tc:SAML:2.0:protocol',
            'KeyDescriptor': {
                    '@use': 'signing',
                    'ds:KeyInfo': {
                        '@xmlns:ds': 'http://www.w3.org/2000/09/xmldsig#',
                        'ds:X509Data': {
                            'ds:X509Certificate': '_Cert Here**'
                            }
                    }
                },
            'NameIDFormat': 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
            'AssertionConsumerService': []
        }
    }
}