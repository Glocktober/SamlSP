"""
Example configuration file for SamlSP

"""
from logging.config import dictConfig

#
# A logging config setup (optional)
#
logging_config = {
        'version' : 1,
    'formatters': {'default': {
        'format': '%(levelname)s in %(module)s: %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://flask.logging.wsgi_errors_stream',
        'formatter': 'default'
    }},
    'root': {
        'level': 'INFO',
        'handlers': ['wsgi']
    }
}

dictConfig(logging_config) 
#
# Flask-session session configuration
#
session_config = {
    'secret_key': b'my secret key',
    'debug': True,
    'SESSION_FILE_DIR': '/var/tmp/samlsp/cache/',
    'SESSION_TYPE': 'filesystem',
    'PERMANENT_SESSION_LIFETIME' : 300,
    'SESSION_COOKIE_NAME' :'spdemo',
    'SESSION_COOKIE_HTTPONLY': True,
    'SESSION_COOKIE_SECURE': True,
}

#
# Next we configure the SAML parameters
#
# This example uses the IdP's metadata XML file
#
saml_config = {
    'sp_id': 'https://sp.example.com',
    'idp_metadata': 'metadata/idp.xml', 
    'url_prefix': '',
    'assertions': ['uid', 'givename', 'surname', 'groups'],
    'user_attr': 'uid',
}

#
# Alternatively we can configure the SAML parameters
# using a URL to the IdP's metadata
# (note: any Metadata signing is not verified)
#
saml_config = {
    'sp_id': 'https://sp.example.com',
    'idp_meta_url': 'https://idp.example.com/saml2/metadata',
    'url_prefix': '',
    'assertions': ['uid', 'givename', 'surname', 'groups'],
    'user_attr': 'uid',
}

#
# The long way...
#
# This alternate example uses a local copy of the IdP's PEM certificate
# and explicitly lists the information required to use the IdP
#
with open('certs/idp.example.com.cer','rb') as f:
    idp_cert = f.read()

saml_config = {
    'sp_id': 'https://sp.example.com',          # Entity Id of the SP
    'idp_id': 'https://idp.example.com',        # Entity ID of the IdP
    'idp_url': 'https://idp.example.com/saml2', # IdP's Http-Redirect SSO URL
    'idp_cert': idp_cert,                       # IdP's putlic certificate
    'url_prefix': '',                           # Url Prefix for SamlSP's endpoints (/ is default)
    'assertions': [
        'uid',                      # These parameters, if present in the
        'givename',                 # SAMLResponse from the IdP, are included
        'surname',                  # in the users session['attributes'] key
        'groups'
        ],
    'user_attr': 'uid',             # the attribute used to define session['username']
                                    # default is the value of the nameid
}

