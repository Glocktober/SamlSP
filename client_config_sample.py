from logging.config import dictConfig
import os
from base64 import b64decode

DIR=os.path.dirname(__file__)
abspath = lambda p : os.path.join(DIR,p)

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

with open(abspath('certs/idp.example.com.cer'),'rb') as f:
    idp_cert = f.read()

saml_config = {
    'sp_id': 'https://sp.example.com',
    'idp_id': 'https://idp.example.com',
    'idp_url': 'https://idp.example.com/saml2',
    'idp_cert': idp_cert, 
    'url_prefix': '',
    'assertions': ['uid', 'givename', 'surname', 'groups'],
    'user_attr': 'uid',
}

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
