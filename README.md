## SamlSP - A Python SAML Service Provider for Flask

This Blueprint allows the addition of SAML2 Service Provider functionality (authentication/authorization) into a Flask application.

### Features:
* HTTP-Redirect binding for AuthenRequests, with optional Request signing
* HTTP-Post binding for AuthnResponse with signing verification
  * /acs
* Response assertions attributes are stored in the session variable
* A metadata endpoint providing XML configuration for IdP's
  * /metadata
* Loads IdP metadata from file or URL
* Single Log Out (SLO) is not supported

## Installation

```bash
# pip install SamlSP
```
or pull from github for sample client_app.py and configuration file.
```bash
# git clone https://github.com/Glocktober/SamlSP.git
```

## Configuration

Refer to the sample configuration file [client_config_sample.py]

The Service Provider Entity Id is a URN (and generally a URL) familiar to the IdP that identifies this Service Provider.  This is set with the `sp_id` configuration key.

If requests will be signed then `sp_key` and `sp_cert` configuration settings will need to be specified.  If these are not set, the SAMLRequests will not be signed. `sp_key` specifies the PEM formated private key associated with `sp_cert` - the X509 Public Certificate that is then included in the metadata for use by IdPs to verify the request authenticity. 

The XML metadata file from the IdP can be used to simplify configuring IdP details. This is set with the `idp_metadata` config key.

Alternatively an IdP with an accessible metadata URL can be directly used, with the `idp_meta_url` config key.

The `url_prefix` key is url_prefix of the Flask Blueprint and is '/' by default.  This impacts the prefix for the `/acs` (assertions consumer service) and `/metadata` URLs.

The `assertions` config key is a list of strings - the names of assertions from the IdP that will be included in the users `session['attributes']` data - if they are present in the IdPs SAMLResponse.  

These assertions can be URN's with a full namespace or simple names, depending on the IdP being used and how it's configured. Names are matched caseless, but the IdPs case is reflected in the session attributes.

If no assertions are specified than only the nameId is saved and stored as the `session['username']`

The optional `user_attr` config key is the assertion attribute that is used specify the session['username'] value. By default this is the `NameId` of the SAMLResponse, but it is not uncommon to use `email` or `uid` as the username.

## Using SamlSP for Authentication

You can initate a login by protecting a Flask route with a decorator
```python
from SamlSP import SamlSP
from my_config import sp_config
# see example client_config.py on setup details
auth = SamlSP(sp_config)

@app.route('/')
@auth.require_login
def index_view():
    return f'Hello World!'
```
Alternativly you can explictly call login:
```python
@app.route('/login')
def login():
    return auth.initiate_login(next='/index')
```
On authentication the Flask session is updated to include the keys `username`, `nameid`, and `attributes`. The `session['username']` value is set to the value of configured `user_attr` from the SAML assertions.  `session['nameid']` is set to SAML nameId assertions regardless of the NameID format of the IdP. The `session['attributes']` value is a dict containing any assertions from the SAMLResponse that matched the config file `attributes` list.

Attributes can be accessed via the `session['attributes']` key.
```python
@app.route('/hello')
@auth.require_login
def index_view():
    return f"Hello {session['attributes']['givenName']}!"
```
To log out you can use `session.clear()` - which clears the entire session. If you only want to clear the SAML data, you can use `auth.unauthenticate()` - which will clear the `attributes`, `username`, and `nameID` from the users session.

## notes
This has been tested with SimpleSamlPhp and Azure AD as well as my SamlIdp.