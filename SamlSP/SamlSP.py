
from urllib.parse import urlencode, parse_qs

from flask import (
    Blueprint,
    Response,
    abort, 
    current_app, 
    redirect, 
    request,
    session,
    url_for,
)

from .RequestEncoder import RequestEncoder
from .ResponseDecoder import ResponseDecoder
from .Metadata import loadIdPMetadata
from .SPMetaEncoder import encodeSpMetaData
from .SamlSerializer import SamlResponseSigner, SamlRequestSerializer


class   SamlSP(Blueprint):
    """ SAML Service Provider Flask Blueprint """

    def __init__(self, config, app=None, **kwargs):

        config = loadIdPMetadata(config)

        self.sp_id = config.get('sp_id')
        self.idp_id = config.get('idp_id')
        self.idp_url = config.get('idp_url')
        self.idp_cert = config.get('idp_cert')

        assert self.sp_id, 'Config error: SP entity id is required'
        assert self.idp_id, 'Config error: IdP entity id is required'
        assert self.idp_url, 'Config error: IdP signin URL is required'
        assert self.idp_cert, 'Config error: IdP certificate is required'

        self.sp_cert = config.get('sp_cert')
        self.sp_key = config.get('sp_key')
        self.sp_key_passwd = config.get('sp_key_passwd')

        # use this to verify SAMLResponse <Signature> from http-POST
        self.verifier = SamlResponseSigner(cert=self.idp_cert)
    
        # use this to serialize and (maybe) sign SAMLRequest for http-REDIRECT
        self.requestSerializer = SamlRequestSerializer(
                key=self.sp_key, 
                password=self.sp_key_passwd
        ) 
        url_prefix = config.get('url_prefix')
        self.force_auth = config.get('force_reauth',False)

        temp_attrs = config.get('assertions', ['uid'])
        # we'll match everything in lower case
        self.saml_attrs = [attr.lower() for attr in temp_attrs ]
        self.user_attr = config.get('user_attr', None)

        # login hooks - build_attrs_list() must be first
        self.login_hooks = [self.__build_attrs_list]

        # after auth hooks - runs after successful authentication
        self.after_auth_hooks = {}

        bp_name = config.get('bpname','samlsp')

        Blueprint.__init__(self, name=bp_name, import_name=__name__)

        self.add_url_rule(
            rule='/acs',
            endpoint='acs',
            view_func=self.assertion_consumer_service,
            methods=['POST']
        )

        self.add_url_rule(
            rule='/metadata',
            endpoint='saml2meta',
            view_func=self.saml2meta,
            methods=['GET']
        )

        if app:
            # self register as blueprint
            app.register_blueprint(self, url_prefix=url_prefix)


    def saml2meta(self):
        """ SAML SP Metadata """

        metaxml = encodeSpMetaData(
                spbp=self,
                acsURL = url_for('.acs', _external=True)
            )
        return Response(response=metaxml, headers={
            'Content-Type':'application/xml',
        })


    def validateSignedResponse(self, saml_response, noexcept=True):
        """ Validate Response Signing """

        return self.verifier.verifySamlResponse(saml_response, noexcept)


    def initiate_login(self,*, force_reauth=False, is_passive=False, relayState=None, reqid=None, **kwargs):
        """ Generate a SAMLRequest redirect """
        
        if relayState is None:
            # if relayState is not explicit, build if from **kwargs
            relayState = urlencode(kwargs, doseq=True) if kwargs else ''

        # encode an AuthnRequest
        srequest = RequestEncoder(
                sp_id=self.sp_id,
                idp_url = self.idp_url,
                acsURL=url_for('samlsp.acs',_external=True),
                reqid=reqid,
            )
    
        # isPassive and forceAuthn can be specified at the same time
        # as long as isPassive is verified before forceAuthen is 
        srequest.forceAuthn = force_reauth
        srequest.isPassive = is_passive

        # reder the request as XML
        xml_request = srequest.toxml()

        # create http-REDIRECT query string (possibly signed)
        qs = self.requestSerializer.serializeSamlRequest(xml_request, relayState)
        
        return Response(status=302, headers={
            'Location': self.idp_url + '?' + qs,
            'Cache-Control': 'no-store, no-cache',
            'Pragma': 'no-cache',
            'Expires': -1
        })


    def assertion_consumer_service(self):
        """ Process Http-POST SAMLResponse """

        rawResponse = request.form.get('SAMLResponse')
        relayState = request.form.get('RelayState')

        if rawResponse is None or relayState is None:
            current_app.logger.info('Recieved an incomplete SAMLResponse')
            abort(400, 'Bad or incomplete SAMLResponse')

        try:
            saml_response = ResponseDecoder(
                    response_data= rawResponse, 
                    sp=self,
                )

        except Exception as e:
            current_app.logger.error(f'Failed to parse SAMLResponse: {str(e)}', exc_info=True)
            abort(400, 'Unable to parse SAMLResponse')

        if not saml_response.status_ok:
            # This is an error response
            short_status = saml_response.statusCode.split(':')[-1] or 'Unknown Error'
            status_message = saml_response.statusMessage or 'A problem occured'

            abort(401, f'{status_message} [{short_status}]')
        
        try:
            # nothing in the response can be trusted until this is done:
            saml_response.validate_saml_signing(noexcept=False)
            
        except Exception as e:
            current_app.logger.error(f'Verifying response {str(e)}', exc_info=True)
            abort(400, 'Invalid signature on SAMLResponse')
        
        try:
            current_app.logger.info(f'Verified response {saml_response.responseId} for request {saml_response.inResponseTo}')
            
            if saml_response.audience != self.sp_id:
                raise Exception(f'Bad Audience: expected {self.sp_id} received {saml_response.audience}')
    
            if saml_response.issuer != self.idp_id:
                raise Exception(f'Bad Issuer: expected {self.idp_id} received {saml_response.issuer}')            

            username = saml_response.nameID
            attrs = saml_response.attributeStatement.copy()

            # Run all the login hooks.
            for login_hook in self.login_hooks:
                # each hook can massage the results
                username, attrs = login_hook(username, attrs)

        except Exception as e:
            current_app.logger.info(f'Bad data on verified response: {str(e)}', exc_info=True)
            abort(401, 'Error on verified SAMLResponse')

        # set the final session values
        session['attributes'] = attrs
        session['username'] = username
        session['nameID'] = saml_response.nameID

        current_app.logger.info(f'SAMLResponse: {saml_response.responseId} for "{username}" authenticated')

        # Quo vidas?
        url = relayState

        stateDict = parse_qs(relayState)
        if stateDict:

            if 'after' in stateDict:
                key = stateDict['after'][0]
                if key in self.after_auth_hooks:
                    return self.after_auth_hooks[key](relayState=stateDict)

            elif 'next' in stateDict:
                url = stateDict['next'][0]

        url = url if url else '/'

        return redirect(url)


    def unauthenticate(self):
        """ Remove user login data (unauthenticate) """

        if 'attributes' in session:
            del session['attributes']
        
        if 'username' in session:
            del session['username']

        if 'nameID' in session:
            del session['nameID']


    @property
    def is_authenticated(self):
        """ True if user is authenticated """
        return session.get('username') is not None


    @property
    def my_attrs(self):
        """ Return collected assertions for the current session. """

        return session['attributes'] if self.is_authenticated else {}


    def add_login_hook(self, f):
        """ Add login hook Decorator """
        
        self.login_hooks.append(f)           
        return f


    def require_login(self, f):
        """ Decorator: Require (force) Login if unauthenticated """

        def wrapper(*args, **kwargs):
            if self.is_authenticated:
                return f(*args, **kwargs)
            else:
                return self.initiate_login(request.url)
    
        wrapper.__name__ = f.__name__
        return wrapper


    def __build_attrs_list(self, username, respAttrs):
        """ First login hook builds session attrs """
        
        attrs = {}
        for attr in respAttrs:
            
            # copy response attributes we are looking for
            if attr.lower() in self.saml_attrs:                
                attrs[attr] = respAttrs[attr]
            
        # prefered username or leave it the name_id
        if self.user_attr in respAttrs:
            username = respAttrs[self.user_attr]
        
        if not 'username' in attrs:
            attrs['username'] = username
        
        return username, attrs
