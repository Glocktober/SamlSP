import json

from flask  import (
    Flask, 
    make_response, 
    redirect,
    session,
)
from flask_session import Session

from SamlSP import SamlSP

from client_config import session_config, saml_config

app = Flask(__name__)
app.config.from_mapping(session_config)
app.secret_key = session_config['secret_key']
Session(app)

sp = SamlSP(config=saml_config, app=app)


@app.route('/')
def index():

    user = session.get('username','World')
    return f'<h2>Hello {user}!</h2><br><a href="/login">redo</a>'


@app.route('/login')
def login():

    session.clear()
    return sp.initiate_login(relayState='/')


@app.route('/passive')
def passive_login():

    session.clear()
    return sp.initiate_login(relayState='/', is_passive=True)


@app.route('/force')
def force_login():

    session.clear()
    return sp.initiate_login(relayState='/', force_reauth=True)


@app.route('/logout')
def logout():

    session.clear()
    return redirect('/')


import json
@app.route('/sess')
def get_sess():

    ll = [x for x in session]
    jsess = json.dumps({
            'attributes': session.get('attributes'),
            'user': session.get('username'),
            'keys' : ll,
        },indent=4)
    resp = make_response( jsess, 200, 
    {'content-type': 'application/json'} )
    return resp


if __name__ == '__main__':
    app.run(port=8000)

else:
    application = app
