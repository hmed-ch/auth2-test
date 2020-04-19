from authlib.integrations.flask_oauth2 import AuthorizationServer, ResourceProtector
from flask_pymongo import PyMongo
from flask import Flask, request, send_from_directory, render_template, redirect, jsonify
from flask import Response, json
from authlib.oauth2.rfc6749 import grants
from werkzeug.security import gen_salt

from models import *



class _AuthorizationServer(AuthorizationServer):
    def handle_response(self, status_code, payload, headers):
        if isinstance(payload, dict):
            if '_id' in payload :
                payload.pop('_id')
            payload = json.dumps(payload)
        return Response(payload, status=status_code, headers=headers)

class PasswordGrant(grants.ResourceOwnerPasswordCredentialsGrant):
    def authenticate_user(self, username, password):
        user = mongo.db.user.find_one({'username': username},{'_id':0})
        if user is not None and password==user['password']:

            return User.from_dict(User,user)

def query_client(client_id):
    
    client = mongo.db["client"].find_one({'client_id': client_id},{'_id':0})
    if client :
        return Client.from_dict(Client,client)



def save_token(token, request):
    if request.user:
        user_id = request.user.get_user_id()
    else:
        user_id = None
    client = request.client
    token['user_id']=user_id
    token['client_id']=request.client.client_id
    token['revoked']=False
    mongo.db.token.insert(token)
        
from authlib.oauth2.rfc6750 import BearerTokenValidator

class bearer_cls(BearerTokenValidator):
    def authenticate_token(self, token_string):
        q = mongo.db.token.find_one({'access_token':token_string})
        if q :
            return Token.from_dict(Token,q)

    def request_invalid(self, request):
        return False

    def token_revoked(self, token):

        return token.revoked




def config_oauth(app):
    authorization.init_app(app)

    # support all grants
    
    authorization.register_grant(PasswordGrant)

    # support revocation
    #revocation_cls = create_revocation_endpoint(db.session, OAuth2Token)
    #authorization.register_endpoint(revocation_cls)

    # protect resource
    #bearer_cls = _BearerTokenValidator
    require_oauth.register_token_validator(bearer_cls())

app = Flask(__name__)


app.config['MONGO_URI'] = "mongodb://localhost:27017/testauth2"

mongo = PyMongo(app)

authorization = _AuthorizationServer(
    query_client=query_client,
    save_token=save_token,
)
require_oauth = ResourceProtector()
config_oauth(app)


@app.route('/oauth/token', methods=['POST'])
def issue_token():
    
    return authorization.create_token_response()




@app.route('/Notification', methods=['GET'])
@require_oauth()
def api_me():
    print(require_oauth.acquire_token().user_id)
    
    return jsonify({'title':require_oauth.acquire_token().user_id})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3310, debug=True, threaded=True)

