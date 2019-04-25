from datetime import timedelta

import simplekv
import simplekv.memory
from flask import Flask
from flask import request
from flask import jsonify

# TODO fix __init__.py to make imports easier
from flask_jwt_extended import JWTManager
from flask_jwt_extended import jwt_required
from flask_jwt_extended import fresh_jwt_required
from flask_jwt_extended import jwt_identity
from flask_jwt_extended import jwt_claims
from flask_jwt_extended import create_refresh_access_token
from flask_jwt_extended import create_fresh_access_token
from flask_jwt_extended import refresh_access_token
from flask_jwt_extended import revoke_token
from flask_jwt_extended import unrevoke_token
from flask_jwt_extended import get_stored_tokens

# Example users database

USERS = {
    'test1': {
        'id': 1,
        'password': 'abc123',
        'type': 'restricted',
    },
    'test2': {
        'id': 2,
        'password': 'abc123',
        'type': 'admin',
    },
}


# Flask test stuff
app = Flask(__name__)
app.debug = True
app.secret_key = 'super-secret'


# Optional configuration options
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1) # default to 15 min
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=7) # default to 30 days
app.config['ALGORITHM'] = 'HS512' # defalt HS256

# Enable JWT blacklist / token revoke
app.config['JWT_BLACKLIST_ENABLED'] = True

#
# We are going to be using a simple in memory blacklist for this example. In
# production, you will likely prefer something like redis (it can work with
# multiple threads and processes, and supports automatic removal of expired
# tokens to the blacklist doesn't blow up). Check here for available options:
# http://pythonhosted.org/simplekv/
blacklist_store = simplekv.memory.DictStore()
app.config['JWT_BLACKLIST_STORE'] = blacklist_store

# Only check the blacklist for refresh token. Available options are:
#   'all': Check both access and refresh tokens
#   'refresh' Check only for refresh token
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = 'refresh'


jwt = JWTManager(app)


# Function to add custom claims to the JWT (optional)
@jwt.user_claims_loader
def my_claims(identity):
    return {
        'type': USERS[identity]['type'],
        'ip': request.remote_addr,
    }


# Function to change the result if someone without a token tries to access a
# protected endpoint  (optional)
@jwt.unauthorized_loader
def my_unauthorized_response():
    return jsonify({
        'status': 401,
        'sub_status': 100,
        'message': 'You must submit a valid JWT to access this endpoint',
    })


# Function to change the result if someone with an expired token tries to access a
# protected endpoint (optional)
@jwt.expired_token_loader
def my_expired_response():
    return jsonify({
        'status': 401,
        'sub_status': 101,
        'message': 'Token expired',
    })


# Endpoint for authing an user
@app.route('/auth/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if username is None or password is None:
        return jsonify({"msg": "Missing username or password"}), 422

    if username not in USERS:
        return jsonify({'msg': 'Bad username or password'}), 401

    if USERS[username]['password'] != password:
        return jsonify({'msg': 'Bad username or password'}), 401

    return create_refresh_access_token(identity=username)


# Endpoint for getting a fresh access token for an user
@app.route('/auth/fresh-login', methods=['POST'])
def fresh_login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if username is None or password is None:
        return jsonify({"msg": "Missing username or password"}), 422

    if username not in USERS:
        return jsonify({'msg': 'Bad username or password'}), 401

    if USERS[username]['password'] != password:
        return jsonify({'msg': 'Bad username or password'}), 401

    return create_fresh_access_token(identity=username)


# Endpoint for generating a non-fresh access token from the refresh token
@app.route('/auth/refresh', methods=['POST'])
def refresh_token():
    return refresh_access_token()


@app.route('/protected', methods=['GET'])
@jwt_required
def non_fresh_protected():
    ip = jwt_claims('test1')['ip']
    username = jwt_identity  # Access identity through jwt_identity proxy

    msg = '{} says hello from {}'.format(username, ip)
    return jsonify({'msg': msg})


@app.route('/protected-fresh', methods=['GET'])
@fresh_jwt_required
def fresh_protected():
    ip = jwt_claims('test1')['ip']
    msg = '{} says hello from {} (fresh)'.format(jwt_identity, ip)
    return jsonify({'msg': msg})


# TODO endpoint for revoking and unrevoking a token 
@app.route('/auth/tokens/<string:jti>', methods=['PUT'])
def revoke_jwt(jti):
    # TODO you should put some extra protection on this, so a user can only
    #      modify their tokens
    revoke = request.json.get('revoke', None)
    if revoke is None:
        return jsonify({'msg': "Missing json argument: 'revoke'"}), 422
    if not isinstance(revoke, bool):
        return jsonify({'msg': "'revoke' must be a boolean"}), 422
    if revoke:
        revoke_token(jti)
    else:
        unrevoke_token(jti)


# Endpoint for listing tokens
@app.route('/auth/tokens', methods=['GET'])
def list_tokens():
    # TODO you should put some extra protection on this, so a user can only
    #      view their tokens, or some extra privillage roles so an admin can
    #      view everyones token
    return jsonify(get_stored_tokens()), 200





if __name__ == '__main__':
    app.run()
