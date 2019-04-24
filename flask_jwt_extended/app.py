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
from flask_jwt_extended import refresh
from flask_jwt_extended import fresh_authenticate
from flask_jwt_extended import jwt_user_claims
from flask_jwt_extended import authenticate

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
#
# We are going to be using a simple in memory blacklist for this example. In
# production, you will likely prefer something like redis (it can work with
# multiple threads and processes, and supports automatic removal of expired
# tokens to the blacklist doesn't blow up). Check here for available options:
# http://pythonhosted.org/simplekv/
blacklist_store = simplekv.memory.DictStore()
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_STORE'] = blacklist_store
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = 'refresh'  # Only check blacklist for refresh tokens


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
@app.route('/auth', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if username is None or password is None:
        return jsonify({"msg": "Missing username or password"}), 422

    if username not in USERS:
        return jsonify({'msg': 'Bad username or password'}), 401

    if USERS[username]['password'] != password:
        return jsonify({'msg': 'Bad username or password'}), 401

    return authenticate(identity=username)


# Endpoint for getting a fresh access token for an user
@app.route('/fresh-auth', methods=['POST'])
def fresh_login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if username is None or password is None:
        return jsonify({"msg": "Missing username or password"}), 422

    if username not in USERS:
        return jsonify({'msg': 'Bad username or password'}), 401

    if USERS[username]['password'] != password:
        return jsonify({'msg': 'Bad username or password'}), 401

    return fresh_authenticate(identity=username)


# Endpoint for generating a non-fresh access token from the refresh token
@app.route('/refresh', methods=['POST'])
def refresh_token():
    return refresh()


@app.route('/protected', methods=['GET'])
@jwt_required
def non_fresh_protected():
    ip = jwt_user_claims('test1')['ip']
    msg = '{} says hello from {}'.format(jwt_identity, ip)
    return jsonify({'msg': msg})


@app.route('/protected-fresh', methods=['GET'])
@fresh_jwt_required
def fresh_protected():
    ip = jwt_user_claims('test1')['ip']
    msg = '{} says hello from {} (fresh)'.format(jwt_identity, ip)
    return jsonify({'msg': msg})


if __name__ == '__main__':
    app.run()
