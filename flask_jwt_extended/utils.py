import json
import datetime
import uuid

from functools import wraps

from flask import Flask
from flask import request
from flask import jsonify
from flask import current_app
from werkzeug.local import LocalProxy

import jwt

try:
    from flask import _app_ctx_stack as ctx_stack
except ImportError:
    from flask import _request_ctx_stack as ctx_stack

from flask_jwt_extended.config import ACCESS_EXPIRES
from flask_jwt_extended.config import REFRESH_EXPIRES
from flask_jwt_extended.config import ALGORITHM
from flask_jwt_extended.config import BLACKLIST_STORE
from flask_jwt_extended.config import BLACKLIST_ENABLED
from flask_jwt_extended.config import BLACKLIST_TOKEN_CHECKS
from flask_jwt_extended.exceptions import JWTEncodeError
from flask_jwt_extended.exceptions import JWTDecodeError
from flask_jwt_extended.exceptions import InvalidHeaderError
from flask_jwt_extended.exceptions import NoAuthHeaderError
from flask_jwt_extended.exceptions import WrongTokenError
from flask_jwt_extended.exceptions import RevokedTokenError
from flask_jwt_extended.exceptions import FreshTokenRequired


# Proxy for accessing the identity of the JWT in this context
jwt_identity = LocalProxy(lambda: _get_identity())

# Proxy for getting the dictionary of custom user claims in this JWT
jwt_user_claims = LocalProxy(lambda: _get_user_claims())


def _get_identity():
    """Returns the identity of the JWT in this context. If no JWT present, None is returned
    """
    return getattr(ctx_stack.top, 'jwt_identity', None)


def _get_user_claims():
    """Returns the dictionary of custom user claims in this JWT. If no custom user claims present, an empty dict returned
    """
    return getattr(ctx_stack.pop, 'jwt_user_claims', {})


def _encode_access_token(identity, secret, algorithm, token_expire_delta, fresh, user_claims=None):
    """Creates a new accdess token

    :param identity: Some identifier of who this client is (most common would be a client id)
    :param secret: Secret key to encode the JWT with
    :param fresh: If this should be a 'fresh' token or not
    :param algorithm: Which algorithm to use for the token
    :return: Encoded JWT
    """
    # Verify that all of our custom data we are encoding is what we expected
    user_claims = {} if user_claims is None else user_claims
    if not isinstance(user_claims, dict):
        raise JWTEncodeError('user_claims must be a dict')
    if not isinstance(fresh,  bool):
        raise JWTEncodeError('fresh must be a bool')
    try:
        json.dumps(user_claims)
    except Exception as e:
        raise JWTEncodeError('Error json serializing user_claims: {}'.format(str(e)))

    # create the jwt
    now = datetime.datetime.utcnow()
    uid = str(uuid.uuid4())
    token_data = {
        'exp': now + token_expire_delta,
        'iat': now,
        'nbf': now,
        'jti': uid,
        'identity': identity,
        'fresh': fresh,
        'type': 'access',
        'user_claims': user_claims,
    }
    encoded_token = jwt.encode(token_data, secret, algorithm).decode('utf-8')
    _store_token_if_blacklist_enabled(uid, token_expire_delta, token_type='access')
    return encoded_token


def _encode_refresh_token(identity, secret, algorithm, token_expire_delta):
    """Creates a new refresh token, which can be used to create subsequent access tokens

    :param identity: TODO - not sure I want this. flask-jwt leads to unnecessary db calls on every call
    :param secret: Secret key to encode the JWT with
    :param algorithm: Which algorithm to use for the token
    :return: Encoded JWT
    """
    now = datetime.datetime.utcnow()
    uid = str(uuid.uuid4())
    token_data = {
        'exp': now + token_expire_delta,
        'iat': now,
        'nbf': now,
        'jti': uid,
        'identity': identity,
        'type': 'refresh',
    }
    encoded_token = jwt.encode(token_data, secret, algorithm).decode('utf-8')
    _store_token_if_blacklist_enabled(uid, token_expire_delta, token_type='refresh')
    return encoded_token


def _decode_jwt(token, secret, algorithm):
    """Decodes an encoded JWT

    :param token: The encoded JWT string to decode
    :param secret: Secret Key used to encode the JWT
    :param algorithm: Algorithm used to encode the JWT
    :return: Dictionary containing contents of the JWT
    """
    # exp, iat, nbf are all verified by pyjwt.
    # We just need to verify custom claims
    data = jwt.decode(token, secret, algorithm=algorithm)
    if 'jti' not in data or not isinstance(data['jti'], str):
        raise JWTDecodeError("Missing or invalid claim: jti")
    if 'identity' not in data:
        raise JWTDecodeError('Missing claim: identity')
    if 'type' not in data or data['type'] not in ('refresh', 'access'):
        raise JWTDecodeError('Missing or invalid claim: type')
    if data['type'] == 'access':
        if 'fresh' not in data or not isinstance(data['fresh'], bool):
            raise JWTDecodeError('Missing or invalid claim: fresh')
        if 'user_claims' not in data or not isinstance(data['user_claims'], dict):
            raise JWTDecodeError('Missing or invalid claim: user_claims')
    return data


def _decode_jwt_from_request():
    """Parse encoded JWT string from request

    :return: Encoded JWT string, or None if it does not exist
    """
    # Verify we have the auth header
    auth_header = request.headers.get('Authorization', None)
    if not auth_header:
        raise NoAuthHeaderError('Missing Authorization Header')

    # Make sure the header is valid
    parts = auth_header.split()
    if parts[0] != 'Bearer':
        msg = "Badly formatted authorization header. Shoud be 'Bearer <JWT>'"
        raise InvalidHeaderError(msg)
    elif len(parts) != 2:
        msg = "Badly formatted authorization header. Shoud be 'Bearer <JWT>'"
        raise InvalidHeaderError(msg)

    token = parts[1]
    secret = _get_secret_key()
    return _decode_jwt(token, secret, 'HS256')


def jwt_required(fn):
    """If you decorate a view with this, it will ensure that the requester has a valid
    JWT before calling the actual view. This does not check the freshness of the token.
    (TODO href to those docs)
    See also: fresh_jwt_required()

    access_token_required?

    :param fn: The view function to decorate
    :type fn: function
    """
    @_handle_callbacks_on_error
    @wraps(fn)
    def wrapper(*args, **kwargs):
        # attempt to decode the token
        jwt_data = _decode_jwt_from_request()

        # Verify if is access token
        if jwt_data['type'] != 'access':
            raise WrongTokenError('Only access tokens can access this endpoint')

        _check_blacklist(jwt_data)

        ctx_stack.top.jwt_identity = jwt_data['identity']
        ctx_stack.top.jwt_user_claims = jwt_data['user_claims']
        return fn(*args, **kwargs)
    return wrapper


def fresh_jwt_required(fn):
    """If you decorate a view with this, it will ensure that the requester has a valid JWT before calling the actural view
    TODO docs about freshness and callbacks
    See also: jwt_required

    :param fn: The view function to decorate
    :type fn: function
    """
    @_handle_callbacks_on_error
    @wraps(fn)
    def wrapper(*args, **kwargs):
        jwt_data = _decode_jwt_from_request()

        # Verify this is an access token
        if jwt_data['type'] != 'access':
            raise WrongTokenError('Only access tokens can access this endpoint')

        _check_blacklist(jwt_data)

        # Check if the token is fresh
        if not jwt_data['fresh']:
            raise FreshTokenRequired('Fresh token required')

        ctx_stack.top.jwt_identity = jwt_data['identity']
        ctx_stack.top.jwt_user_claims = jwt_data['user_claims']
        return fn(*args, **kwargs)
    return wrapper


def authenticate(identity):
    # Token settings
    config = current_app.config
    access_expire_delta = config.get('JWT_ACCESS_TOKEN_EXPIRES', ACCESS_EXPIRES)
    refresh_expire_delta = config.get('JWT_REFRESH_TOKEN_EXPIRES', REFRESH_EXPIRES)
    algorithm = config.get('JWT_ALGORITHM', ALGORITHM)

    user_claims = current_app.jwt_manager.user_claims_callback(identity)
    secret = _get_secret_key()
    access_token = _encode_access_token(identity, secret, algorithm, access_expire_delta, fresh=True, user_claims=user_claims)
    refresh_token = _encode_refresh_token(identity, secret, algorithm, refresh_expire_delta)

    ret = {
            'access_token': access_token,
            'refresh_token': refresh_token,
    }
    return jsonify(ret), 200


@_handle_callbacks_on_error
def refresh():
    jwt_data = _decode_jwt_from_request()

    # verify this is a refresh token
    if jwt_data['type'] != 'refresh':
        raise WrongTokenError('Only refresh tokens can access this endpoint')

    _check_blacklist(jwt_data)

    config = current_app.config
    access_expire_delta = config.get('JWT_ACCESS_TOKEN_EXPIRES', ACCESS_EXPIRES)
    algorithm = config.get('JWT_ALGORITHM', ALGORITHM)
    secret = _get_secret_key()
    identity = jwt_data['identity']
    user_claims = current_app.jwt_manager.user_claims_callback(identity)
    access_token = _encode_access_token(identity, secret, algorithm, access_expire_delta, fresh=False, user_claims=user_claims)
    ret = {'access_token': access_token}
    return jsonify(ret), 200


def fresh_authenticate(identity):
    secret = _get_secret_key()
    config = current_app.config
    access_expire_delta = config.get('JWT_ACCESS_TOKEN_EXPIRES', ACCESS_EXPIRES)
    refresh_expire_delta = config.get('JWT_REFRESH_TOKEN_EXPIRES', REFRESH_EXPIRES)
    algorithm = config.get('JWT_ALGORITHM', ALGORITHM)

    user_claims = current_app.jwt_manager.user_claims_callback(identity)
    access_token = _encode_access_token(identity, secret, algorithm, access_expire_delta, fresh=True, user_claims=user_claims)
    ret = {
        'access_token': access_token,
    }
    return jsonify(ret), 200


def _get_secret_key():
    key = current_app.config.get('SECRET_KEY', None)
    if not key:
        raise RuntimeError('flask SECRET_KEY must be set')
    return key


def _blacklist_enabled():
    return current_app.config.get('JWT_BLACKLIST', BLACKLIST_ENABLED)


def _get_blacklist_store():
    return current_app.config.get('JWT_BLACKLIST_STORE', BLACKLIST_STORE)


def _blacklist_checks():
    return current_app.config.get('JWT_BLACKLIST_TOKEN_CHECKS', BLACKLIST_TOKEN_CHECKS)


def _store_supports_ttl(store):
    return getattr(store, 'ttl_support', False)


def _store_token_if_blacklist_enabled(jti, token_expire_delta, token_type):
    # If the blacklist isn't enabled, do nothing
    if not _blacklist_enabled():
        return

    # If configured to only check refresh tokens and this isn't a refresh token, return
    if _blacklist_checks() == 'refresh' and token_type != 'refresh':
        return

    # Otherwise store the token in the blacklist (with current status of active)
    store = _get_blacklist_store()
    if _store_supports_ttl(store):
        ttl = token_expire_delta + datetime.timedelta(minutes=15)
        ttl_secs = ttl.total_seconds()
        store.put(key=jti, value="active", ttl_secs=ttl_secs)
    else:
        store.put(key=jti, value="active")

def _handle_callbacks_on_error(fn):
    """Helper decorator that will catch any exceptions we expecte to encounter
    when dealing with a JWT, and call the appropriate callback function for
    handling that error. Callback functions can be set in using the *_loader
    methods in jwt_manager
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        m = current_app.jwt_manager
        try:
            return fn(*args, **kwargs)
        except NoAuthHeaderError:
            return m.unauthorized_callback()
        except jwt.ExpiredSignatureError:
            return m.expired_token_callback()
        except (InvalidHeaderError, jwt.InvalidTokenError, JWTDecodeError, WrongTokenError) as e:
            return m.invalid_token_callback(str(e))
        except RevokedTokenError:
            return m.blacklisted_token_callback()
        except FreshTokenRequired:
            return m.token_needs_refresh_callback()
    return wrapper



def _check_blacklist(jwt_data):
    if not _blacklist_enabled():
        return

    store = _get_blacklist_store()
    token_type = jwt_data['type']
    jti = jwt_data['jti']

    if token_type == 'access' and _blacklist_checks() == 'all':
        token_status = store[jti]
        if token_status != 'active':
            raise RevokedTokenError('{} has been revoked'.format(jti))

    if token_type == 'refresh' and _blacklist_checks() in ('all', 'refresh'):
        token_status = store[jti]
        if token_status != 'active':
            raise RevokedTokenError('{} has been revoked'.format(jti))
