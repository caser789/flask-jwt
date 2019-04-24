from flask import jsonify

try:
    from flask import _app_ctx_stack as ctx_stack
except ImportError:
    from flask import _request_ctx_stack as ctx_stack


class JWTManager:

    def __init__(self, app=None):
        # Function that will be called to add custom user claims to a JWT
        self.user_claims_callback = lambda: {}

        # Function that will be called when an expired token is received
        self.expired_token_callback = lambda: (jsonify({'msg': 'Token has expired'}), 401)

        # Function that will be called when an invalid token is received
        self.invalid_token_callback = lambda err: (jsonify({'msg': err}), 422)

        # Function that will be called when attempting to access a protected endpoint without a valid token
        self.unauthorized_callback = lambda: (jsonify({'msg': 'Missing Authorization Header'}), 401)

        # Function that will be called when attempting to access a fresh_jwt_required endpoint with a valid non-fresh token
        self.token_needs_refresh_callback = lambda: (jsonify({'msg': 'Fresh token required'}), 401)

        # Function that will be called when a revoked token attempts to access
        # a protected endpoint
        self.blacklisted_token_callback = lambda: (jsonify({'msg': 'Token has been revoked'}), 401)

        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """
        register this extension with app
        """
        app.jwt_manager = self

    def user_claims_loader(self, callback):
        """This sets the callback method for adding custom user claims to a JWT

        By default, no extra user claims will be added to the JWT.

        :param callback: The callback function for setting custom user claims
        """
        self.user_claims_callback = callback
        return callback

    def expired_token_loader(self, callback):
        """Sets the callback method to be called if an expired JWT is received

        The default implementation will return json '{"msg": "Token has expired"}' with 401

        Callback must be a function that takes 0 argument
        """
        self.expired_token_callback = callback
        return callback

    def invalid_token_loader(self, callback):
        """Sets the callback method to be called if an invalid JWT is received

        The default implementation will return json '{"msg": <err>}' with 401

        Callback must be a function that takes only one argument
        """
        self.invalid_token_callback = callback
        return callback

    def unauthorized_loader(self, callback):
        """Sets the callback method to be called if an invalid JWT is received

        """
        self.unauthorized_callback = callback
        return callback

    def token_needs_refresh_loader(self, callback):
        self.token_needs_refresh_callback = callback
        return callback

    def blacklist_token_loader(self, callback):
        """Sets the callback method to be called if a blacklisted (revoked) token
        attempt to access a protected endpoint
        The default implementation will return json '{"msg": "Token has been revoked"}'
        with a 401 status code.
        Callback must be a function that takes no arguments
        """
        self.blacklisted_token_callback = callback
        return callback
