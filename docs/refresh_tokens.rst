Refresh Tokens
==============

Flask-JWT-Extended supports refresh tokens out of the box. These are longer lived token which cannot access a jwt_required protected endpoint, but can be used to create new access tokens once an old access token has expired. By setting the access tokens to a shorter lifetime (see Options below), and utilizing fresh tokens for critical views (see Fresh Tokens below) we can help reduce the damage done if an access token is stolen. Here is an example of how you might use them in your application:


.. code-block:: python

  from flask import Flask, jsonify, request
  from flask_jwt_extended import JWTManager, jwt_required, create_access_token, \
      jwt_refresh_token_required, create_refresh_token, get_jwt_identity

  app = Flask(__name__)
  app.secret_key = 'super-secret'  # Change this!
  jwt = JWTManager(app)


  @app.route('/login', methods=['POST'])
  def login():
      username = request.json.get('username', None)
      password = request.json.get('password', None)
      if username != 'test' and password != 'test':
          return jsonify({"msg": "Bad username or password"}), 401

      # Use create_access_token() and create_refresh_token() to create our
      # access and refresh tokens
      ret = {
          'access_token': create_access_token(identity=username),
          'refresh_token': create_refresh_token(identity=username)
      }
      return jsonify(ret), 200


  # The jwt_refresh_token_required decorator insures a valid refresh token is
  # present in the request before calling this endpoint. We can use the
  # get_jwt_identity() function to get the identity of the refresh toke, and use
  # the create_access_token() function again to make a new access token for this
  # identity.
  @app.route('/refresh', methods=['POST'])
  @jwt_refresh_token_required
  def refresh():
      current_user = get_jwt_identity()
      ret = {
          'access_token': create_access_token(identity=current_user)
      }
      return jsonify(ret), 200


  @app.route('/protected', methods=['GET'])
  @jwt_required
  def protected():
      username = get_jwt_identity()
      return jsonify({'hello': 'from {}'.format(username)}), 200

  if __name__ == '__main__':
      app.run()
