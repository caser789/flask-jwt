import datetime

# How long an access token will live before it expires
ACCESS_EXPIRES = datetime.timedelta(minutes=15)


# How long the refresh token will live before it expires
REFRESH_EXPIRES = datetime.timedelta(days=30)


# What algorithm to use to sign the token. See here for a list of options:
# https://github.com/jpadilla/pyjwt/blob/master/jwt/api_jwt.py
ALGORITHM = 'HS256'


# Blacklist enabled
# blacklist storage options (simplekv)
# blacklist check requests (all, refresh_token, none)
BLACKLIST_ENABLED = False
BLACKLIST_STORE = None

# blacklist check requests. Possible values are all, refresh, and None
BLACKLIST_TOKEN_CHECKS = None
