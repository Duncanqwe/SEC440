import os
import json
from flask import Flask, redirect, url_for, session, request
from requests_oauthlib import OAuth2Session

# Read credentials from creds.json
fileObject = open("creds.json", "r")
jsoncontent = fileObject.read()
creds = json.loads(jsoncontent)

# Define your client_id, client_secret, etc. from creds.json
client_id = creds['client_id']
client_secret = creds['client_secret']
authorization_base_url = 'https://github.com/login/oauth/authorize'
token_url = 'https://github.com/login/oauth/access_token'
redirect_uri = 'https://127.0.0.1:5000'

app = Flask(__name__)
app.secret_key = os.urandom(24)

@app.route("/")
def index():
    """Step 1: User Authorization.
    Redirect the user/resource owner to the OAuth provider (i.e. Github)
    using an URL with a few key OAuth parameters.
    """
    github = OAuth2Session(client_id, redirect_uri=redirect_uri)
    authorization_url, state = github.authorization_url(authorization_base_url)

    # State is used to prevent CSRF, keep this for later.
    session['oauth_state'] = state
    return redirect(authorization_url)

@app.route("/callback", methods=["GET"])
def callback():
    """ Step 2: User authorization, this happens on the provider. """

    # Step 3: Retrieving an access token.
    github = OAuth2Session(client_id, redirect_uri=redirect_uri, state=session['oauth_state'])
    token = github.fetch_token(token_url, client_secret=client_secret, authorization_response=request.url)

    # Step 4: Fetching a protected resource using an OAuth 2 token.
    session['oauth_token'] = token
    return redirect(url_for('.profile'))

@app.route("/profile", methods=["GET"])
def profile():
    """Fetching a protected resource using an OAuth 2 token.
    """
    github = OAuth2Session(client_id, token=session['oauth_token'])
    return jsonify(github.get('https://api.github.com/user').json())

if __name__ == "__main__":
    # This allows us to use a plain HTTP callback
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = "1"

    app.run(ssl_context="adhoc")
