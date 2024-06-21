from requests_oauthlib import OAuth2Session
from flask import Flask, request, redirect, session, url_for
from flask.json import jsonify
import os
import json
from flask_session import Session

app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

fileObject = open("creds.json", "r")
jsoncontent = fileObject.read()
creds = json.loads(jsoncontent)

# This information is obtained upon registration of a new GitHub OAuth
# application here: https://github.com/settings/applications/new
client_id = creds['client_id']
client_secret = creds['client_secret']
authorization_base_url = 'https://github.com/login/oauth/authorize'
token_url = 'https://github.com/login/oauth/access_token'


@app.route("/")
def demo():
    """Step 1: User Authorization.

    Redirect the user/resource owner to the OAuth provider (i.e. Github)
    using an URL with a few key OAuth parameters.
    """
    github = OAuth2Session(client_id)
    authorization_url, state = github.authorization_url(authorization_base_url)

    # State is used to prevent CSRF, keep this for later.
    session['oauth_state'] = state
    print(f"State set in session: {state}")
    return redirect(authorization_url)


@app.route("/callback", methods=["GET"])
def callback():
    """ Step 3: Retrieving an access token.

    The user has been redirected back from the provider to your registered
    callback URL. With this redirection comes an authorization code included
    in the redirect URL. We will use that to obtain an access token.
    """
    try:
        oauth_state = session['oauth_state']
        github = OAuth2Session(client_id, state=oauth_state)
        token = github.fetch_token(token_url, client_secret=client_secret,
                                   authorization_response=request.url)

        session['oauth_token'] = token
        return redirect(url_for('.profile'))
    except KeyError as e:
        print(f"KeyError: {str(e)}")
        return jsonify({"error": "Session state not found"}), 400
    except Exception as e:
        print(f"Exception: {str(e)}")
        return jsonify({"error": "An error occurred"}), 500


@app.route("/profile", methods=["GET"])
def profile():
    """Fetching a protected resource using an OAuth 2 token.
    """
    try:
        oauth_token = session['oauth_token']
        github = OAuth2Session(client_id, token=oauth_token)
        user_info = github.get('https://api.github.com/user').json()
        return jsonify(user_info)
    except KeyError as e:
        print(f"KeyError: {str(e)}")
        return jsonify({"error": "OAuth token not found"}), 400
    except Exception as e:
        print(f"Exception: {str(e)}")
        return jsonify({"error": "An error occurred"}), 500


if __name__ == "__main__":
    # This allows us to use a plain HTTP callback
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = "1"

    app.secret_key = os.urandom(24)
    app.run(ssl_context="adhoc")
