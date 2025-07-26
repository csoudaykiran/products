import connexion
from flask import request, jsonify, redirect
import jwt
import time
from urllib.parse import urlencode
from flask_cors import CORS

# Secret key for JWT encoding (in prod use env variable)
JWT_SECRET = "secret123"
JWT_ALGORITHM = "HS256"

# Mock clients with allowed scopes
CLIENTS = {
    "123": {"secret": "abc123", "scopes": ["read"]},
    "456": {"secret": "xyz456", "scopes": ["read", "write"]},
}

# Authorization codes storage (mock)
AUTH_CODES = {}

app = connexion.App(__name__, specification_dir='.')
flask_app = app.app

CORS(flask_app)

# OAuth2 Authorization endpoint (simulated user approval)
@flask_app.route('/authorize')
def authorize():
    # Extract query parameters
    client_id = request.args.get('client_id')
    redirect_uri = request.args.get('redirect_uri')
    scope = request.args.get('scope')  # e.g. "read write"
    state = request.args.get('state')

    if client_id not in CLIENTS:
        return "Invalid client_id", 400

    # For demo: auto-approve scopes allowed for client
    allowed_scopes = CLIENTS[client_id]['scopes']
    requested_scopes = scope.split() if scope else []
    approved_scopes = [s for s in requested_scopes if s in allowed_scopes]

    # Generate authorization code (random string)
    code = f"authcode-{int(time.time())}"
    AUTH_CODES[code] = {
        "client_id": client_id,
        "scopes": approved_scopes,
    }

    # Redirect back to client with code and state
    params = {'code': code}
    if state:
        params['state'] = state
    redirect_url = redirect_uri + "?" + urlencode(params)
    return redirect(redirect_url)


# OAuth2 Token endpoint
@flask_app.route('/token', methods=['POST'])
def token():
    grant_type = request.form.get('grant_type')
    code = request.form.get('code')
    client_id = request.form.get('client_id')
    # client_secret = request.form.get('client_secret')

    if grant_type != 'authorization_code':
        return jsonify({"error": "unsupported_grant_type"}), 400

    # if client_id not in CLIENTS or CLIENTS[client_id]['secret'] != client_secret:
    #     return jsonify({"error": "invalid_client"}), 401

    if code not in AUTH_CODES or AUTH_CODES[code]['client_id'] != client_id:
        return jsonify({"error": "invalid_grant"}), 400

    scopes = AUTH_CODES[code]['scopes']

    # Create JWT access token with scopes
    payload = {
        "sub": client_id,
        "scope": scopes,
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    # Remove used auth code
    del AUTH_CODES[code]

    return jsonify({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": " ".join(scopes),
    })


def verify_token(token, required_scopes=None):
    print(f"[DEBUG] verify_token called with token={token}, required_scopes={required_scopes}")

    if not token:
        return {"active": False, "error": "Missing Bearer token"}

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        token_scopes = payload.get("scope", [])
        if isinstance(token_scopes, str):
            token_scopes = token_scopes.split()

        # Check if all required scopes are present
        if required_scopes and not all(scope in token_scopes for scope in required_scopes):
            return {"active": False, "error": f"Missing required scopes: {required_scopes}"}

        return {
            "active": True,
            "client_id": payload.get("sub"),
            "scope": " ".join(token_scopes),
            "sub": payload.get("sub"),
            "exp": payload.get("exp"),
            "iat": payload.get("iat")
        }

    except jwt.ExpiredSignatureError:
        return {"active": False, "error": "Token expired"}
    except jwt.InvalidTokenError:
        return {"active": False, "error": "Invalid token"}

# API endpoint implementations

def get_items():
    ok, result = verify_token(["read"])
    if not ok:
        return jsonify({"error": result}), 403
    return jsonify({"items": ["apple", "banana", "cherry"]})


def create_item():
    ok, result = verify_token(["write"])
    if not ok:
        return jsonify({"error": result}), 403
    data = request.json
    if not data or "name" not in data:
        return jsonify({"error": "Missing 'name' field"}), 400
    return jsonify({"message": "Item created", "item": data}), 201


# Add API from OpenAPI spec
app.add_api('open.yml', arguments={'title': 'OAuth2 Scope Demo API'}, pythonic_params=True)

# Map endpoint functions
app.app.add_url_rule('/items', 'get_items', get_items, methods=['GET'])
app.app.add_url_rule('/items', 'create_item', create_item, methods=['POST'])


if __name__ == '__main__':
    app.run(port=5000)
