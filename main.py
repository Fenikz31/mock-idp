import base64
import json
import os
import secrets
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, abort, jsonify, redirect, render_template_string, request, url_for

app = Flask(__name__)
# Disable static file handling for .json files to allow routes with .json extension
app.url_map.strict_slashes = False

# -------------------------------------------------------------------
# User catalog utilities (drives mock identities)

USER_CATALOG_PATH = Path(
    os.getenv(
        "MOCK_IDP_USER_CATALOG",
        Path(__file__).with_name("users.json"),
    )
)
USER_CATALOG_AUTO_RELOAD = os.getenv("MOCK_IDP_USER_CATALOG_AUTO_RELOAD", "false").lower() in ("true", "1", "yes")
_USER_CATALOG_CACHE: Dict[str, Any] = {"data": None, "etag": None}


def _load_user_catalog_from_disk() -> List[Dict]:
    global _USER_CATALOG_CACHE  # pylint: disable=global-statement
    try:
        stat = USER_CATALOG_PATH.stat()
        should_reload = (
            _USER_CATALOG_CACHE["data"] is None
            or USER_CATALOG_AUTO_RELOAD
            or _USER_CATALOG_CACHE["etag"] != stat.st_mtime
        )
        if should_reload:
            with USER_CATALOG_PATH.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
                if isinstance(data, list):
                    _USER_CATALOG_CACHE = {"data": data, "etag": stat.st_mtime}
                else:
                    app.logger.warning("User catalog at %s must be a list. Ignoring.", USER_CATALOG_PATH)
                    _USER_CATALOG_CACHE = {"data": [], "etag": stat.st_mtime}
    except FileNotFoundError:
        if _USER_CATALOG_CACHE["data"] is None:
            app.logger.warning("User catalog not found at %s", USER_CATALOG_PATH)
        _USER_CATALOG_CACHE = {"data": [], "etag": None}
    return _USER_CATALOG_CACHE["data"] or []


def get_user_catalog() -> List[Dict]:
    """Expose the cached mock user catalog."""
    return _load_user_catalog_from_disk()


def find_user_profile(identifier: Optional[str]) -> Optional[Dict]:
    """Lookup a mock user profile by id or email."""
    if not identifier:
        return None
    catalog = get_user_catalog()
    normalized_email = identifier.strip().lower()
    for entry in catalog:
        email = entry.get("email")
        if email and email.strip().lower() == normalized_email:
            return entry
        if entry.get("id") == identifier:
            return entry
    return None

# -------------------------------------------------------------------
# Configuration helpers

ISSUER = os.getenv("OIDC_ISSUER", "http://localhost:5000")
SIGNING_KEY = os.getenv("OIDC_SIGNING_KEY", "dummy-signing-key")
SIGNING_ALG = os.getenv("OIDC_SIGNING_ALG", "RS256")
KEY_ID = os.getenv("OIDC_SIGNING_KEY_ID", "mock-key")
ACCESS_TOKEN_TTL_SECONDS = int(os.getenv("OIDC_ACCESS_TOKEN_TTL", "3600"))
CODE_TTL_SECONDS = int(os.getenv("OIDC_CODE_TTL", "120"))
STRICT_VALIDATION = os.getenv("OIDC_STRICT_VALIDATION", "false").lower() in ("true", "1", "yes")
AUTO_APPROVE = os.getenv("OIDC_AUTO_APPROVE", "true").lower() in ("true", "1", "yes")

# Generate RSA key pair for RS256 signing
def generate_rsa_key_pair():
    """Generate a new RSA key pair for JWT signing."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

# Initialize RSA keys
RSA_PRIVATE_KEY, RSA_PUBLIC_KEY = generate_rsa_key_pair()

DEFAULT_CLIENTS: Dict[str, Dict] = {
    "test-questel-client": {
        "client_secret": "test-questel-secret",
        "redirect_uris": [
            "http://localhost:8080/oidc/external/callback",
        ],
        "allowed_email_domains": ["questel.com"],
        "display_name": "Questel Mock IdP",
        "default_email": "user@questel.com",
        "default_first_name": "Quality",
        "default_last_name": "Assurance",
        "default_account_name": "Questel Test Account",
        "default_services": ["EQCORPORATEPLUS"],
        "default_rights": ["read", "write"],
        "scopes": ["openid", "profile", "email", "account", "services", "rights"],
    }
}


def load_clients() -> Dict[str, Dict]:
    """Load client configuration from JSON env/file or fallback to default."""
    config_json = os.getenv("OIDC_CLIENTS_JSON")
    config_file = os.getenv("OIDC_CLIENTS_FILE")

    if config_json:
        return json.loads(config_json)
    if config_file and os.path.exists(config_file):
        with open(config_file, "r", encoding="utf-8") as handle:
            return json.load(handle)
    return DEFAULT_CLIENTS


CLIENTS = load_clients()
SUPPORTED_SCOPES = sorted(
    {scope for client in CLIENTS.values() for scope in client.get("scopes", [])}
    or ["openid", "profile", "email"]
)

AUTHORIZATION_CODES: Dict[str, Dict] = {}
ACCESS_TOKENS: Dict[str, Dict] = {}


def get_client(client_id: str) -> Optional[Dict]:
    return CLIENTS.get(client_id)


def validate_redirect_uri(client: Dict, redirect_uri: str) -> bool:
    allowed = client.get("redirect_uris", [])
    if not allowed:
        return True
    if redirect_uri in allowed:
        return True
    parsed = urlparse(redirect_uri)
    host = parsed.netloc
    allowed_hosts = client.get("allowed_redirect_hosts", [])
    return host in allowed_hosts


def validate_email(client: Dict, email: str) -> bool:
    if not email or not email.strip():
        app.logger.debug("validate_email: email is empty or whitespace only")
        return False
    # Basic email format validation
    if "@" not in email:
        app.logger.debug("validate_email: email '%s' does not contain '@'", email)
        return False
    try:
        domain_part = email.split("@")[1]
        if "." not in domain_part:
            app.logger.debug("validate_email: email '%s' domain part '%s' does not contain '.'", email, domain_part)
            return False
    except IndexError:
        app.logger.debug("validate_email: email '%s' split by '@' failed", email)
        return False
    # In lenient mode (STRICT_VALIDATION=false), accept all emails
    if not STRICT_VALIDATION:
        app.logger.debug("validate_email: email '%s' accepted in lenient mode", email)
        return True
    # In strict mode, check allowed domains
    domains = client.get("allowed_email_domains", [])
    if not domains:
        app.logger.debug("validate_email: email '%s' accepted (no domain restrictions)", email)
        return True
    is_allowed = any(email.lower().endswith(f"@{domain.lower()}") for domain in domains)
    app.logger.debug("validate_email: email '%s' domain check result: %s", email, is_allowed)
    return is_allowed


def default_email_for_client(client: Dict) -> str:
    email = client.get("default_email")
    if email:
        return email
    domains = client.get("allowed_email_domains", [])
    if domains:
        return f"user@{domains[0]}"
    return "user@example.com"


def build_user_claims(client: Dict, email: str, scopes: List[str]) -> Dict:
    profile = find_user_profile(email)
    base = {
        "sub": email,
        "email": email,
        "given_name": client.get("default_first_name", "Quality"),
        "family_name": client.get("default_last_name", "Assurance"),
        "name": f"{client.get('default_first_name', 'Quality')} {client.get('default_last_name', 'Assurance')}",
    }

    if profile:
        given = profile.get("firstname")
        family = profile.get("lastname")
        if given:
            base["given_name"] = given
        if family:
            base["family_name"] = family
        full_name = f"{given or ''} {family or ''}".strip()
        if full_name:
            base["name"] = full_name
        if profile.get("account"):
            base["account"] = profile.get("account")
        if profile.get("services"):
            base["services"] = profile.get("services")
        if profile.get("rights"):
            base["rights"] = profile.get("rights")
        if profile.get("id"):
            base["user_id"] = profile.get("id")

    if "account" in scopes and "account" not in base:
        base["account"] = client.get("default_account_name", "Questel Test Account")
    if "services" in scopes and "services" not in base:
        base["services"] = client.get("default_services", [])
    if "rights" in scopes and "rights" not in base:
        base["rights"] = client.get("default_rights", [])
    return base


def issue_id_token(client_id: str, email: str, scopes: List[str], nonce: Optional[str]):
    now = int(time.time())
    client = CLIENTS[client_id]
    claims = build_user_claims(client, email, scopes)
    payload = {
        "iss": ISSUER,
        "aud": client_id,
        "sub": claims["sub"],
        "email": claims["email"],
        "given_name": claims.get("given_name"),
        "family_name": claims.get("family_name"),
        "name": claims.get("name"),
        "iat": now,
        "exp": now + ACCESS_TOKEN_TTL_SECONDS,
        "auth_time": now,
    }
    if nonce:
        payload["nonce"] = nonce
    
    # Use RSA private key for RS256, or symmetric key for HS256
    if SIGNING_ALG.startswith("RS"):
        # PyJWT accepts cryptography key objects directly
        return jwt.encode(payload, RSA_PRIVATE_KEY, algorithm=SIGNING_ALG, headers={"kid": KEY_ID})
    else:
        return jwt.encode(payload, SIGNING_KEY, algorithm=SIGNING_ALG, headers={"kid": KEY_ID})


# -------------------------------------------------------------------
# User catalog exposure (used by mock-client-rp)
@app.route("/users.json")
def list_mock_users():
    return jsonify(get_user_catalog())


# -------------------------------------------------------------------
# Lenient-mode helpers (always-positive responses by default)
def pick_default_client() -> Optional[Tuple[str, Dict]]:
    try:
        return next(iter(CLIENTS.items()))
    except StopIteration:
        return None


def coerce_client(client_id: Optional[str]) -> Tuple[str, Dict]:
    if client_id and client_id in CLIENTS:
        return client_id, CLIENTS[client_id]
    default_entry = pick_default_client()
    if default_entry and not STRICT_VALIDATION:
        app.logger.warning("Unknown client_id '%s', falling back to '%s'", client_id, default_entry[0])
        return default_entry
    if not client_id:
        abort(400, description="Missing client_id")
    abort(400, description="Unknown client_id")


def coerce_redirect_uri(client: Dict, redirect_uri: Optional[str]) -> str:
    if redirect_uri and validate_redirect_uri(client, redirect_uri):
        return redirect_uri
    allowed = client.get("redirect_uris", [])
    if allowed and not STRICT_VALIDATION:
        fallback = allowed[0]
        app.logger.warning("Invalid redirect_uri '%s', using fallback '%s'", redirect_uri, fallback)
        return fallback
    if redirect_uri:
        abort(400, description="Invalid redirect_uri for this client")
    if allowed:
        return allowed[0]
    abort(400, description="redirect_uri is required")


def coerce_email(client: Dict, email: Optional[str]) -> str:
    app.logger.debug("coerce_email: called with email='%s', STRICT_VALIDATION=%s", email, STRICT_VALIDATION)
    if email:
        email = email.strip()
        if validate_email(client, email):
            app.logger.debug("coerce_email: email '%s' validated successfully", email)
            return email.lower()
        else:
            app.logger.debug("coerce_email: email '%s' failed validation", email)
    else:
        app.logger.debug("coerce_email: email is None or empty")
    if STRICT_VALIDATION:
        abort(400, description="Email domain not allowed or missing email")
    fallback = default_email_for_client(client)
    app.logger.warning("Invalid email '%s', using fallback '%s'", email, fallback)
    return fallback


# -------------------------------------------------------------------
# Discovery document
@app.route("/.well-known/openid-configuration")
def openid_config():
    return jsonify(
        {
            "issuer": ISSUER,
            "authorization_endpoint": f"{ISSUER}/authorize",
            "token_endpoint": f"{ISSUER}/token",
            "userinfo_endpoint": f"{ISSUER}/userinfo",
            "jwks_uri": f"{ISSUER}/jwks.json",
            "scopes_supported": SUPPORTED_SCOPES,
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": [SIGNING_ALG],
            "claims_supported": [
                "sub",
                "email",
                "name",
                "given_name",
                "family_name",
                "account",
                "services",
                "rights",
            ],
        }
    )


# -------------------------------------------------------------------
# JWKS
def jwks():
    """Generate JWKS response"""
    if SIGNING_ALG.startswith("RS"):
        # Export RSA public key as JWK
        public_numbers = RSA_PUBLIC_KEY.public_numbers()
        
        # Calculate byte length for n (modulus) - for 2048-bit key, it's 256 bytes
        n_value = public_numbers.n
        n_bit_length = n_value.bit_length()
        n_byte_length = (n_bit_length + 7) // 8
        n_bytes = n_value.to_bytes(n_byte_length, byteorder="big")
        
        # e (exponent) is typically 65537, which fits in 3 bytes
        e_value = public_numbers.e
        e_bit_length = e_value.bit_length()
        e_byte_length = (e_bit_length + 7) // 8  # Calculate byte length
        e_bytes = e_value.to_bytes(e_byte_length, byteorder="big")
        
        jwk_key = {
            "kty": "RSA",
            "kid": KEY_ID,
            "use": "sig",
            "alg": SIGNING_ALG,
            "n": base64.urlsafe_b64encode(n_bytes).decode("utf-8").rstrip("="),
            "e": base64.urlsafe_b64encode(e_bytes).decode("utf-8").rstrip("="),
        }
    elif SIGNING_ALG.startswith("HS"):
        jwk_key = {
            "kty": "oct",
            "kid": KEY_ID,
            "use": "sig",
            "alg": SIGNING_ALG,
            "k": SIGNING_KEY,
        }
    else:
        abort(500, description=f"Unsupported signing algorithm: {SIGNING_ALG}")

    return jsonify({"keys": [jwk_key]})

# Register JWKS routes - well-known first to ensure it's matched before /jwks.json
# Use add_url_rule for explicit control over route registration
app.add_url_rule("/.well-known/jwks.json", "well_known_jwks", jwks, methods=["GET"], strict_slashes=False)
app.add_url_rule("/jwks.json", "jwks", jwks, methods=["GET"])

# Fallback 404 handler for /.well-known/jwks.json (workaround for Flask route matching issues)
@app.errorhandler(404)
def handle_404(e):
    """Handle 404 errors, specifically for /.well-known/jwks.json"""
    if request.path == "/.well-known/jwks.json" or request.path == "/.well-known/jwks.json/":
        return jwks()
    # Return standard 404 for other paths
    return jsonify({"error": "Not found", "path": request.path}), 404


# -------------------------------------------------------------------
# Authorization endpoint
@app.route("/authorize")
def authorize():
    client_id, client = coerce_client(request.args.get("client_id"))
    redirect_uri = coerce_redirect_uri(client, request.args.get("redirect_uri"))
    state = request.args.get("state", "")
    nonce = request.args.get("nonce", "")
    scope = request.args.get("scope", "openid profile email")

    force_form = request.args.get("prompt", "").lower() == "login"
    if AUTO_APPROVE and not force_form:
        # Support both 'login_hint' (OIDC standard) and 'email' parameters
        # login_hint takes precedence if both are provided
        email_param = request.args.get("login_hint") or request.args.get("email")
        app.logger.info("AUTO_APPROVE: login_hint='%s', email='%s', using email_param='%s'", 
                       request.args.get("login_hint"), request.args.get("email"), email_param)
        email = coerce_email(client, email_param)
        app.logger.info("AUTO_APPROVE: final email after coerce_email='%s'", email)
        code = create_authorization_code(client_id, email, scope.split(), nonce)
        return redirect(f"{redirect_uri}?code={code}&state={state}")

    form_html = f"""
    <html>
      <body>
        <h2>{client.get('display_name', 'Mock OIDC Login')}</h2>
        <p>Client: {client_id}</p>
        <p>Redirect URI: {redirect_uri}</p>
        <form method="post" action="/login">
          <input type="hidden" name="client_id" value="{client_id}">
          <input type="hidden" name="redirect_uri" value="{redirect_uri}">
          <input type="hidden" name="state" value="{state}">
          <input type="hidden" name="nonce" value="{nonce}">
          <input type="hidden" name="scope" value="{scope}">
           Email: <input type="text" name="email" value="{request.args.get('login_hint', request.args.get('email', ''))}"><br>
          <button type="submit">Login</button>
        </form>
      </body>
    </html>
    """
    return render_template_string(form_html)


@app.route("/login", methods=["POST"])
def login():
    client_id, client = coerce_client(request.form.get("client_id"))
    redirect_uri = coerce_redirect_uri(client, request.form.get("redirect_uri"))
    email = coerce_email(client, request.form.get("email", "").strip().lower())
    state = request.form.get("state", "")
    nonce = request.form.get("nonce", "")
    scope = request.form.get("scope", "openid profile email")

    code = create_authorization_code(client_id, email, scope.split(), nonce)
    return redirect(f"{redirect_uri}?code={code}&state={state}")


def create_authorization_code(client_id: str, email: str, scopes: List[str], nonce: str) -> str:
    code = secrets.token_urlsafe(32)
    AUTHORIZATION_CODES[code] = {
        "email": email,
        "client_id": client_id,
        "scopes": scopes,
        "nonce": nonce,
        "expires_at": datetime.utcnow() + timedelta(seconds=CODE_TTL_SECONDS),
    }
    return code


def extract_client_credentials():
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Basic "):
        try:
            import base64

            decoded = base64.b64decode(auth_header.split(" ")[1]).decode("utf-8")
            client_id, client_secret = decoded.split(":", 1)
            return client_id, client_secret
        except Exception:  # pylint: disable=broad-except
            abort(400, description="Invalid Authorization header")
    return request.form.get("client_id"), request.form.get("client_secret")


@app.route("/token", methods=["POST"])
def token():
    client_id, client_secret = extract_client_credentials()
    client_id, client = coerce_client(client_id)

    expected_secret = client.get("client_secret")
    if expected_secret and client_secret != expected_secret:
        if STRICT_VALIDATION:
            abort(401, description="Invalid client credentials")
        app.logger.warning("Invalid client_secret for '%s', accepting in lenient mode", client_id)

    code = request.form.get("code")
    grant_type = request.form.get("grant_type", "authorization_code")
    if grant_type != "authorization_code":
        abort(400, description="Only authorization_code grant is supported")

    code_data = AUTHORIZATION_CODES.pop(code, None)
    if not code_data:
        if STRICT_VALIDATION:
            abort(400, description="Invalid or expired code")
        app.logger.warning("Invalid code provided, issuing tokens anyway (lenient mode)")
        code_data = {
            "email": default_email_for_client(client),
            "client_id": client_id,
            "scopes": client.get("scopes", ["openid"]),
            "nonce": "",
            "expires_at": datetime.utcnow() + timedelta(seconds=CODE_TTL_SECONDS),
        }
    if code_data["client_id"] != client_id:
        if STRICT_VALIDATION:
            abort(400, description="Code was not issued for this client")
        app.logger.warning("Code belonged to another client, overriding to '%s'", client_id)
        code_data["client_id"] = client_id
    if code_data["expires_at"] < datetime.utcnow():
        if STRICT_VALIDATION:
            abort(400, description="Code expired")
        app.logger.warning("Code expired, refreshing expiration timestamp")
        code_data["expires_at"] = datetime.utcnow() + timedelta(seconds=CODE_TTL_SECONDS)

    email = code_data["email"]
    scopes = code_data["scopes"]
    nonce = code_data["nonce"]
    access_token = secrets.token_urlsafe(32)

    ACCESS_TOKENS[access_token] = {
        "email": email,
        "client_id": client_id,
        "scopes": scopes,
        "expires_at": datetime.utcnow() + timedelta(seconds=ACCESS_TOKEN_TTL_SECONDS),
    }

    id_token = issue_id_token(client_id, email, scopes, nonce)
    user_claims = build_user_claims(client, email, scopes)

    return jsonify(
        {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_TTL_SECONDS,
            "id_token": id_token,
            "scope": " ".join(scopes),
            "userinfo": user_claims,
        }
    )


# -------------------------------------------------------------------
# Health check endpoint
@app.route("/selfTest")
def self_test():
    return (
        jsonify(
            {
                "status": "ok",
                "service": "Questel Mock OIDC Provider",
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }
        ),
        200,
    )


# -------------------------------------------------------------------
# Userinfo endpoint
@app.route("/userinfo")
def userinfo():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        if STRICT_VALIDATION:
            abort(401, description="Missing bearer token")
        app.logger.warning("Missing bearer token, returning default claims (lenient mode)")
        default_entry = pick_default_client()
        client = default_entry[1] if default_entry else {}
        email = default_email_for_client(client) if client else "user@example.com"
        scopes = client.get("scopes", ["openid"]) if client else ["openid"]
        return jsonify(build_user_claims(client, email, scopes))

    token = auth_header.split(" ")[1]
    token_data = ACCESS_TOKENS.get(token)
    if not token_data or token_data["expires_at"] < datetime.utcnow():
        if STRICT_VALIDATION:
            abort(401, description="Invalid or expired token")
        app.logger.warning("Invalid token '%s', returning default claims (lenient mode)", token)
        default_entry = pick_default_client()
        client = default_entry[1] if default_entry else {}
        email = default_email_for_client(client) if client else "user@example.com"
        scopes = client.get("scopes", ["openid"]) if client else ["openid"]
        return jsonify(build_user_claims(client, email, scopes))

    client = get_client(token_data["client_id"])
    claims = build_user_claims(client, token_data["email"], token_data["scopes"])
    return jsonify(claims)


# -------------------------------------------------------------------
# Callback (for manual testing in browser)
@app.route("/callback")
def callback():
    code = request.args.get("code", "")
    state = request.args.get("state", "")
    return f"✅ Logged in with code={code}, state={state}"


# -------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=True)
