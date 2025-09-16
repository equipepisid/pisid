import time
import secrets
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import Dict
from flask import Blueprint, request, redirect, render_template, session, url_for, current_app, jsonify, abort
import jwt
from ...extensions import db, limiter
from ...models import User, OAuthClient, OAuthConsent


oauth_bp = Blueprint("oauth", __name__, template_folder="../../templates/oauth")

# Simple in-memory store for authorization codes (demo purpose)
AUTH_CODES: Dict[str, dict] = {}


def _require_login():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return User.query.get(user_id)


def _validate_client_and_redirect(client_id: str, redirect_uri: str) -> OAuthClient:
    client = OAuthClient.query.filter_by(client_id=client_id).first()
    if not client:
        abort(400, "invalid_client")
    allowed = [u.strip() for u in client.redirect_uris.split(",")]
    if redirect_uri not in allowed:
        abort(400, "invalid_redirect_uri")
    return client


@oauth_bp.route("/authorize", methods=["GET", "POST"])
def authorize():
    # Params: response_type=(code|token), client_id, redirect_uri, scope, state
    response_type = request.values.get("response_type")
    client_id = request.values.get("client_id")
    redirect_uri = request.values.get("redirect_uri")
    scope = request.values.get("scope", "openid profile email")
    state = request.values.get("state")

    if not response_type or not client_id or not redirect_uri:
        abort(400, "invalid_request")

    user = _require_login()
    if not user:
        # after login, redirect back here
        session["post_login_redirect"] = request.full_path
        return redirect(url_for("auth.login"))

    client = _validate_client_and_redirect(client_id, redirect_uri)

    # Has consent?
    consent = OAuthConsent.query.filter_by(user_id=user.id, client_id=client_id).first()
    if request.method == "POST":
        decision = request.form.get("decision")
        if decision == "approve":
            if not consent:
                consent = OAuthConsent(user_id=user.id, client_id=client_id, scope=scope)
                db.session.add(consent)
                db.session.commit()
            if response_type == "code":
                code = secrets.token_urlsafe(32)
                AUTH_CODES[code] = {
                    "user_id": user.id,
                    "client_id": client_id,
                    "scope": scope,
                    "exp": time.time() + 300,
                }
                params = {"code": code}
                if state:
                    params["state"] = state
                return redirect(f"{redirect_uri}?{urllib.parse.urlencode(params)}")
            elif response_type == "token":
                # Implicit: issue access token directly and return via fragment
                now = datetime.now(timezone.utc)
                exp_seconds = current_app.config.get("OAUTH_ACCESS_TOKEN_EXPIRES", 3600)
                payload = {
                    "sub": str(user.uuid),
                    "email": user.email,
                    "scope": scope,
                    "aud": client_id,
                    "iat": int(now.timestamp()),
                    "exp": int((now + timedelta(seconds=exp_seconds)).timestamp()),
                }
                access_token = jwt.encode(payload, current_app.config["OAUTH_JWT_SECRET"], algorithm=current_app.config["OAUTH_JWT_ALG"])  # type: ignore
                fragment = {
                    "access_token": access_token,
                    "token_type": "Bearer",
                    "expires_in": exp_seconds,
                }
                if state:
                    fragment["state"] = state
                return redirect(f"{redirect_uri}#{urllib.parse.urlencode(fragment)}")
        else:
            # denied
            params = {"error": "access_denied"}
            if state:
                params["state"] = state
            return redirect(f"{redirect_uri}?{urllib.parse.urlencode(params)}")

    # GET or need consent
    return render_template("oauth/consent.html", client=client, scope=scope)


@oauth_bp.route("/token", methods=["POST"])
@limiter.limit("20/minute")
def token():
    # grant_type=authorization_code, code, redirect_uri, client_id, client_secret
    grant_type = request.form.get("grant_type")
    if grant_type != "authorization_code":
        return jsonify({"error": "unsupported_grant_type"}), 400

    code = request.form.get("code")
    client_id = request.form.get("client_id")
    client_secret = request.form.get("client_secret")
    redirect_uri = request.form.get("redirect_uri")
    if not all([code, client_id, client_secret, redirect_uri]):
        return jsonify({"error": "invalid_request"}), 400

    client = _validate_client_and_redirect(client_id, redirect_uri)  # also validates redirect_uri

    # Verify client_secret (stored as bcrypt hash)
    import bcrypt as _bcrypt
    if not _bcrypt.checkpw(client_secret.encode("utf-8"), client.client_secret_hash):
        return jsonify({"error": "invalid_client"}), 401

    data = AUTH_CODES.pop(code, None)
    if not data or data.get("client_id") != client_id or data.get("exp", 0) < time.time():
        return jsonify({"error": "invalid_grant"}), 400

    user = User.query.get(data["user_id"])  # type: ignore
    if not user:
        return jsonify({"error": "invalid_grant"}), 400

    now = datetime.now(timezone.utc)
    exp_seconds = current_app.config.get("OAUTH_ACCESS_TOKEN_EXPIRES", 3600)
    payload = {
        "sub": str(user.uuid),
        "email": user.email,
        "scope": data.get("scope", "openid"),
        "aud": client_id,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=exp_seconds)).timestamp()),
    }
    token = jwt.encode(payload, current_app.config["OAUTH_JWT_SECRET"], algorithm=current_app.config["OAUTH_JWT_ALG"])  # type: ignore
    return jsonify({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": exp_seconds,
    })


@oauth_bp.route("/userinfo", methods=["GET"])
def userinfo():
    # Expect Authorization: Bearer <token>
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "invalid_token"}), 401
    token = auth.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, current_app.config["OAUTH_JWT_SECRET"], algorithms=[current_app.config["OAUTH_JWT_ALG"]])  # type: ignore
    except Exception:
        return jsonify({"error": "invalid_token"}), 401
    return jsonify({
        "sub": payload.get("sub"),
        "email": payload.get("email"),
        "scope": payload.get("scope"),
        "aud": payload.get("aud"),
    })
