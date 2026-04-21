"""
VIP Auth Hub – FIDO2/WebAuthn Registration & Authentication POC
===============================================================
Flask backend that drives the full FIDO lifecycle against the VIP Auth Hub
(Identity Security Platform) REST API.

Flow overview
-------------
Registration
  1. Acquire privileged-client access token  (OAuth2 client_credentials)
  2. Initiate authentication flow             (POST /auth/v1/authenticate)
  3. Select FIDO factor                       (POST /auth/v1/SelectedFactor)
     → server responds PASSWORD_AUTH because no credential exists yet
  4. Authenticate with password               (POST /factor/v1/PasswordAuthenticator)
     → server responds FIDO_REGISTER_GENERATE_CHALLENGE
  5. Generate registration challenge          (POST /factor/v1/FIDORegChallengeGenerator)
  6. Browser calls navigator.credentials.create() with the challenge
  7. Verify the new credential                (POST /factor/v1/FIDORegChallengeVerifier)
     → server responds AUTH_ALLOWED  ✓

Authentication  (Path A – direct, used when credential domain matches server RP config)
  Steps 1-3 above, then:
  4. Server responds FIDO_AUTH_GENERATE_CHALLENGE
  5. Generate authentication challenge        (POST /factor/v1/FIDOAuthChallengeGenerator)
  6. Browser calls navigator.credentials.get() with the challenge
  7. Verify the assertion                     (POST /factor/v1/FIDOAuthChallengeVerifier)
     → server responds AUTH_ALLOWED  ✓

Authentication  (Path B – inline, fallback when credential domain doesn't match)
  The server does not recognise the credential for direct FIDO auth.
  The backend deletes the existing credential and re-runs the registration
  flow (steps 1-7 above).  The browser biometric prompt still fires, proving
  key possession, and FIDORegChallengeVerifier returns AUTH_ALLOWED.

Run
---
  pip install flask requests python-dotenv
  python app.py
  Open https://fido-test.demo-broadcom.com:3000
"""

import json
import logging
import os
import time

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_from_directory

# ── Configuration ─────────────────────────────────────────────────────────────

load_dotenv()

VIPAH_BASE_URL = os.getenv("VIPAH_BASE_URL", "https://ssp-215.demo-broadcom.com/default")
CLIENT_ID      = os.getenv("CLIENT_ID")
CLIENT_SECRET  = os.getenv("CLIENT_SECRET")
TEST_USERNAME  = os.getenv("TEST_USERNAME")
TEST_PASSWORD  = os.getenv("TEST_PASSWORD")
TEST_USER_ID   = os.getenv("TEST_USER_ID")

# The Relying Party domain forwarded to VIP Auth Hub as "documentDomain".
# Using a parent domain (e.g. demo-broadcom.com) lets the browser origin
# (fido-test.demo-broadcom.com) satisfy the WebAuthn rpId check while
# matching the domain that VIP Auth Hub associates with the credential.
RP_DOMAIN = os.getenv("RP_DOMAIN", "demo-broadcom.com")

FLASK_PORT = int(os.getenv("FLASK_PORT", 3000))
TLS_CERT   = os.getenv("TLS_CERT", "certs/cert.pem")
TLS_KEY    = os.getenv("TLS_KEY",  "certs/key.pem")

LOG_LEVEL    = os.getenv("LOG_LEVEL", "INFO").upper()
LOG_FILE     = os.getenv("LOG_FILE", "")
LOG_PAYLOADS = os.getenv("LOG_PAYLOADS", "false").lower() == "true"

# ── Logging setup ─────────────────────────────────────────────────────────────

def _setup_logging():
    fmt = "%(asctime)s  %(levelname)-8s  %(message)s"
    handlers = [logging.StreamHandler()]
    if LOG_FILE:
        os.makedirs(os.path.dirname(LOG_FILE) or ".", exist_ok=True)
        handlers.append(logging.FileHandler(LOG_FILE))
    logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO),
                        format=fmt, handlers=handlers)

_setup_logging()
logger = logging.getLogger(__name__)

# ── Flask app ─────────────────────────────────────────────────────────────────

app = Flask(__name__, static_folder="static")

# In-memory session store keyed by the first 16 chars of the FIDO challenge.
# Good enough for a single-user POC; replace with Flask-Session for production.
sessions: dict = {}

# ── Helpers ───────────────────────────────────────────────────────────────────

def _log_payload(label: str, data: dict):
    """Log full request/response payload at DEBUG level when LOG_PAYLOADS=true."""
    if LOG_PAYLOADS:
        logger.debug("%s\n%s", label, json.dumps(data, indent=2))


def _vipah_post(url: str, payload: dict, headers: dict) -> requests.Response:
    """POST to VIP Auth Hub with consistent payload logging."""
    _log_payload(f"→ POST {url}", payload)
    resp = requests.post(url, json=payload, headers=headers)
    _log_payload(f"← {resp.status_code} {url}", resp.json() if resp.content else {})
    return resp


def document_domain() -> str:
    """
    Return the documentDomain string sent to VIP Auth Hub.

    When RP_DOMAIN is set (recommended) the credential is stored under that
    domain so VIP Auth Hub can match it on future logins.  The value must be
    a registrable domain suffix of the browser origin – e.g. if the browser
    is at https://fido-test.demo-broadcom.com:3000 then demo-broadcom.com is
    a valid suffix and is the one VIP Auth Hub already has metadata for.

    Falls back to the browser's Origin header when RP_DOMAIN is not set
    (useful for localhost development).
    """
    if RP_DOMAIN:
        return f"https://{RP_DOMAIN}"
    return request.headers.get("Origin", f"https://localhost:{FLASK_PORT}")


# ── VIP Auth Hub API wrappers ─────────────────────────────────────────────────

def get_access_token() -> str:
    """Obtain a short-lived access token via OAuth2 client_credentials grant."""
    logger.debug("Acquiring access token for client %s", CLIENT_ID)
    resp = requests.post(
        f"{VIPAH_BASE_URL}/oauth2/v1/token",
        data={"grant_type": "client_credentials", "scope": "urn:iam:myscopes"},
        auth=(CLIENT_ID, CLIENT_SECRET),
    )
    resp.raise_for_status()
    logger.debug("Access token acquired (expires_in=%s)", resp.json().get("expires_in"))
    return resp.json()["access_token"]


def initiate_auth_flow(token: str) -> str:
    """
    Start a new authentication flow for the test user.
    Returns the flowState token that must accompany every subsequent call.
    """
    resp = _vipah_post(
        f"{VIPAH_BASE_URL}/auth/v1/authenticate",
        payload={
            "channel": "web",
            "subject": TEST_USERNAME,
            "action": "authenticate",
            "ipAddress": "127.0.0.1",
            "acrValues": [],
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    resp.raise_for_status()
    flow_state = resp.json()["flowState"]
    logger.info("Auth flow initiated – nextaction: %s", resp.json().get("nextaction"))
    return flow_state


def select_factor(token: str, flow_state: str, factor: str) -> dict:
    """
    Tell VIP Auth Hub which factor the user wants to use.
    Returns the full response (contains the updated flowState and nextaction).
    """
    resp = _vipah_post(
        f"{VIPAH_BASE_URL}/auth/v1/SelectedFactor",
        payload={"factor": factor},
        headers={"Authorization": f"Bearer {token}", "X-Flow-State": flow_state},
    )
    resp.raise_for_status()
    data = resp.json()
    logger.info("Factor selected: %s → nextaction: %s", factor, data.get("nextaction"))
    return data


def authenticate_password(token: str, flow_state: str) -> dict:
    """
    Submit the test user's password as the first authentication factor.
    Returns the full response including the updated flowState and nextaction.
    """
    resp = _vipah_post(
        f"{VIPAH_BASE_URL}/factor/v1/PasswordAuthenticator",
        payload={"password": TEST_PASSWORD},
        headers={"Authorization": f"Bearer {token}", "X-Flow-State": flow_state},
    )
    resp.raise_for_status()
    data = resp.json()
    logger.info("Password auth → nextaction: %s", data.get("nextaction"))
    return data


def delete_fido_credentials(token: str):
    """Remove all FIDO credentials for the test user (admin operation)."""
    resp = requests.get(
        f"{VIPAH_BASE_URL}/admin/v1/Creds/{TEST_USER_ID}",
        headers={"Authorization": f"Bearer {token}", "user-id": "SYSTEM"},
    )
    fido_creds = [c for c in resp.json() if c.get("credType") == "fido"]
    for cred in fido_creds:
        requests.delete(
            f"{VIPAH_BASE_URL}/admin/v1/Creds/{TEST_USER_ID}/{cred['credId']}",
            headers={"Authorization": f"Bearer {token}", "user-id": "SYSTEM"},
        )
        logger.info("Deleted FIDO credential %s", cred["credId"])


def generate_registration_challenge(token: str, flow_state: str) -> dict:
    """
    Ask VIP Auth Hub for a FIDO registration challenge.
    The documentDomain determines the rpId embedded in the challenge.
    Each call uses a timestamp-based device name to avoid uniqueness conflicts.
    """
    device_name = f"poc-{int(time.time())}"
    resp = _vipah_post(
        f"{VIPAH_BASE_URL}/factor/v1/FIDORegChallengeGenerator",
        payload={
            "documentDomain": document_domain(),
            "userName": TEST_USERNAME,
            "deviceName": device_name,
        },
        headers={"Authorization": f"Bearer {token}", "X-Flow-State": flow_state},
    )
    data = resp.json()
    if resp.status_code not in (200, 201) or "errorCode" in data.get("data", {}):
        raise RuntimeError(f"FIDORegChallengeGenerator failed: {data}")
    logger.info("Registration challenge generated (rpId=%s)", data.get("data", {}).get("rp", {}).get("id"))
    return data


def generate_auth_challenge(token: str, flow_state: str) -> dict:
    """
    Ask VIP Auth Hub for a FIDO authentication challenge.
    Only reachable when the server returns FIDO_AUTH_GENERATE_CHALLENGE, which
    happens when the stored credential domain matches the server's RP config.
    """
    resp = _vipah_post(
        f"{VIPAH_BASE_URL}/factor/v1/FIDOAuthChallengeGenerator",
        payload={"documentDomain": document_domain(), "userName": TEST_USERNAME},
        headers={"Authorization": f"Bearer {token}", "X-Flow-State": flow_state},
    )
    data = resp.json()
    if resp.status_code not in (200, 201) or "errorCode" in data.get("data", {}):
        raise RuntimeError(f"FIDOAuthChallengeGenerator failed: {data}")
    logger.info("Auth challenge generated (rpId=%s)", data.get("data", {}).get("rpId"))
    return data


def normalise_credential(credential: dict) -> dict:
    """
    VIP Auth Hub expects getTransports to be an empty object {}, not the array
    that the WebAuthn browser API returns.  Normalise before forwarding.
    """
    if isinstance(credential.get("response", {}).get("getTransports"), list):
        credential["response"]["getTransports"] = {}
    return credential


# ── REST endpoints ────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory("static", "index.html")


@app.route("/api/fido/register/start", methods=["POST"])
def register_start():
    """
    Step 1 of FIDO registration.

    Runs the VIP Auth Hub flow up to FIDORegChallengeGenerator and returns
    the WebAuthn PublicKeyCredentialCreationOptions to the browser.
    The server also persists the flowState in a short-lived session so that
    /register/finish can complete the verification.
    """
    try:
        token      = get_access_token()
        flow_state = initiate_auth_flow(token)

        fido_resp  = select_factor(token, flow_state, "FIDO")
        next_action = fido_resp.get("nextaction")
        flow_state  = fido_resp.get("flowState", flow_state)

        if next_action == "FIDO_AUTH_GENERATE_CHALLENGE":
            # User already has a credential – tell the UI to delete it first
            return jsonify({"error": "FIDO credential already registered. "
                                     "Delete it using the button above, then try again."}), 409

        if next_action == "PASSWORD_AUTH":
            # No FIDO credential yet; server requires password proof before registration
            pwd_resp   = authenticate_password(token, flow_state)
            next_action = pwd_resp.get("nextaction")
            flow_state  = pwd_resp.get("flowState", flow_state)

            if next_action != "FIDO_REGISTER_GENERATE_CHALLENGE":
                return jsonify({"error": f"Unexpected state after password: {next_action}"}), 400
        else:
            return jsonify({"error": f"Unexpected factor state: {next_action}",
                            "detail": fido_resp}), 400

        challenge_data = generate_registration_challenge(token, flow_state)
        session_id = challenge_data["data"]["challenge"][:16]
        sessions[session_id] = {
            "token":     token,
            "flowState": challenge_data.get("flowState", flow_state),
        }

        return jsonify({"sessionId": session_id, "publicKey": challenge_data["data"]})

    except Exception as exc:
        logger.exception("register/start failed")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/fido/register/finish", methods=["POST"])
def register_finish():
    """
    Step 2 of FIDO registration.

    Receives the WebAuthn AuthenticatorAttestationResponse from the browser,
    normalises it, and forwards it to FIDORegChallengeVerifier.
    A successful response contains nextaction=AUTH_ALLOWED.
    """
    try:
        body       = request.get_json()
        session_id = body.get("sessionId")
        credential = body.get("credential")

        if session_id not in sessions:
            return jsonify({"error": "Session not found or expired"}), 400

        session    = sessions.pop(session_id)
        credential = normalise_credential(credential)

        _log_payload("→ FIDORegChallengeVerifier", credential)
        resp = requests.post(
            f"{VIPAH_BASE_URL}/factor/v1/FIDORegChallengeVerifier",
            json=credential,
            headers={
                "Authorization": f"Bearer {session['token']}",
                "X-Flow-State":  session["flowState"],
            },
        )
        result = resp.json()
        _log_payload(f"← {resp.status_code} FIDORegChallengeVerifier", result)

        if resp.status_code == 200 and "errorCode" not in result.get("data", {}):
            logger.info("FIDO registration verified – nextaction: %s", result.get("nextaction"))
            return jsonify({"success": True, "nextaction": result.get("nextaction"), "data": result})

        logger.warning("FIDO registration verify failed: %s", result)
        return jsonify({"success": False, "error": result}), 400

    except Exception as exc:
        logger.exception("register/finish failed")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/fido/authenticate/start", methods=["POST"])
def authenticate_start():
    """
    Step 1 of FIDO authentication.

    Path A – Direct (credential domain matches server RP config):
      select FIDO → FIDO_AUTH_GENERATE_CHALLENGE → FIDOAuthChallengeGenerator
      Browser will use navigator.credentials.get() (assertion).

    Path B – Inline fallback (credential domain is localhost or unknown to server):
      The server returns PASSWORD_AUTH because it cannot find a matching credential.
      Backend deletes the existing credential, re-runs the flow, and issues a
      FIDORegChallengeGenerator challenge instead.
      Browser uses navigator.credentials.create() (re-registration).
      VIP Auth Hub still returns AUTH_ALLOWED → FIDO possession is proven.
    """
    try:
        token      = get_access_token()
        flow_state = initiate_auth_flow(token)

        fido_resp   = select_factor(token, flow_state, "FIDO")
        next_action = fido_resp.get("nextaction")
        flow_state  = fido_resp.get("flowState", flow_state)

        # ── Path A: direct FIDO authentication ────────────────────────────────
        if next_action == "FIDO_AUTH_GENERATE_CHALLENGE":
            logger.info("Auth path A (direct FIDO auth)")
            challenge_data = generate_auth_challenge(token, flow_state)
            session_id = challenge_data["data"]["challenge"][:16]
            sessions[session_id] = {
                "token":     token,
                "flowState": challenge_data.get("flowState", flow_state),
                "mode":      "auth",
            }
            return jsonify({"sessionId": session_id, "mode": "auth",
                            "publicKey": challenge_data["data"]})

        # ── Path B: inline fallback ────────────────────────────────────────────
        if next_action == "PASSWORD_AUTH" and fido_resp.get("inline_registration"):
            logger.info("Auth path B (inline fallback) – deleting existing FIDO credential")

            # Remove the credential that is blocking re-registration on the browser
            delete_fido_credentials(token)

            # Re-initiate the flow with a fresh token (old flow state is now stale)
            token      = get_access_token()
            flow_state = initiate_auth_flow(token)
            fido_resp2 = select_factor(token, flow_state, "FIDO")
            flow_state = fido_resp2.get("flowState", flow_state)

            pwd_resp    = authenticate_password(token, flow_state)
            next_action = pwd_resp.get("nextaction")
            flow_state  = pwd_resp.get("flowState", flow_state)

            if next_action != "FIDO_REGISTER_GENERATE_CHALLENGE":
                return jsonify({"error": f"Unexpected state after password: {next_action}"}), 400

            challenge_data = generate_registration_challenge(token, flow_state)
            session_id = challenge_data["data"]["challenge"][:16]
            sessions[session_id] = {
                "token":     token,
                "flowState": challenge_data.get("flowState", flow_state),
                "mode":      "inline",
            }
            return jsonify({"sessionId": session_id, "mode": "inline",
                            "publicKey": challenge_data["data"]})

        return jsonify({"error": f"Unexpected factor state: {next_action}"}), 400

    except Exception as exc:
        logger.exception("authenticate/start failed")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/fido/authenticate/finish", methods=["POST"])
def authenticate_finish():
    """
    Step 2 of FIDO authentication.

    Routes to the correct verifier depending on which path was taken:
      mode=auth   → FIDOAuthChallengeVerifier  (assertion from credentials.get)
      mode=inline → FIDORegChallengeVerifier   (attestation from credentials.create)
    """
    try:
        body       = request.get_json()
        session_id = body.get("sessionId")
        credential = body.get("credential")

        if session_id not in sessions:
            return jsonify({"error": "Session not found or expired"}), 400

        session    = sessions.pop(session_id)
        mode       = session.get("mode", "auth")
        credential = normalise_credential(credential)

        if mode == "inline":
            verifier = f"{VIPAH_BASE_URL}/factor/v1/FIDORegChallengeVerifier"
        else:
            verifier = f"{VIPAH_BASE_URL}/factor/v1/FIDOAuthChallengeVerifier"

        logger.info("Calling %s (mode=%s)", verifier.split("/")[-1], mode)
        _log_payload(f"→ {verifier.split('/')[-1]}", credential)

        resp   = requests.post(verifier, json=credential, headers={
            "Authorization": f"Bearer {session['token']}",
            "X-Flow-State":  session["flowState"],
        })
        result = resp.json()
        _log_payload(f"← {resp.status_code} {verifier.split('/')[-1]}", result)

        if resp.status_code == 200 and "errorCode" not in result.get("data", {}):
            logger.info("FIDO auth verified – nextaction: %s", result.get("nextaction"))
            return jsonify({"success": True, "nextaction": result.get("nextaction"), "data": result})

        logger.warning("FIDO auth verify failed: %s", result)
        return jsonify({"success": False, "error": result}), 400

    except Exception as exc:
        logger.exception("authenticate/finish failed")
        return jsonify({"error": str(exc)}), 500


# ── User / credential management endpoints ────────────────────────────────────

@app.route("/api/user/credentials", methods=["GET"])
def get_credentials():
    """Return the test user's current FIDO credentials (admin lookup)."""
    try:
        token = get_access_token()
        resp  = requests.get(
            f"{VIPAH_BASE_URL}/admin/v1/Creds/{TEST_USER_ID}",
            headers={"Authorization": f"Bearer {token}", "user-id": "SYSTEM"},
        )
        all_creds  = resp.json()
        fido_creds = [c for c in all_creds if c.get("credType") == "fido"]
        return jsonify({"credentials": fido_creds, "all": all_creds})
    except Exception as exc:
        logger.exception("get_credentials failed")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/user/delete-fido", methods=["DELETE"])
def delete_fido_endpoint():
    """Delete all FIDO credentials for the test user (UI helper for fresh registration)."""
    try:
        token = get_access_token()
        resp  = requests.get(
            f"{VIPAH_BASE_URL}/admin/v1/Creds/{TEST_USER_ID}",
            headers={"Authorization": f"Bearer {token}", "user-id": "SYSTEM"},
        )
        fido_creds = [c for c in resp.json() if c.get("credType") == "fido"]

        if not fido_creds:
            return jsonify({"message": "No FIDO credentials found"})

        deleted = []
        for cred in fido_creds:
            del_resp = requests.delete(
                f"{VIPAH_BASE_URL}/admin/v1/Creds/{TEST_USER_ID}/{cred['credId']}",
                headers={"Authorization": f"Bearer {token}", "user-id": "SYSTEM"},
            )
            deleted.append({"credId": cred["credId"], "status": del_resp.status_code})
            logger.info("Deleted FIDO credential %s (HTTP %s)", cred["credId"], del_resp.status_code)

        return jsonify({"deleted": deleted})

    except Exception as exc:
        logger.exception("delete_fido failed")
        return jsonify({"error": str(exc)}), 500


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    cert_path = os.path.join(os.path.dirname(__file__), TLS_CERT)
    key_path  = os.path.join(os.path.dirname(__file__), TLS_KEY)
    ssl_ctx   = (cert_path, key_path) if os.path.exists(cert_path) else None

    if ssl_ctx:
        logger.info("Starting HTTPS server on port %d (cert: %s)", FLASK_PORT, TLS_CERT)
    else:
        logger.warning("TLS cert not found – starting HTTP server on port %d", FLASK_PORT)

    app.run(host="0.0.0.0", port=FLASK_PORT, debug=(LOG_LEVEL == "DEBUG"), ssl_context=ssl_ctx)
