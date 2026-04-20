import jwt
import requests
import json
import time
import uuid
import os
from typing import Tuple

RSA_KEYPAIR_PATH = "./rsa-keypair.json"

# ---------------------------------------------------------------------------
# Environment configuration
# ---------------------------------------------------------------------------
# Required
OKTA_DOMAIN = os.getenv("OKTA_DOMAIN", "idhub.oktapreview.com")
OKTA_API_TOKEN = os.getenv("OKTA_API_TOKEN", "003W5OQ1-sA72vDhkutCtwyAkRQfkuRPxZwbpEGChB")          # SSWS token for provider config lookup
PROVIDER_ID = os.getenv("PROVIDER_ID", "sse2hy80y2zY45Wlb0h8")                # Security Events Provider ID from Okta

# Transmitter identity
ISS = os.getenv("ISS", "https://fb0457e3--okta-ssf-link.netlify.live")

# Subject — must be a real Okta user UID (e.g. 00ur6yt2ufUA59XMy0h7)
# Using iss_sub format: iss = your transmitter ISS, sub = Okta user UID
SUBJECT_OKTA_UID = os.getenv("SUBJECT_OKTA_UID", "00ur6yt2ufUA59XMy0h7")

DEBUG = os.getenv("DEBUG", "false").lower() == "true"


# ---------------------------------------------------------------------------
# Key loading
# ---------------------------------------------------------------------------

def load_keypair() -> Tuple[str, str]:
    """Load RSA private key and key ID from JSON file."""
    try:
        with open(RSA_KEYPAIR_PATH, "r") as f:
            key_data = json.load(f)
        return key_data["privateKey"], key_data["kid"]
    except (FileNotFoundError, KeyError, json.JSONDecodeError) as e:
        raise RuntimeError(f"Failed to load RSA keypair: {e}")


# ---------------------------------------------------------------------------
# Stream configuration lookup
# ---------------------------------------------------------------------------

def get_push_endpoint() -> str:
    """
    Fetch the Security Events Provider config from Okta.
    Okta's push endpoint for receiving events is typically the standard security-events endpoint.
    """
    return f"https://{OKTA_DOMAIN}/security/api/v1/security-events"


# ---------------------------------------------------------------------------
# Event generation
# ---------------------------------------------------------------------------

def generate_ssf_event(private_key: str, kid: str, push_endpoint: str) -> str:
    """
    Generate a signed SSF event JWT.

    Key correctness points:
    - aud must equal the push_endpoint URL exactly (not just the domain).
    - sub_id must reference a real Okta principal; otherwise Okta accepts
      the JWT but silently discards the event with no system log entry.
    - The nested subject inside the event payload should match sub_id.
    """
    iat = int(time.time())
    jti = str(uuid.uuid4())

    # aud MUST typically be the Okta domain
    aud = f"https://{OKTA_DOMAIN}"

    # Subject: iss_sub format — iss must be the Okta tenant (not the transmitter)
    # because the subject is an Okta-managed user identified by their Okta UID.
    sub_id = {
        "format": "iss_sub",
        "iss": f"https://{OKTA_DOMAIN}",
        "sub": SUBJECT_OKTA_UID,
    }

    # Consistent subject reference inside the event payload
    event_subject = {
        "format": "iss_sub",
        "iss": f"https://{OKTA_DOMAIN}",
        "sub": SUBJECT_OKTA_UID,
    }

    events = {
        "https://schemas.okta.com/secevent/okta/event-type/user-risk-change": {
            "current_level": "low",
            "event_timestamp": iat,
            "initiating_entity": "admin",
            "previous_level": "medium",
            "reason_admin": {"en": "Elevated risk detected via SSF transmitter"},
            "reason_user": {"en": "Your account risk level was updated"},
            "subject": event_subject,
        }
    }

    payload = {
        "iss": ISS,
        "jti": jti,
        "iat": iat,
        "aud": aud,
        "sub_id": sub_id,
        "events": events,
    }

    if DEBUG:
        print(f"[DEBUG] JWT payload:\n{json.dumps(payload, indent=2)}\n")

    try:
        token = jwt.encode(
            payload,
            private_key,
            algorithm="RS256",
            headers={"kid": kid, "typ": "secevent+jwt"},
        )
        return token
    except Exception as e:
        raise RuntimeError(f"Failed to generate JWT: {e}")


# ---------------------------------------------------------------------------
# Transmission
# ---------------------------------------------------------------------------

def transmit_to_okta(token: str, push_endpoint: str) -> requests.Response:
    """Transmit the signed SET to Okta's stream-specific push endpoint."""
    headers = {"Content-Type": "application/secevent+jwt"}
    print(f"[INFO] POSTing SET to: {push_endpoint}")
    try:
        response = requests.post(push_endpoint, headers=headers, data=token, timeout=10)
        response.raise_for_status()
    except requests.RequestException as e:
        body = e.response.content if hasattr(e, 'response') and e.response else b""
        raise RuntimeError(f"Failed to transmit event to Okta: {e}\nResponse body: {body}")

    print(f"[INFO] Status Code : {response.status_code}")
    print(f"[INFO] Response    : {response.text or '(empty)'}")
    return response


# ---------------------------------------------------------------------------
# Post-transmission verification hint
# ---------------------------------------------------------------------------

def print_verification_hint() -> None:
    """
    After transmission, tell the operator exactly what to check in Okta.
    The system log event is security.events.provider.receive_event.
    If absent after a 202, the likely causes are:
      1. sub_id did not resolve to a known Okta principal.
      2. Transmitted event type not in the stream's events_requested list.
      3. Tenant entitlement not enabled for SSF inbound event logging.
    """
    print(
        "\n[INFO] Verification steps:\n"
        f"  1. Okta System Log → filter event type: security.events.provider.receive_event\n"
        f"  2. If no entry appears despite 202, check:\n"
        f"     a) SUBJECT_OKTA_UID ({SUBJECT_OKTA_UID}) resolves in your Okta tenant\n"
        f"        GET https://{OKTA_DOMAIN}/api/v1/users/{SUBJECT_OKTA_UID}\n"
        f"     b) Event type 'user-risk-change' is in the stream's events_requested list\n"
        f"        GET https://{OKTA_DOMAIN}/api/v1/security-events-providers/{PROVIDER_ID}\n"
        f"     c) Raise an Okta support ticket to confirm tenant entitlement for\n"
        f"        inbound SSF event logging (may be feature-flagged)\n"
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """Main entry point."""
    # Validate required env vars
    missing = []
    if not OKTA_API_TOKEN:
        missing.append("OKTA_API_TOKEN")
    if not PROVIDER_ID:
        missing.append("PROVIDER_ID")
    if missing:
        print(
            f"[WARN] Missing env vars: {', '.join(missing)}\n"
            "       Stream config lookup will be skipped; using fallback endpoint.\n"
            "       Set these to ensure the correct push endpoint is resolved.\n"
        )

    try:
        private_key, kid = load_keypair()
        push_endpoint = get_push_endpoint()
        token = generate_ssf_event(private_key, kid, push_endpoint)
        print(f"[INFO] Generated JWT (prefix): {token[:60]}...")
        response = transmit_to_okta(token, push_endpoint)

        if response.status_code == 202:
            print("\n[OK] Event transmitted successfully (202 Accepted).")
            print_verification_hint()
        else:
            print(f"\n[FAIL] Unexpected status: {response.status_code}")

    except Exception as e:
        print(f"\n[ERROR] {e}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()