# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an **Okta Shared Signals Framework (SSF) Event Transmitter** — a Python utility that generates RSA-signed JWT security events and transmits them to Okta's Security Events API (`/security/api/v1/security-events`). It acts as an external transmitter in the SSF spec, notifying Okta of user risk changes.

## Setup and Running

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Transmit a security event to Okta
python transmit-okta-event.py

# Regenerate public/jwks.json from rsa-keypair.json
python generate_jwks.py

# Fetch Okta system logs to verify event receipt
python get_logs.py
```

There are no build steps, test suite, or linter configured.

## Architecture

Three standalone scripts with no shared module layer:

- **`transmit-okta-event.py`** — Main script. Loads `rsa-keypair.json`, constructs an SSF `user-risk-change` JWT payload (with `iss`, `sub_id` using `iss_sub` format, `events`, `aud`, `jti`, `iat`), signs it RS256, and POSTs it to Okta. Expects a `202 Accepted` response.

- **`generate_jwks.py`** — Reads `rsa-keypair.json`, extracts the RSA public key components (`n`, `e`), and writes `public/jwks.json`. This JWKS endpoint is what Okta uses to verify JWT signatures from this transmitter.

- **`get_logs.py`** — Queries the Okta System Log API for events of types `security.events.provider.receive_event`, `app.api.errors`, and `core.server.api.error` to confirm Okta received and processed the transmitted event.

## Configuration

All runtime configuration is controlled via environment variables (with hardcoded fallback defaults in the scripts):

| Variable | Purpose |
|---|---|
| `OKTA_DOMAIN` | Okta tenant domain (e.g. `idhub.oktapreview.com`) |
| `OKTA_API_TOKEN` | Okta API token used by `get_logs.py` for system log access |
| `PROVIDER_ID` | Security Events Provider ID registered in Okta |
| `ISS` | Issuer identifier URI for this transmitter |
| `SUBJECT_OKTA_UID` | Okta UID of the user the event targets |
| `DEBUG` | Set to `true` to print the JWT payload before signing |

`rsa-keypair.json` holds the RSA private key, public key, `kid`, and algorithm. The `kid` must match what is registered in the JWKS endpoint Okta has configured for this provider.

## Key Dependencies

- `PyJWT` — JWT creation and RS256 signing
- `cryptography` — RSA private key loading (PEM format)
- `requests` — HTTP POST to Okta API and log fetching

## Netlify / Tunneling

A `.netlify/state.json` exists with a live tunnel slug (`fb0457e3`), indicating the JWKS endpoint (`public/jwks.json`) can be served locally via `netlify dev` and exposed publicly so Okta can fetch the public key for signature verification during development.
