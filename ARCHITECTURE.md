# Okta SSF Event Transmitter — Architecture

## Overview

This system implements an **inbound Security Event Transmitter** for Okta using the [Shared Signals Framework (SSF)](https://openid.net/wg/sharedsignals/) specification. It generates cryptographically signed Security Event Tokens (SETs) and pushes them to Okta's Security Events API, enabling external systems to notify Okta of user risk changes.

---

## Component Overview

| Component | File | Role |
|---|---|---|
| Key Setup | `generate_jwks.py` | Derives public JWKS from RSA keypair for Okta to verify signatures |
| Live JWKS Host | Netlify Dev + Live Tunnel | Serves `public/jwks.json` at a public URL during local development |
| Event Transmitter | `transmit-okta-event.py` | Builds, signs, and POSTs the SET JWT to Okta |
| Log Inspector | `get_logs.py` | Queries Okta System Log to verify event receipt |
| Key Material | `rsa-keypair.json` | RSA-2048 private/public keypair used for RS256 signing |
| Public Key | `public/jwks.json` | JWK Set (public key only) served to Okta for signature verification |

---

## Setup Sequence

One-time setup to establish trust between this transmitter and Okta.

```mermaid
sequenceDiagram
    participant Dev as Developer
    participant Script as generate_jwks.py
    participant Netlify as Netlify Live Tunnel
    participant OktaAdmin as Okta Admin Console

    Dev->>Script: python generate_jwks.py
    Script->>Script: Load rsa-keypair.json
    Script->>Script: Extract RSA public key (n, e)
    Script-->>Dev: Writes public/jwks.json

    Dev->>Netlify: npx netlify-cli dev --dir=public --live
    Netlify-->>Dev: Live URL: https://fb0457e3--okta-ssf-link.netlify.live

    Dev->>OktaAdmin: Create Security Events Provider
    Note over OktaAdmin: issuer = https://fb0457e3--okta-ssf-link.netlify.live<br/>jwks_url = https://fb0457e3--okta-ssf-link.netlify.live/jwks.json
    OktaAdmin-->>Dev: Provider ID (e.g. sse2hy80y2zY45Wlb0h8)
```

---

## Event Transmission Sequence

Runtime flow for transmitting a `user-risk-change` event to Okta.

```mermaid
sequenceDiagram
    participant Script as transmit-okta-event.py
    participant Keypair as rsa-keypair.json
    participant Netlify as Netlify Live Tunnel<br/>(JWKS Host)
    participant Okta as Okta Security Events API<br/>/security/api/v1/security-events

    Script->>Keypair: Load RSA private key + kid
    Keypair-->>Script: privateKey (PEM), kid: ssf-rsa-1756575638808

    Script->>Script: Build JWT payload
    Note over Script: iss: https://fb0457e3--okta-ssf-link.netlify.live<br/>aud: https://idhub.oktapreview.com<br/>sub_id: {format: iss_sub, sub: <okta_uid>}<br/>events: {user-risk-change: {...}}<br/>jti, iat

    Script->>Script: Sign JWT (RS256, kid header, typ: secevent+jwt)
    Script->>Okta: POST /security/api/v1/security-events<br/>Content-Type: application/secevent+jwt<br/>Body: <signed SET JWT>

    Okta->>Netlify: GET /jwks.json
    Netlify-->>Okta: RSA public key (JWK Set)

    Okta->>Okta: Verify JWT signature<br/>Validate iss, aud, sub_id
    Okta-->>Script: 202 Accepted

    Note over Okta: Emits system log event:<br/>security.events.provider.receive_event
```

---

## Verification Sequence

After transmission, confirm Okta received and processed the event.

```mermaid
sequenceDiagram
    participant Dev as Developer
    participant Script as get_logs.py
    participant OktaLogs as Okta System Log API<br/>/api/v1/logs

    Dev->>Script: python get_logs.py
    Script->>OktaLogs: GET /api/v1/logs?filter=eventType eq "security.events.provider.receive_event"<br/>Authorization: SSWS <token>
    OktaLogs-->>Script: Log entries (JSON)
    Script-->>Dev: Print first 3 matching events
```

---

## JWT Structure

The signed SET (Security Event Token) sent to Okta:

**Header**
```json
{
  "alg": "RS256",
  "kid": "ssf-rsa-1756575638808",
  "typ": "secevent+jwt"
}
```

**Payload**
```json
{
  "iss": "https://fb0457e3--okta-ssf-link.netlify.live",
  "aud": "https://idhub.oktapreview.com",
  "iat": 1776131674,
  "jti": "<uuid>",
  "sub_id": {
    "format": "iss_sub",
    "iss": "https://fb0457e3--okta-ssf-link.netlify.live",
    "sub": "<okta_user_uid>"
  },
  "events": {
    "https://schemas.okta.com/secevent/okta/event-type/user-risk-change": {
      "current_level": "low",
      "previous_level": "medium",
      "event_timestamp": 1776131674,
      "initiating_entity": "admin",
      "reason_admin": { "en": "Elevated risk detected via SSF transmitter" },
      "reason_user": { "en": "Your account risk level was updated" },
      "subject": {
        "format": "iss_sub",
        "iss": "https://idhub.oktapreview.com",
        "sub": "<okta_user_uid>"
      }
    }
  }
}
```

---

## Key Constraint: `iss` Must Match Provider Registration

Okta looks up the Security Events Provider by the `iss` claim in the incoming JWT. If `iss` does not exactly match the `issuer` field registered in the provider config, Okta returns `400 Bad Request` with an empty body.

The registered provider config can be inspected via:
```
GET https://{OKTA_DOMAIN}/api/v1/security-events-providers/{PROVIDER_ID}
Authorization: SSWS <token>
```
