import requests
import json

domain = "idhub.oktapreview.com"
token = "003W5OQ1-sA72vDhkutCtwyAkRQfkuRPxZwbpEGChB"
provider_id = "sse2hy80y2zY45Wlb0h8"

url = f"https://{domain}/api/v1/security-events-providers/{provider_id}"
headers = {
    "Authorization": f"SSWS {token}",
    "Content-Type": "application/json"
}

payload = {
    "name": "Test",
    "settings": {
        "issuer": "https://fb0457e3--okta-ssf-link.netlify.live",
        "jwks_url": "https://fb0457e3--okta-ssf-link.netlify.live/jwks.json"
    }
}

resp = requests.put(url, headers=headers, json=payload)
print(f"Update Provider Status: {resp.status_code}")
print(resp.text)
