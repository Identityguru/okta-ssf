import requests
import json

domain = "idhub.oktapreview.com"
token = "003W5OQ1-sA72vDhkutCtwyAkRQfkuRPxZwbpEGChB"
url = f"https://{domain}/api/v1/logs?filter=eventType eq \"security.events.provider.receive_event\" or eventType eq \"app.api.errors\" or eventType eq \"core.server.api.error\""
headers = {"Authorization": f"SSWS {token}"}
resp = requests.get(url, headers=headers)
logs = resp.json()

for log in logs[:3]:
    print(json.dumps(log, indent=2))
