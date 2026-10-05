import ssl
import urllib.request

response = urllib.request.urlopen('https://127.0.0.1:8443/healthz', context=ssl._create_unverified_context(), timeout=3)
raise SystemExit(0 if response.status == 200 else 1)
