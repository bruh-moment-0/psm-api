import requests

_URLBASE = "https://raw.githubusercontent.com/bruh-moment-0/psm-url/refs/heads/main/url.txt"
resp = requests.get(_URLBASE)
APIURL = resp.text.strip()
