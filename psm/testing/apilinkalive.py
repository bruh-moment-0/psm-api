import requests
from apilinkget import APIURL

def apiTunnelAlive():
    try:
        test = requests.get(APIURL, timeout=5)
        if test.status_code == 200:
            return True
        else:
            return False
    except requests.exceptions.RequestException as e:
        return False

print(f"{APIURL}: {apiTunnelAlive()}")