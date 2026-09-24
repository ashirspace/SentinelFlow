import requests
import urllib3
import re

urllib3.disable_warnings()

url = "https://siem.abpplus.com/login"
r = requests.get(url, verify=False)
print("Login page status:", r.status_code)

scripts = re.findall(r'src="(/static/js/[^"]+)"', r.text)
for s in scripts:
    asset_url = f"https://siem.abpplus.com{s}"
    res = requests.get(asset_url, verify=False)
    print(f"Asset: {s} -> HTTP {res.status_code}, {len(res.content)} bytes")

styles = re.findall(r'href="(/static/css/[^"]+)"', r.text)
for css in styles:
    asset_url = f"https://siem.abpplus.com{css}"
    res = requests.get(asset_url, verify=False)
    print(f"CSS: {css} -> HTTP {res.status_code}, {len(res.content)} bytes")
