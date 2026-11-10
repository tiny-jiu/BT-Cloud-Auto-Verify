#!/usr/bin/env python3
"""Recognize and handle several BT Cloud WAF challenge flows."""

import hashlib
import re
import sys

import requests


SLIDER_TEXT = "".join(map(chr, (0x6ED1, 0x52A8, 0x9A8C, 0x8BC1)))
HUMAN_DETECTION_TEXT = "".join(map(chr, (0x4EBA, 0x673A, 0x8BC6, 0x522B)))

if len(sys.argv) != 2:
    print("Usage: python cloud_verify.py http://target.example/")
    sys.exit(1)

URL = sys.argv[1]
BASE = URL.rstrip("/").rsplit("/", 1)[0]


def compute(value, offset=1):
    """Encode characters as shifted ASCII values and hash the result."""
    return hashlib.md5(
        "".join(str(ord(char) + offset) for char in value).encode()
    ).hexdigest()


session = requests.Session()
session.headers["User-Agent"] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
)

first = session.get(URL, timeout=15, allow_redirects=False)
print(f"Initial response: HTTP {first.status_code}")

if first.status_code == 403 and len(first.text) < 200:
    print("Detected a cookie-based invisible check; retrying the request.")
    first = session.get(URL, timeout=15)
    print(f"Retry response: HTTP {first.status_code}")
    if len(first.text) < 500 and session.cookies:
        print("The page accepted the retry.")
        print(first.text)
        sys.exit(0)

has_human = "renji_" in first.text
has_slider = "huadong_" in first.text
has_redirect = "btwaf=" in first.text
is_timed_check = has_human and "bt-info" in first.text and HUMAN_DETECTION_TEXT in first.text

if has_redirect:
    print("Detected a redirect challenge.")
    match = re.search(r'btwaf=(\d+)"', first.text)
    if match:
        session.get(f"{BASE}/?btwaf={match.group(1)}", timeout=15)
elif is_timed_check:
    print("Detected a timed human check.")
elif has_slider:
    print("Detected a slider challenge.")
elif has_human:
    print("Detected an invisible human check.")
else:
    print("No supported challenge was detected.")
    sys.exit(0)

mode = "renji" if has_human else "huadong"
script = re.search(rf'src="(/{mode}_[^"]+\.js\?[^"]+)"', first.text)
if not script:
    print("The challenge script could not be found.")
    sys.exit(1)

script_response = session.get(f"{BASE}{script.group(1)}", timeout=15)
key_match = re.search(r'(?:bt_)?key\s*=\s*"([^"]+)"', script_response.text)
value_match = re.search(r'(?:bt_)?value\s*=\s*"([^"]+)"', script_response.text)
if not key_match or not value_match:
    print("The challenge values could not be extracted.")
    sys.exit(1)

key = key_match.group(1)
value = value_match.group(1)
offset = 0 if mode == "renji" else 1
computed = compute(value, offset)
verification_type = (
    "96c4e20a0e951f471d32dae103e83881"
    if mode == "renji"
    else "ad82060c2e67cc7e2cc47552a4fc1242"
)
endpoint = "yanzheng_ip.php" if mode == "renji" else "yanzheng_huadong.php"
verification_url = (
    f"{BASE}/a20be899_96a6_40b2_88ba_32f1f75f1552_{endpoint}"
    f"?type={verification_type}&key={key}&value={computed}"
)
verification = session.get(verification_url, timeout=15)
print(f"Verification response: {verification.text.strip()}")

try:
    final = session.get(URL, timeout=30)
except requests.RequestException:
    final = None

passed = (
    final is not None
    and "huadong" not in final.text
    and SLIDER_TEXT not in final.text
    and "btwaf" not in final.text
)
if final is not None:
    print(f"Final response: HTTP {final.status_code}")
print("Challenge passed." if passed else "The result could not be confirmed.")
