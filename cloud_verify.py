#!/usr/bin/env python3
"""识别并处理宝塔云 WAF 的几种行为验证流程。"""

import hashlib
import re
import sys

import requests


SLIDER_TEXT = "".join(map(chr, (0x6ED1, 0x52A8, 0x9A8C, 0x8BC1)))
HUMAN_DETECTION_TEXT = "".join(map(chr, (0x4EBA, 0x673A, 0x8BC6, 0x522B)))

if len(sys.argv) != 2:
    print("用法：python cloud_verify.py http://target.example/")
    sys.exit(1)

URL = sys.argv[1]
BASE = URL.rstrip("/").rsplit("/", 1)[0]


def compute(value, offset=1):
    """将字符转为带偏移量的 ASCII 编码，拼接后计算 MD5。"""
    return hashlib.md5(
        "".join(str(ord(char) + offset) for char in value).encode()
    ).hexdigest()


session = requests.Session()
session.headers["User-Agent"] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
)

first = session.get(URL, timeout=15, allow_redirects=False)
print(f"首次响应：HTTP {first.status_code}")

if first.status_code == 403 and len(first.text) < 200:
    print("检测到基于 Cookie 的隐式验证，正在重试请求。")
    first = session.get(URL, timeout=15)
    print(f"重试响应：HTTP {first.status_code}")
    if len(first.text) < 500 and session.cookies:
        print("页面已接受重试请求。")
        print(first.text)
        sys.exit(0)

has_human = "renji_" in first.text
has_slider = "huadong_" in first.text
has_redirect = "btwaf=" in first.text
is_timed_check = has_human and "bt-info" in first.text and HUMAN_DETECTION_TEXT in first.text

if has_redirect:
    print("检测到跳转验证。")
    match = re.search(r'btwaf=(\d+)"', first.text)
    if match:
        session.get(f"{BASE}/?btwaf={match.group(1)}", timeout=15)
elif is_timed_check:
    print("检测到定时人机检测。")
elif has_slider:
    print("检测到滑块验证。")
elif has_human:
    print("检测到隐式人机验证。")
else:
    print("未检测到支持的验证类型。")
    sys.exit(0)

mode = "renji" if has_human else "huadong"
script = re.search(rf'src="(/{mode}_[^"]+\.js\?[^"]+)"', first.text)
if not script:
    print("找不到验证脚本。")
    sys.exit(1)

script_response = session.get(f"{BASE}{script.group(1)}", timeout=15)
key_match = re.search(r'(?:bt_)?key\s*=\s*"([^"]+)"', script_response.text)
value_match = re.search(r'(?:bt_)?value\s*=\s*"([^"]+)"', script_response.text)
if not key_match or not value_match:
    print("无法提取验证参数。")
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
print(f"验证接口响应：{verification.text.strip()}")

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
    print(f"最终响应：HTTP {final.status_code}")
print("验证通过。" if passed else "无法确认验证结果。")
