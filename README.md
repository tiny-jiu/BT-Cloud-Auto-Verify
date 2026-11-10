# BT Cloud Auto Verify

Protocol notes and Python code for recognizing several BT Cloud WAF challenge flows.

## Supported modes

| Mode | Page clue | Handling |
| --- | --- | --- |
| Five-second shield | `btwaf=` | Retry with the returned cookie |
| Invisible check | `renji_` and `bt-info` | Extract the embedded values and calculate the response |
| Slider | `huadong_` | Use the slider offset and the matching verification endpoint |

## Behind the flow

The five-second shield sets a cookie and redirects the browser. Retrying with that cookie is enough; no calculation is needed.

The invisible check loads a `renji_*.js` file containing a key and value. The script calculates the ASCII-based MD5 value and submits it to `yanzheng_ip.php`.

The slider flow is similar, but each byte is shifted by one and the result is sent to `yanzheng_huadong.php`.

## Usage

```bash
pip install requests
python cloud_verify.py http://target.example/
```

For security research and authorized testing only.
