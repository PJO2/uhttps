#!/usr/bin/env python3
"""
test_uhttps_requests.py
Simple, clear tests using requests:
- normal GET/POST
- GET with query args
- directory traversal attempts
- long-path / header floods
Run: python3 test_uhttps_requests.py --host 127.0.0.1 --port 8443 --scheme https
"""

import argparse
import requests
import urllib.parse
import sys

def do_request(session, method, url, **kwargs):
    print(f"\n-> {method} {url}")
    try:
        r = session.request(method, url, timeout=5, **kwargs)
        print(f"Status: {r.status_code}   len={len(r.content)}")
        print("Headers:", r.headers)
        print("Body (first 400 bytes):")
        print(r.content[:400])
    except Exception as e:
        print("Exception:", e)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", default="8080", type=int)
    p.add_argument("--scheme", choices=("http","https"), default="http")
    args = p.parse_args()

    base = f"{args.scheme}://{args.host}:{args.port}"

    # requests session (for HTTPS with self-signed certs, verify=False)
    sess = requests.Session()
    sess.verify = False  # ignore self-signed; ok for testing local server

    # 1. Normal GET index
    do_request(sess, "GET", base + "/index.html")

    # 2. GET with query args
    params = {"search": "network+testing", "page": "1"}
    url = base + "/index.html?" + urllib.parse.urlencode(params)
    do_request(sess, "GET", url)

    # 3. Get a deep path
    do_request(sess, "GET", base + "/my_longdirectory_name/file.bin")

    # 4. Directory traversal attempts (plain)
    do_request(sess, "GET", base + "/../../../../etc/passwd")
    # percent-encoded traversal
    do_request(sess, "GET", base + "/%2e%2e%2f%2e%2e%2fetc/passwd")

    # 5. Null byte (percent encoded) attempt in path / filename
    do_request(sess, "GET", base + "/secret.txt%00.png")

    # 6. Very long path (buffer overflow style)
    long_path = "/" + ("A" * 20000) + ".txt"
    do_request(sess, "GET", base + long_path)

    # 7. Very long query string
    long_q = "q=" + ("B" * 20000)
    do_request(sess, "GET", base + "/index.html?" + long_q)

    # 8. Header flood: very long Host header
    headers = {"Host": "H" * 16000}
    do_request(sess, "GET", base + "/index.html", headers=headers)

    # 9. POST with a large body
    big_body = b"X" * 200000
    do_request(sess, "POST", base + "/upload", data=big_body, headers={"Content-Type":"application/octet-stream"})

    # 10. CRLF injection attempt (try to inject new header using encoded CRLF)
    # Many servers filter this, but it's worth checking what the server does with percent-encoded CRLF in path.
    crlf_path = "/vulnerable?name=normal%0d%0aInjected-Header:evil"
    do_request(sess, "GET", base + crlf_path)

if __name__ == "__main__":
    if sys.version_info < (3,6):
        print("Use Python 3.6+")
        sys.exit(1)
    main()

