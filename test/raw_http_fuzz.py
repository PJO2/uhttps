#!/usr/bin/env python3
"""
raw_http_fuzz.py
Send raw / malformed HTTP over TCP to test parsing edge-cases.
"""

import socket
import argparse
import ssl
import time

def send_raw(host, port, payload, use_tls=False):
    print(f"\n---> connecting to {host}:{port} TLS={use_tls}")
    s = socket.create_connection((host, port), timeout=5)
    if use_tls:
        ctx = ssl.create_default_context()
        # for testing self-signed
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=host)

    s.sendall(payload)
    # give server time to respond
    time.sleep(0.5)
    try:
        resp = s.recv(65536)
        print("Received:", resp[:1000])
    except Exception as e:
        print("recv exception:", e)
    s.close()

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", default=8080, type=int)
    p.add_argument("--tls", action="store_true")
    args = p.parse_args()

    # 1. Normal raw GET
    payload = b"GET /index.html HTTP/1.1\r\nHost: %b\r\nConnection: close\r\n\r\n" % args.host.encode()
    send_raw(args.host, args.port, payload, use_tls=args.tls)

    # 2. Truncated request (no final CRLF)
    payload2 = b"GET /index.html HTTP/1.1\r\nHost: " + args.host.encode() + b"\r\n"
    send_raw(args.host, args.port, payload2, use_tls=args.tls)

    # 3. Oversized request-line (very long URI)
    big_uri = b"/" + b"A" * 30000 + b".html"
    payload3 = b"GET " + big_uri + b" HTTP/1.1\r\nHost: " + args.host.encode() + b"\r\n\r\n"
    send_raw(args.host, args.port, payload3, use_tls=args.tls)

    # 4. CRLF injection in header value (raw bytes)
    payload4 = b"GET / HTTP/1.1\r\nHost: " + args.host.encode() + b"\r\nX-Test: normal\r\nInjected: oops\r\n\r\n"
    send_raw(args.host, args.port, payload4, use_tls=args.tls)

    # 5. A request with embedded null byte
    payload5 = b"GET /secret.txt%00 HTTP/1.1\r\nHost: " + args.host.encode() + b"\r\n\r\n"
    send_raw(args.host, args.port, payload5, use_tls=args.tls)

    # 6. Path with many ../ and percent-encoding
    trav = b"/" + b"..%2f" * 60 + b"etc/passwd"
    payload6 = b"GET " + trav + b" HTTP/1.1\r\nHost: " + args.host.encode() + b"\r\n\r\n"
    send_raw(args.host, args.port, payload6, use_tls=args.tls)

