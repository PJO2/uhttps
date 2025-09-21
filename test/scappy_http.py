#!/usr/bin/env python3
# Requires scapy: pip install scapy
from scapy.all import *
import argparse

def send_http_payload(dst, dport, payload):
    # perform a TCP handshake (SYN, SYN-ACK, ACK) and send a single PSH
    ip = IP(dst=dst)
    syn = TCP(dport=dport, flags='S', sport=RandShort())
    synack = sr1(ip/syn, timeout=2, verbose=0)
    if synack is None:
        print("No SYN-ACK received.")
        return
    sport = synack.dport
    ack = TCP(dport=dport, sport=sport, flags='A', seq=synack.ack, ack=synack.seq+1)
    send(ip/ack, verbose=0)
    psh = TCP(dport=dport, sport=sport, flags='PA', seq=synack.ack, ack=synack.seq+1)
    send(ip/psh/payload, verbose=0)
    # close
    fin = TCP(dport=dport, sport=sport, flags='FA', seq=synack.ack + len(payload), ack=synack.seq+1)
    send(ip/fin, verbose=0)

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--dst", default="127.0.0.1")
    p.add_argument("--port", default=8080, type=int)
    args = p.parse_args()

    payload = b"GET /" + b"A"*5000 + b" HTTP/1.1\r\nHost: " + args.dst.encode() + b"\r\nConnection: close\r\n\r\n"
    print("Sending crafted TCP-level payload (may require root).")
    send_http_payload(args.dst, args.port, payload)

