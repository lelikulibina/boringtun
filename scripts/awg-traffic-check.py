#!/usr/bin/env python3
"""Real TCP and UDP echo checks over the AmneziaWG test tunnel.

The server mode runs inside the server network namespace. Client mode runs
inside the client namespace and verifies byte-for-byte echo integrity.
Only the Python standard library is required.
"""
import socket
import sys
import threading
import time

HOST = "10.77.0.1"
TCP_PORT = 40101
UDP_PORT = 40102
TCP_BYTES = 256 * 1024
UDP_BYTES = 1200


def tcp_echo_server(ready):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((HOST, TCP_PORT))
    listener.listen(4)
    ready.set()
    while True:
        conn, _ = listener.accept()
        with conn:
            while True:
                data = conn.recv(16384)
                if not data:
                    break
                conn.sendall(data)


def udp_echo_server(ready):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, UDP_PORT))
    ready.set()
    while True:
        data, addr = sock.recvfrom(65535)
        sock.sendto(data, addr)


def run_server():
    tcp_ready = threading.Event()
    udp_ready = threading.Event()
    threading.Thread(target=tcp_echo_server, args=(tcp_ready,), daemon=True).start()
    threading.Thread(target=udp_echo_server, args=(udp_ready,), daemon=True).start()
    if not tcp_ready.wait(5) or not udp_ready.wait(5):
        raise RuntimeError("TCP/UDP echo listeners did not become ready")
    print("READY", flush=True)
    while True:
        time.sleep(3600)


def run_client():
    payload = bytes((i * 31 + 7) & 0xFF for i in range(TCP_BYTES))
    with socket.create_connection((HOST, TCP_PORT), timeout=10) as sock:
        sock.settimeout(10)
        sock.sendall(payload)
        sock.shutdown(socket.SHUT_WR)
        received = bytearray()
        while True:
            chunk = sock.recv(16384)
            if not chunk:
                break
            received.extend(chunk)
    if received != payload:
        raise RuntimeError(
            "TCP echo mismatch: sent %d bytes, received %d"
            % (len(payload), len(received))
        )

    udp_payload = bytes((i * 17 + 3) & 0xFF for i in range(UDP_BYTES))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        sock.sendto(udp_payload, (HOST, UDP_PORT))
        received, _ = sock.recvfrom(65535)
    if received != udp_payload:
        raise RuntimeError(
            "UDP echo mismatch: sent %d bytes, received %d"
            % (len(udp_payload), len(received))
        )

    print(
        "PASS TCP echo (%d bytes); PASS UDP echo (%d bytes)"
        % (len(payload), len(udp_payload))
    )


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("server", "client"):
        sys.exit("usage: awg-traffic-check.py server|client")
    if sys.argv[1] == "server":
        run_server()
    else:
        run_client()
