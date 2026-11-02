#!/usr/bin/env python3
"""End-to-end TCP/UDP echo traffic over a real namespace-based AWG tunnel."""
import argparse
import socket
import threading
import time

TCP_BYTES = 4 * 1024 * 1024
CHUNK = 16 * 1024
UDP_COUNT = 64
UDP_SIZE = 1200


def recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        block = sock.recv(min(CHUNK, size - len(data)))
        if not block:
            raise RuntimeError(f"TCP closed after {len(data)} of {size} bytes")
        data.extend(block)
    return bytes(data)


def server(host, tcp_port, udp_port):
    def tcp_loop():
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, tcp_port))
        listener.listen(4)
        while True:
            conn, _ = listener.accept()
            with conn:
                remaining = TCP_BYTES
                while remaining:
                    block = conn.recv(min(CHUNK, remaining))
                    if not block:
                        break
                    conn.sendall(block)
                    remaining -= len(block)

    def udp_loop():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((host, udp_port))
        while True:
            data, peer = sock.recvfrom(65535)
            sock.sendto(data, peer)

    threading.Thread(target=tcp_loop, daemon=True).start()
    threading.Thread(target=udp_loop, daemon=True).start()
    while True:
        time.sleep(3600)


def client(host, tcp_port, udp_port):
    deadline = time.monotonic() + 15
    conn = None
    while time.monotonic() < deadline:
        try:
            conn = socket.create_connection((host, tcp_port), timeout=2)
            break
        except OSError:
            time.sleep(0.2)
    if conn is None:
        raise RuntimeError("TCP echo server did not become reachable")

    with conn:
        conn.settimeout(10)
        sent = 0
        while sent < TCP_BYTES:
            size = min(CHUNK, TCP_BYTES - sent)
            payload = bytes(((sent + i) & 0xff) for i in range(size))
            conn.sendall(payload)
            if recv_exact(conn, size) != payload:
                raise RuntimeError(f"TCP echo mismatch at offset {sent}")
            sent += size
    print(f"PASS TCP: {TCP_BYTES} bytes echoed exactly")

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(5)
    for index in range(UDP_COUNT):
        prefix = index.to_bytes(4, "big")
        payload = prefix + bytes(
            ((index + i) & 0xff) for i in range(UDP_SIZE - len(prefix))
        )
        udp.sendto(payload, (host, udp_port))
        echoed, _ = udp.recvfrom(65535)
        if echoed != payload:
            raise RuntimeError(f"UDP echo mismatch for datagram {index}")
    udp.close()
    print(f"PASS UDP: {UDP_COUNT} datagrams of {UDP_SIZE} bytes echoed exactly")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("server", "client"))
    parser.add_argument("host")
    parser.add_argument("tcp_port", type=int)
    parser.add_argument("udp_port", type=int)
    args = parser.parse_args()
    if args.mode == "server":
        server(args.host, args.tcp_port, args.udp_port)
    else:
        client(args.host, args.tcp_port, args.udp_port)


if __name__ == "__main__":
    main()
