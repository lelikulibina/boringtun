#!/usr/bin/env python3
"""Real bidirectional TCP/UDP payload test for the AWG namespace harness.

The TCP echo moves 4 MiB in each direction. UDP sends 64 independently
verified datagrams. The peer is a separate process in the opposite network
namespace; this is not an in-process tunnel mock.
"""
import argparse
import socket
import threading
import time

TCP_BYTES = 4 * 1024 * 1024
CHUNK = 16 * 1024
UDP_COUNT = 64
UDP_SIZE = 1200


def recv_exact(sock, size):
    parts = bytearray()
    while len(parts) < size:
        block = sock.recv(min(CHUNK, size - len(parts)))
        if not block:
            raise RuntimeError(f"connection closed after {len(parts)} of {size} bytes")
        parts.extend(block)
    return bytes(parts)


def server(host, tcp_port, udp_port):
    stop = threading.Event()

    def tcp_loop():
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, tcp_port))
        listener.listen(4)
        listener.settimeout(1)
        try:
            while not stop.is_set():
                try:
                    conn, _ = listener.accept()
                except socket.timeout:
                    continue
                with conn:
                    remaining = TCP_BYTES
                    while remaining:
                        data = conn.recv(min(CHUNK, remaining))
                        if not data:
                            break
                        conn.sendall(data)
                        remaining -= len(data)
        finally:
            listener.close()

    def udp_loop():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, udp_port))
        sock.settimeout(1)
        try:
            while not stop.is_set():
                try:
                    data, peer = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                sock.sendto(data, peer)
        finally:
            sock.close()

    threads = [
        threading.Thread(target=tcp_loop, daemon=True),
        threading.Thread(target=udp_loop, daemon=True),
    ]
    for thread in threads:
        thread.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop.set()


def client(host, tcp_port, udp_port):
    deadline = time.monotonic() + 15
    tcp = None
    while time.monotonic() < deadline:
        try:
            tcp = socket.create_connection((host, tcp_port), timeout=2)
            break
        except OSError:
            time.sleep(0.2)
    if tcp is None:
        raise RuntimeError("TCP echo service did not become reachable")
    with tcp:
        tcp.settimeout(10)
        sent = 0
        while sent < TCP_BYTES:
            size = min(CHUNK, TCP_BYTES - sent)
            payload = bytes(((sent + i) & 0xff) for i in range(size))
            tcp.sendall(payload)
            echoed = recv_exact(tcp, size)
            if echoed != payload:
                raise RuntimeError(f"TCP echo mismatch at byte {sent}")
            sent += size
    print(f"PASS TCP: {TCP_BYTES} bytes sent and echoed")

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(5)
    for index in range(UDP_COUNT):
        prefix = index.to_bytes(4, "big")
        payload = prefix + bytes(((index + i) & 0xff) for i in range(UDP_SIZE - len(prefix)))
        udp.sendto(payload, (host, udp_port))
        echoed, _ = udp.recvfrom(65535)
        if echoed != payload:
            raise RuntimeError(f"UDP echo mismatch for datagram {index}")
    udp.close()
    print(f"PASS UDP: {UDP_COUNT} datagrams of {UDP_SIZE} bytes sent and echoed")


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
