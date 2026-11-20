"""Minimal MQTT 3.1.1 authentication and read-ACL probe.

Credentials are read from environment variables and are never printed.
The probe connects, verifies CONNACK success, subscribes with QoS 0,
verifies SUBACK success, and disconnects without publishing.
"""

import os
import socket
import struct
import sys
import uuid


def encode_remaining_length(length):
    encoded = bytearray()

    while True:
        byte = length % 128
        length //= 128
        if length:
            byte |= 0x80
        encoded.append(byte)
        if not length:
            return bytes(encoded)


def encode_string(value):
    data = value.encode("utf-8")
    return struct.pack("!H", len(data)) + data


def packet(packet_type, flags, payload):
    header = bytes([(packet_type << 4) | flags])
    return header + encode_remaining_length(len(payload)) + payload


def read_packet(sock):
    first = sock.recv(1)
    if len(first) != 1:
        raise RuntimeError("Connection closed before a response was received.")

    multiplier = 1
    remaining = 0
    while True:
        byte = sock.recv(1)
        if len(byte) != 1:
            raise RuntimeError("Connection closed in packet length.")
        value = byte[0]
        remaining += (value & 0x7F) * multiplier
        if not value & 0x80:
            break
        multiplier *= 128
        if multiplier > 128**3:
            raise RuntimeError("Malformed MQTT remaining length.")

    body = bytearray()
    while len(body) < remaining:
        chunk = sock.recv(remaining - len(body))
        if not chunk:
            raise RuntimeError("Connection closed in packet body.")
        body.extend(chunk)

    return first[0], bytes(body)


def main():
    host = os.environ.get("MQTT_PROBE_HOST", "127.0.0.1")
    port = int(os.environ.get("MQTT_PROBE_PORT", "1884"))
    topic = os.environ.get("MQTT_PROBE_TOPIC", "")
    username = os.environ.get("MQTT_PROBE_USERNAME", "")
    password = os.environ.get("MQTT_PROBE_PASSWORD", "")

    if not topic or not username or not password:
        raise SystemExit("Required MQTT probe settings are missing.")

    client_id = "iomt-auth-probe-" + uuid.uuid4().hex

    variable_header = (
        encode_string("MQTT")
        + bytes([4])
        + bytes([0xC2])
        + struct.pack("!H", 30)
    )
    connect_payload = (
        encode_string(client_id)
        + encode_string(username)
        + encode_string(password)
    )

    with socket.create_connection((host, port), timeout=5) as sock:
        sock.settimeout(5)
        sock.sendall(packet(1, 0, variable_header + connect_payload))
        packet_type, connack = read_packet(sock)

        if packet_type >> 4 != 2 or len(connack) != 2:
            raise RuntimeError("Invalid CONNACK response.")

        return_code = connack[1]
        if return_code != 0:
            print(f"connect_return_code={return_code}")
            return 2

        subscribe_payload = (
            struct.pack("!H", 1)
            + encode_string(topic)
            + bytes([0])
        )
        sock.sendall(packet(8, 2, subscribe_payload))
        packet_type, suback = read_packet(sock)

        if packet_type >> 4 != 9 or len(suback) < 3:
            raise RuntimeError("Invalid SUBACK response.")

        granted_qos = suback[2]
        if granted_qos == 0x80:
            print("subscribe_authorized=false")
            return 3

        sock.sendall(b"\xE0\x00")
        print("connect_authenticated=true")
        print("subscribe_authorized=true")
        print(f"granted_qos={granted_qos}")
        return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"probe_error={type(exc).__name__}")
        raise SystemExit(1)
