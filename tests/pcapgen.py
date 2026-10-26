"""Writes tiny synthetic PCAP files so adapter tests need no real traffic or network."""
import socket
import struct


def _eth(payload: bytes) -> bytes:
    return b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00" + payload


def _ipv4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0x4000, 64, proto, 0,
                         socket.inet_aton(src), socket.inet_aton(dst))
    return header + payload


def tcp(sport: int, dport: int, flags: int = 0x02) -> bytes:
    return struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 0x50, flags, 8192, 0, 0)


def udp(sport: int, dport: int, data: bytes = b"") -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data


def make_pcap(path, packets):
    """packets: list of (epoch_seconds, src_ip, dst_ip, 'tcp'|'udp', sport, dport)."""
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for ts, src, dst, kind, sport, dport in packets:
        l4 = tcp(sport, dport) if kind == "tcp" else udp(sport, dport, b"x")
        frame = _eth(_ipv4(src, dst, 6 if kind == "tcp" else 17, l4))
        out += struct.pack("<IIII", int(ts), 0, len(frame), len(frame)) + frame
    path.write_bytes(out)
    return path


SAMPLE = [
    (1761300000, "10.0.0.5", "10.0.0.1", "udp", 50000, 53),
    (1761300001, "10.0.0.5", "93.184.216.34", "tcp", 40000, 443),
    (1761300002, "10.0.0.5", "93.184.216.34", "tcp", 40000, 443),
    (1761300003, "10.0.0.7", "10.0.0.1", "tcp", 40100, 22),
]
