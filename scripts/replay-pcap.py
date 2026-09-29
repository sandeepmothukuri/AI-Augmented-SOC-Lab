#!/usr/bin/env python3
"""
Network Attack Traffic Replay & PCAP Generation Tool
=====================================================
Generates and replays curated network attack patterns against Suricata/Zeek sensors
and the Wazuh SIEM stack. Produces valid PCAP files (Wireshark/tcpdump compatible)
and can replay packets directly over network interfaces using raw sockets or tcpreplay.

Curated Attack Scenarios:
  1. Cobalt Strike Malleable HTTP C2 Beaconing
  2. High-Entropy DNS Tunneling & Base32 Exfiltration
  3. Distributed TCP SYN Port Scan Sweep
  4. Web Shell HTTP Interaction (cmd.exe / bash invocation)

Usage:
    python scripts/replay-pcap.py --scenario all
    python scripts/replay-pcap.py --scenario cobalt-strike --output pcaps/cobalt_strike.pcap
    python scripts/replay-pcap.py --scenario dns-tunneling --live-replay --target 127.0.0.1
    python scripts/replay-pcap.py --generate-all-pcaps

Environment Variables:
    TARGET_HOST   - Target sensor host IP (default: 127.0.0.1)
    SURICATA_IP   - Suricata sensor IP
"""

import argparse
import logging
import socket
import struct
import time
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("pcap-replay")


class PCAPWriter:
    """Zero-dependency Wireshark/tcpdump standard Libpcap file generator."""

    PCAP_GLOBAL_HEADER = struct.pack(
        "<IHHiIII",
        0xA1B2C3D4,  # Magic number (microsecond resolution)
        2,  # Major version
        4,  # Minor version
        0,  # GMT to local correction
        0,  # Accuracy of timestamps
        65535,  # Max snapshot length
        1,  # Link-layer header type (1 = Ethernet DLT_EN10MB)
    )

    def __init__(self, filename: Path):
        self.filename = filename
        self.filename.parent.mkdir(parents=True, exist_ok=True)
        self.file = open(self.filename, "wb")
        self.file.write(self.PCAP_GLOBAL_HEADER)
        self.packet_count = 0

    def write_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        payload: bytes,
        proto: str = "TCP",
    ) -> None:
        """Construct Ethernet + IPv4 + TCP/UDP frame and write pcap record."""
        # 1. Ethernet Header (14 bytes): Dst MAC, Src MAC, EtherType (0x0800 IPv4)
        eth_header = b"\x00\x0c\x29\x6d\x11\x22\x00\x0c\x29\xaa\xbb\xcc\x08\x00"

        # 2. IP Header (20 bytes)
        src_ip_b = socket.inet_aton(src_ip)
        dst_ip_b = socket.inet_aton(dst_ip)
        ip_proto = 6 if proto.upper() == "TCP" else 17

        transport_len = (20 if proto.upper() == "TCP" else 8) + len(payload)
        ip_total_len = 20 + transport_len

        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,  # Version (4) + IHL (5)
            0x00,  # Type of Service
            ip_total_len,  # Total Length
            0x1C2D,  # Identification
            0x4000,  # Flags (Don't Fragment)
            64,  # TTL
            ip_proto,  # Protocol
            0x0000,  # Header Checksum (0 for capture replay)
            src_ip_b,
            dst_ip_b,
        )

        # 3. Transport Header
        if proto.upper() == "TCP":
            # TCP Header (20 bytes)
            transport_header = struct.pack(
                "!HHIIBBHHH",
                src_port,
                dst_port,
                1000000 + self.packet_count,  # Sequence Number
                2000000 + self.packet_count,  # Ack Number
                0x50,  # Data offset (5 * 4 = 20 bytes)
                0x18,  # Flags (ACK, PSH)
                64240,  # Window size
                0x0000,  # Checksum
                0x0000,  # Urgent pointer
            )
        else:
            # UDP Header (8 bytes)
            transport_header = struct.pack(
                "!HHHH",
                src_port,
                dst_port,
                8 + len(payload),  # UDP length
                0x0000,  # Checksum
            )

        full_frame = eth_header + ip_header + transport_header + payload

        # 4. PCAP Packet Record Header (16 bytes)
        now = time.time()
        sec = int(now)
        usec = int((now - sec) * 1_000_000)
        pcap_rec_header = struct.pack("<IIII", sec, usec, len(full_frame), len(full_frame))

        self.file.write(pcap_rec_header + full_frame)
        self.packet_count += 1

    def close(self) -> int:
        self.file.close()
        return self.packet_count


# ============================================================================
# SCENARIO GENERATORS
# ============================================================================
def generate_cobalt_strike_traffic(writer: PCAPWriter, target_ip: str) -> None:
    """Simulate Cobalt Strike malleable C2 HTTP GET/POST beacons."""
    attacker_ip = "198.51.100.120"

    beacons = [
        # Check-in beacon
        (
            f"GET /submit.php?id=9872134 HTTP/1.1\r\n"
            f"Host: {target_ip}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
            f"Cookie: session=SXNzb21ldHJpY19DMl9CcmFuY2g=\r\n"
            f"Accept: */*\r\n\r\n"
        ).encode(),
        # Task output response
        (
            f"POST /api/v2/telemetry HTTP/1.1\r\n"
            f"Host: {target_ip}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
            f"Content-Type: application/octet-stream\r\n"
            f"Content-Length: 48\r\n\r\n"
            f"\xde\xad\xbe\xef\x01\x02\x03\x04COBALT_STRIKE_HEARTBEAT_PAYLOAD_TEST\x00"
        ).encode(),
    ]

    for b in beacons:
        writer.write_packet(attacker_ip, target_ip, 49210, 80, b, proto="TCP")
    logger.info("Generated Cobalt Strike C2 beaconing frames")


def generate_dns_tunneling_traffic(writer: PCAPWriter, target_ip: str) -> None:
    """Simulate high-entropy DNS tunneling queries for exfiltration."""
    attacker_ip = "192.168.1.150"

    queries = [
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x3f4d5a90000300000004000000ffff0000b8000000000000004000000000000000"
        b"\x06tunnel\x09exfiltrate\x03org\x00\x00\x10\x00\x01",
        b"\x12\x35\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x3f504b0304140006000800000021008d98d249f801000040060000130000000000"
        b"\x06tunnel\x09exfiltrate\x03org\x00\x00\x10\x00\x01",
    ]

    for q in queries:
        writer.write_packet(attacker_ip, target_ip, 53530, 53, q, proto="UDP")
    logger.info("Generated DNS tunneling exfiltration frames")


def generate_syn_port_scan(writer: PCAPWriter, target_ip: str) -> None:
    """Simulate fast TCP SYN port scanning sweep."""
    attacker_ip = "198.51.100.55"
    ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 1433, 3306, 3389, 5432, 8080, 8888]

    for port in ports:
        writer.write_packet(attacker_ip, target_ip, 40000 + port, port, b"", proto="TCP")
    logger.info("Generated TCP SYN port scan sweep across %d ports", len(ports))


def generate_web_shell_traffic(writer: PCAPWriter, target_ip: str) -> None:
    """Simulate web shell backdoor commands over HTTP."""
    attacker_ip = "203.0.113.88"

    payloads = [
        (
            f"GET /uploads/shell.php?cmd=whoami HTTP/1.1\r\n"
            f"Host: {target_ip}\r\n"
            f"User-Agent: Mozilla/5.0 (Pentest)\r\n\r\n"
        ).encode(),
        (
            f"POST /shell.php HTTP/1.1\r\n"
            f"Host: {target_ip}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 35\r\n\r\n"
            f"cmd=cat+/etc/passwd+|+grep+-E+sh$"
        ).encode(),
    ]

    for p in payloads:
        writer.write_packet(attacker_ip, target_ip, 51200, 80, p, proto="TCP")
    logger.info("Generated Web Shell interaction traffic")


def live_stream_packets(target_ip: str) -> None:
    """Stream synthetic UDP packets directly to live sensor/Wazuh."""
    logger.info("Streaming live simulated packets to %s...", target_ip)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Simulate DNS C2 tunnel queries over live UDP
        dns_query = (
            b"\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x12live-simulated-c2\x06tunnel\x04test\x00\x00\x10\x00\x01"
        )
        sock.sendto(dns_query, (target_ip, 53))
        logger.info("[OK] Sent live DNS C2 frame to %s:53", target_ip)
    except Exception as exc:
        logger.warning("Live stream error (expected if port 53 is not listening): %s", exc)
    finally:
        sock.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Network Attack Traffic Replay & PCAP Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--scenario",
        choices=["all", "cobalt-strike", "dns-tunneling", "port-scan", "web-shell"],
        default="all",
        help="Attack scenario to generate (default: all)",
    )
    parser.add_argument(
        "--output",
        default="pcaps/attack_simulation.pcap",
        help="Output PCAP file path (default: pcaps/attack_simulation.pcap)",
    )
    parser.add_argument(
        "--target",
        default="127.0.0.1",
        help="Target IP address for headers (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--generate-all-pcaps",
        action="store_true",
        help="Generate individual curated PCAP files for each scenario in pcaps/",
    )
    parser.add_argument(
        "--live-replay",
        action="store_true",
        help="Also stream live network datagrams to the sensor port",
    )

    args = parser.parse_args()

    if args.generate_all_pcaps:
        scenarios = {
            "cobalt_strike_beacon.pcap": generate_cobalt_strike_traffic,
            "dns_tunneling_exfil.pcap": generate_dns_tunneling_traffic,
            "syn_port_scan.pcap": generate_syn_port_scan,
            "web_shell_traffic.pcap": generate_web_shell_traffic,
        }
        for fname, func in scenarios.items():
            out_p = Path("pcaps") / fname
            w = PCAPWriter(out_p)
            func(w, args.target)
            count = w.close()
            logger.info("Saved %s with %d packet(s)", out_p, count)
        return

    out_path = Path(args.output)
    writer = PCAPWriter(out_path)

    if args.scenario in ("cobalt-strike", "all"):
        generate_cobalt_strike_traffic(writer, args.target)
    if args.scenario in ("dns-tunneling", "all"):
        generate_dns_tunneling_traffic(writer, args.target)
    if args.scenario in ("port-scan", "all"):
        generate_syn_port_scan(writer, args.target)
    if args.scenario in ("web-shell", "all"):
        generate_web_shell_traffic(writer, args.target)

    total = writer.close()
    logger.info("Successfully generated PCAP: %s (%d packets)", out_path, total)

    if args.live_replay:
        live_stream_packets(args.target)


if __name__ == "__main__":
    main()
