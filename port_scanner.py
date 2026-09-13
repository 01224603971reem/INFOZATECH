#!/usr/bin/env python3
"""Educational local port scanner for authorized defensive testing.

By default, only loopback targets are allowed. Use --allow-authorized-target
only when you own the target or have explicit permission to test it.
"""

from __future__ import annotations

import argparse
import ipaddress
import socket
import sys
from dataclasses import dataclass

COMMON_SERVICES = {
    20: "FTP data",
    21: "FTP control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP alternate",
}


@dataclass
class ScanResult:
    port: int
    state: str
    service: str


def is_loopback_target(target: str) -> bool:
    if target.lower() in {"localhost", "ip6-localhost"}:
        return True
    try:
        return ipaddress.ip_address(target).is_loopback
    except ValueError:
        return False


def resolve_target(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as error:
        raise ValueError(f"Could not resolve target: {target}") from error


def scan_port(target_ip: str, port: int, timeout: float) -> ScanResult:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        status = sock.connect_ex((target_ip, port))
        state = "open" if status == 0 else "closed/filtered"
    except OSError:
        state = "unreachable/error"
    finally:
        sock.close()
    return ScanResult(port, state, COMMON_SERVICES.get(port, "unknown service"))


def build_port_list(port_args: list[str]) -> list[int]:
    ports: set[int] = set()
    for item in port_args:
        for part in item.split(","):
            value = part.strip()
            if not value:
                continue
            if "-" in value:
                start_text, end_text = value.split("-", 1)
                start, end = int(start_text), int(end_text)
                if start > end:
                    raise ValueError("Port range start must not exceed its end")
                if end - start > 200:
                    raise ValueError("For this educational tool, a range may contain at most 201 ports")
                ports.update(range(start, end + 1))
            else:
                ports.add(int(value))
    if not ports or any(port < 1 or port > 65535 for port in ports):
        raise ValueError("Ports must be between 1 and 65535")
    return sorted(ports)


def main() -> int:
    parser = argparse.ArgumentParser(description="Authorized educational TCP port scanner.")
    parser.add_argument("target", nargs="?", default="127.0.0.1", help="Target; defaults to localhost")
    parser.add_argument("--ports", nargs="+", default=["22,80,443,8080"], help="Ports or ranges, e.g. 22 80-82")
    parser.add_argument("--timeout", type=float, default=0.5, help="Timeout per port in seconds")
    parser.add_argument("--allow-authorized-target", action="store_true", help="Acknowledge explicit authorization for a non-loopback target")
    args = parser.parse_args()

    if args.timeout <= 0 or args.timeout > 10:
        print("ERROR: timeout must be greater than 0 and no more than 10 seconds", file=sys.stderr)
        return 1
    if not is_loopback_target(args.target) and not args.allow_authorized_target:
        print("ERROR: Only localhost/loopback targets are allowed by default.", file=sys.stderr)
        print("Use --allow-authorized-target only for a system you own or are explicitly authorized to test.", file=sys.stderr)
        return 1

    try:
        target_ip = resolve_target(args.target)
        ports = build_port_list(args.ports)
    except (ValueError, TypeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print(f"Authorized educational scan: {args.target} ({target_ip})")
    print(f"Ports checked: {len(ports)} | Timeout: {args.timeout}s")
    open_count = 0
    for port in ports:
        result = scan_port(target_ip, port, args.timeout)
        if result.state == "open":
            open_count += 1
            print(f"OPEN: {result.port}/tcp | typical service: {result.service}")
    print(f"Open ports found: {open_count}")
    print("Note: An open port is not automatically a vulnerability; it indicates a reachable service that should be identified, updated, and access-controlled.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
