"""
VulnScope Network Discovery
------------------------------
Finds devices on your local network (LAN/WiFi) by:
  1. Determining your own IP and assumed /24 subnet
  2. Ping-sweeping the subnet (populates the OS's ARP cache)
  3. Reading the ARP table for IP <-> MAC pairs

This does NOT require admin/root privileges (unlike raw ARP packet
crafting with scapy), which makes it much easier to run on a normal
Windows laptop without extra driver installs.

LEGAL NOTE: this only touches your own local network segment, which
is normal network administration — same category of activity as
checking your router's "connected devices" page.
"""

import platform
import re
import socket
import subprocess
import threading
from dataclasses import dataclass
from typing import Optional

IS_WINDOWS = platform.system().lower() == "windows"


@dataclass
class NetworkDevice:
    ip: str
    mac: Optional[str]
    is_self: bool = False


def get_local_ip_and_subnet() -> tuple[str, str]:
    """
    Finds this machine's LAN IP without needing any special permissions,
    by opening a UDP socket toward a public IP (no packet is actually
    sent for UDP connect — this just asks the OS to pick a local route).
    Returns (local_ip, subnet_prefix) e.g. ("192.168.1.42", "192.168.1")
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    finally:
        s.close()
    subnet_prefix = ".".join(local_ip.split(".")[:3])
    return local_ip, subnet_prefix


def _ping_host(ip: str):
    """Fire a single, quick ping — just to nudge the OS into caching the ARP entry."""
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", "300", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    try:
        subprocess.run(cmd, capture_output=True, timeout=2)
    except (subprocess.TimeoutExpired, OSError):
        pass


def ping_sweep(subnet_prefix: str, max_threads: int = 50):
    """Ping every host in the /24 range concurrently to populate the ARP cache."""
    threads = []
    for i in range(1, 255):
        ip = f"{subnet_prefix}.{i}"
        t = threading.Thread(target=_ping_host, args=(ip,), daemon=True)
        t.start()
        threads.append(t)
        if len(threads) >= max_threads:
            for th in threads:
                th.join()
            threads = []
    for th in threads:
        th.join()


def read_arp_table() -> list[NetworkDevice]:
    """Parse the OS's ARP table into a list of (ip, mac) pairs."""
    try:
        output = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True, timeout=5
        ).stdout
    except (subprocess.TimeoutExpired, OSError):
        return []

    devices = []
    if IS_WINDOWS:
        # Windows format:  192.168.1.1          00-14-22-01-23-45     dynamic
        pattern = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F-]{17})")
    else:
        # Linux/Mac format: ? (192.168.1.1) at 00:14:22:01:23:45 [ether] on eth0
        pattern = re.compile(r"\((\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+([0-9a-fA-F:]{17})")

    for line in output.splitlines():
        match = pattern.search(line)
        if match:
            ip, mac = match.group(1), match.group(2)
            mac = mac.upper()
            if mac in ("FF-FF-FF-FF-FF-FF", "FF:FF:FF:FF:FF:FF"):
                continue  # broadcast address, not a real device
            devices.append(NetworkDevice(ip=ip, mac=mac))
    return devices


def discover_devices() -> list[NetworkDevice]:
    """
    Full discovery flow: find our own subnet, ping-sweep it, then
    read back the ARP table for every device that responded.
    """
    local_ip, subnet_prefix = get_local_ip_and_subnet()
    ping_sweep(subnet_prefix)
    devices = read_arp_table()

    # Only keep devices in our own subnet (ARP table may have stale
    # entries from VPNs or other adapters)
    devices = [d for d in devices if d.ip.startswith(subnet_prefix)]

    # Mark ourselves
    found_self = False
    for d in devices:
        if d.ip == local_ip:
            d.is_self = True
            found_self = True
    if not found_self:
        devices.append(NetworkDevice(ip=local_ip, mac=None, is_self=True))

    devices.sort(key=lambda d: tuple(int(x) for x in d.ip.split(".")))
    return devices


if __name__ == "__main__":
    print("Discovering devices on your local network (this takes ~5-10s)...\n")
    devices = discover_devices()
    print(f"{'IP':<18}{'MAC':<20}{'NOTE'}")
    print("-" * 50)
    for d in devices:
        note = "(this machine)" if d.is_self else ""
        print(f"{d.ip:<18}{(d.mac or '-'):<20}{note}")
    print(f"\nTotal devices found: {len(devices)}")