"""
VulnScope Core Scanner
-----------------------
Multi-threaded TCP connect scanner with service banner grabbing.

LEGAL NOTICE: Only scan hosts you own or have explicit permission to test.
Use `localhost`, a home-lab VM, or `scanme.nmap.org` (Nmap's official legal
test target) for development and demos.
"""

import socket
import threading
import queue
import time
from dataclasses import dataclass, field
from typing import Optional


# Common ports worth checking by default. Full 1-65535 scan is possible
# but slow for a demo; this list covers the services most CVEs target.
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465,
    587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000,
    8080, 8443, 9200, 27017,
]

# Service name -> simple probe to send after connecting, to coax a banner
# out of servers that don't announce themselves on connect (like HTTP).
PROBES = {
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8000: b"HEAD / HTTP/1.0\r\n\r\n",
    443: None,  # TLS — handled separately if needed later
}


@dataclass
class PortResult:
    port: int
    state: str  # "open" | "closed" | "filtered"
    service_guess: Optional[str] = None
    banner: Optional[str] = None
    response_time_ms: Optional[float] = None


@dataclass
class ScanResult:
    target: str
    resolved_ip: str
    started_at: float
    finished_at: float = 0.0
    open_ports: list = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        return round(self.finished_at - self.started_at, 2)


def guess_service(port: int) -> str:
    """Fallback service name lookup using the standard socket db."""
    try:
        return socket.getservbyport(port)
    except OSError:
        return "unknown"


def grab_banner(sock: socket.socket, port: int) -> Optional[str]:
    """Try to read a banner; send a probe first for ports that stay silent."""
    try:
        sock.settimeout(1.5)
        probe = PROBES.get(port)
        if probe:
            sock.sendall(probe)
        data = sock.recv(1024)
        if data:
            return data.decode(errors="replace").strip().split("\n")[0][:200]
    except (socket.timeout, ConnectionResetError, OSError):
        return None
    return None


def scan_port(target_ip: str, port: int, timeout: float = 1.0) -> Optional[PortResult]:
    """Attempt a TCP connect to a single port. Returns None if closed/filtered."""
    start = time.time()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((target_ip, port))
        elapsed_ms = round((time.time() - start) * 1000, 1)
        if result == 0:
            banner = grab_banner(sock, port)
            service = guess_service(port)
            return PortResult(
                port=port,
                state="open",
                service_guess=service,
                banner=banner,
                response_time_ms=elapsed_ms,
            )
        return None
    except (socket.timeout, OSError):
        return None
    finally:
        sock.close()


def scan_target(
    target: str,
    ports: list = None,
    max_threads: int = 100,
    timeout: float = 1.0,
) -> ScanResult:
    """
    Scan a target host across the given ports using a thread pool.
    Returns a ScanResult with all discovered open ports.
    """
    ports = ports or COMMON_PORTS
    resolved_ip = socket.gethostbyname(target)
    result = ScanResult(target=target, resolved_ip=resolved_ip, started_at=time.time())

    work_queue: "queue.Queue[int]" = queue.Queue()
    for p in ports:
        work_queue.put(p)

    lock = threading.Lock()

    def worker():
        while True:
            try:
                port = work_queue.get_nowait()
            except queue.Empty:
                return
            port_result = scan_port(resolved_ip, port, timeout)
            if port_result:
                with lock:
                    result.open_ports.append(port_result)
            work_queue.task_done()

    threads = []
    thread_count = min(max_threads, len(ports))
    for _ in range(thread_count):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    result.open_ports.sort(key=lambda r: r.port)
    result.finished_at = time.time()
    return result


def print_report(result: ScanResult):
    print(f"\nScan target : {result.target} ({result.resolved_ip})")
    print(f"Duration    : {result.duration_seconds}s")
    print(f"Open ports  : {len(result.open_ports)}\n")
    print(f"{'PORT':<8}{'SERVICE':<15}{'BANNER'}")
    print("-" * 60)
    for r in result.open_ports:
        banner = (r.banner or "-")[:40]
        print(f"{r.port:<8}{r.service_guess:<15}{banner}")


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "scanme.nmap.org"
    print(f"Scanning {target} ... (only scan hosts you're authorized to test)")
    res = scan_target(target)
    print_report(res)
