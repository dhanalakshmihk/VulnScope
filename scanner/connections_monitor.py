"""
VulnScope Connections Monitor
-------------------------------
Shows live active network connections on THIS machine — which local
process is talking to which remote address/port, and the connection
state. Useful for spotting something unexpected phoning home.

Cross-platform via psutil. On some systems, process name lookup for
connections owned by other users may require elevated permissions;
we degrade gracefully (show "unknown") rather than crash.
"""

import psutil
from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class ConnectionInfo:
    pid: Optional[int]
    process_name: Optional[str]
    local_addr: str
    local_port: int
    remote_addr: Optional[str]
    remote_port: Optional[int]
    status: str  # ESTABLISHED, LISTEN, TIME_WAIT, etc.
    is_remote: bool  # True if there's an active remote peer (vs just listening)


def _process_name(pid: Optional[int]) -> Optional[str]:
    if pid is None:
        return None
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "unknown"


def get_live_connections(kind: str = "inet") -> list[ConnectionInfo]:
    """
    Returns all current network connections on this machine.
    kind: 'inet' (TCP+UDP, v4+v6), 'tcp', or 'udp'
    """
    results = []
    try:
        conns = psutil.net_connections(kind=kind)
    except psutil.AccessDenied:
        # Some platforms require admin/root for full visibility.
        # Fall back to per-process connections, which usually works
        # without elevation for at least the current user's processes.
        conns = []
        for proc in psutil.process_iter(["pid"]):
            try:
                conns.extend(proc.net_connections(kind=kind))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    for c in conns:
        laddr = c.laddr
        raddr = c.raddr
        if not laddr:
            continue
        results.append(ConnectionInfo(
            pid=c.pid,
            process_name=_process_name(c.pid),
            local_addr=laddr.ip,
            local_port=laddr.port,
            remote_addr=raddr.ip if raddr else None,
            remote_port=raddr.port if raddr else None,
            status=c.status,
            is_remote=bool(raddr),
        ))

    # Most interesting first: active remote connections, then listeners
    results.sort(key=lambda r: (not r.is_remote, r.status != "ESTABLISHED"))
    return results


def summarize_connections(connections: list[ConnectionInfo]) -> dict:
    """Quick counts for a dashboard summary card."""
    established = sum(1 for c in connections if c.status == "ESTABLISHED")
    listening = sum(1 for c in connections if c.status == "LISTEN")
    unique_remotes = len({c.remote_addr for c in connections if c.remote_addr})
    return {
        "total": len(connections),
        "established": established,
        "listening": listening,
        "unique_remote_hosts": unique_remotes,
    }


if __name__ == "__main__":
    conns = get_live_connections()
    summary = summarize_connections(conns)
    print(f"Connections: {summary}\n")
    print(f"{'PID':<8}{'PROCESS':<20}{'LOCAL':<22}{'REMOTE':<22}{'STATUS'}")
    print("-" * 90)
    for c in conns[:25]:
        local = f"{c.local_addr}:{c.local_port}"
        remote = f"{c.remote_addr}:{c.remote_port}" if c.remote_addr else "-"
        print(f"{c.pid or '-':<8}{(c.process_name or '-'):<20}{local:<22}{remote:<22}{c.status}")