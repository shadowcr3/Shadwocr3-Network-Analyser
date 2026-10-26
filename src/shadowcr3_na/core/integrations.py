"""What this install can do: honest availability, versions, capabilities and policy of each tool."""
from __future__ import annotations

from dataclasses import dataclass

from .environment import check_environment
from .importers.tshark import find_tshark, find_wireshark, tshark_version


@dataclass(frozen=True, slots=True)
class IntegrationInfo:
    key: str
    name: str
    mode: str  # active | passive | import | planned
    generates_traffic: bool
    privileges: str
    available: bool
    version: str | None
    capabilities: tuple[str, ...]
    status: str


def discover_integrations(nmap_path: str | None = None, tshark_path: str | None = None,
                          wireshark_path: str | None = None) -> list[IntegrationInfo]:
    env = check_environment(nmap_path)
    nmap = IntegrationInfo(
        "nmap", "Nmap", "active", True, "optional (ARP/MAC need elevation)", env.ready,
        env.nmap_version, ("host discovery", "service detection", "scoped, rate-limited"),
        "ready" if env.ready else (env.problems[0] if env.problems else "unavailable"))
    try:
        ts_path: str | None = find_tshark(tshark_path)
        ts_version = tshark_version(ts_path) if ts_path else None
        tshark = IntegrationInfo(
            "tshark", "TShark / Wireshark", "passive", False, "none (offline file analysis)",
            True, ts_version, ("PCAP/PCAPNG import", "display filters", "structured output"),
            "ready")
    except Exception as exc:  # ToolNotFound
        tshark = IntegrationInfo(
            "tshark", "TShark / Wireshark", "passive", False, "none (offline file analysis)",
            False, None, ("PCAP/PCAPNG import", "display filters"), str(exc))
    viewer = find_wireshark(wireshark_path)
    wireshark = IntegrationInfo(
        "wireshark", "Wireshark (viewer)", "passive", False, "none", viewer is not None, None,
        ("open a capture in Wireshark",),
        "ready" if viewer else "not installed (optional)")
    return [
        nmap, tshark, wireshark,
        IntegrationInfo("suricata", "Suricata (EVE JSON import)", "import", False, "none", True,
                        None, ("alert import", "severity and signature preserved"),
                        "ready (file import; Suricata itself is not required)"),
        IntegrationInfo("zeek", "Zeek (conn.log import)", "import", False, "none", True, None,
                        ("TSV and JSON conn.log", "conversation aggregation"),
                        "ready (file import; Zeek itself is not required)"),
        IntegrationInfo("greenbone", "Greenbone Community Edition", "planned", False, "n/a",
                        False, None, ("vulnerability report import",), "planned, not implemented"),
        IntegrationInfo("osint", "SpiderFoot / Amass", "planned", False, "n/a", False, None,
                        ("OSINT finding import",), "planned, not implemented"),
    ]
