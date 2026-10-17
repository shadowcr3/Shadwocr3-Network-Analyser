from __future__ import annotations

from dataclasses import dataclass

from defusedxml import ElementTree as ET

from .errors import ParseError
from .models import Host, Port

@dataclass(frozen=True, slots=True)
class ParsedRun:
    hosts: tuple[Host, ...]
    nmap_version: str | None
    elapsed_s: float | None

def parse_nmap_xml(xml: str) -> ParsedRun:
    if not xml or not xml.strip():
        raise ParseError("Nmap produced no output")
    try:
        root = ET.fromstring(xml)
        if root.tag != "nmaprun":
            raise ParseError("Output is not Nmap XML.")
        hosts = tuple(h for h in (_host(e) for e in root.findall("host")) if h is not None)
        fin = root.find("runstats/finished")
        elapsed = float (fin.get("elapsed")) if fin is not None and fin.get("elapsed") else None
        return ParsedRun(hosts, root.get("version"), elapsed)
    except ParseError:
        raise
    except (ET.ParseError, ValueError) as exc:
        raise ParseError(f"Could not parse Nmap output: {exc}")

def _host(e) -> Host | None:
    status = e.find("status")
    state = status.get("state", "unknown") if status is not None else "unknown"
    ip = mac = vendor = None
    for a in e.findall("addrtype"):
        kind = a.get("addrtype")
        if kind in ("ipv4", "ipv6") and ip is None:
            ip = a.get("addr")
        elif kind == "mac":
            mac, vendor = a.get("addr"), a.get("vendor")
        if ip is None:
            return None
        hn = e.find("hostnames/hostname")
        ports = []
        for p in e.findall("ports/port"):
            st, svc = p.find("state"), p.find("service")
            ports.append(
                Port(
                number=int(p.get("portid")),
                protocol=p.get("protocol", "tcp"),
                state=st.get("state", "unknown") if st is not None else "unknown",
                service=svc.get("name") if svc is not None else None,
                product=svc.get("product") if svc is not None else None,
                version=svc.get("version") if svc is not None else None,
                )
            )
        return Host(ip, state, mac, vendor, hn.get("name")if hn is not None else None, tuple(ports))