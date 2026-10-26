from pathlib import Path

import pytest

from shadowcr3_na.core.errors import ParseError
from shadowcr3_na.core.parser import parse_nmap_xml

FIXTURES = Path(__file__).parent / "fixtures"

SERVICES = """<?xml version="1.0"?>
<nmaprun version="7.95">
<host><status state="up"/>
<address addr="192.168.1.20" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.6"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
<port protocol="tcp" portid="443"><state state="closed"/></port>
</ports></host>
<runstats><finished elapsed="5.02" exit="success"/></runstats>
</nmaprun>"""

ENTITY = """<?xml version="1.0"?>
<!DOCTYPE nmaprun [<!ENTITY x "boom">]>
<nmaprun version="7.95"><host><address addr="&x;" addrtype="ipv4"/></host></nmaprun>"""


def test_discovery_fixture():
    run = parse_nmap_xml((FIXTURES / "discovery.xml").read_text(encoding="utf-8"))
    assert (run.nmap_version, run.elapsed_s, run.finished_ok) == ("7.95", 2.31, True)
    first, second = run.hosts
    assert (first.ip, first.state, first.mac, first.vendor, first.hostname) == (
        "192.168.1.1", "up", "AA:BB:CC:00:11:22", "TP-Link", "router.lan")
    assert second.hostname is None and second.vendor is None


def test_ports_and_open_filter():
    (host,) = parse_nmap_xml(SERVICES).hosts
    assert [(p.number, p.state, p.service) for p in host.ports] == [
        (22, "open", "ssh"), (80, "open", "http"), (443, "closed", None)]
    assert [p.number for p in host.open_ports] == [22, 80]
    assert host.ports[0].product == "OpenSSH" and host.ports[0].version == "9.6"


@pytest.mark.parametrize("xml", [
    "", "   ", "not xml", "<html/>",
    ("<nmaprun><host><address addr='1.1.1.1' addrtype='ipv4'/>"
     "<ports><port portid='x'/></ports></host></nmaprun>"),
])
def test_bad_input_raises_parse_error(xml):
    with pytest.raises(ParseError):
        parse_nmap_xml(xml)


def test_entity_declarations_are_rejected():
    with pytest.raises(ParseError):
        parse_nmap_xml(ENTITY)


def test_zero_hosts_is_a_valid_result_and_missing_summary_is_unknown():
    run = parse_nmap_xml("<nmaprun version='7.95'/>")
    assert run.hosts == () and run.finished_ok is None


def test_failed_finish_is_reported():
    run = parse_nmap_xml("<nmaprun><runstats><finished exit='error'/></runstats></nmaprun>")
    assert run.finished_ok is False


def test_host_without_ip_is_dropped():
    assert parse_nmap_xml("<nmaprun><host><status state='up'/></host></nmaprun>").hosts == ()
