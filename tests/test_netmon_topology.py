from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from shadowcr3_na.core import netmon
from shadowcr3_na.core.errors import MetricsUnavailable
from shadowcr3_na.core.integrations import discover_integrations
from shadowcr3_na.core.records import AssetRow, ConnectionRow
from shadowcr3_na.core.topology import (
    PARTIAL_NOTICE,
    build_topology,
    circular_layout,
    filter_topology,
    is_recent,
)

T0 = datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc)


def counters(rx, tx, prx, ptx):
    return SimpleNamespace(bytes_recv=rx, bytes_sent=tx, packets_recv=prx, packets_sent=ptx)


class Feed:
    def __init__(self):
        self.now, self.data = 100.0, {}

    def __call__(self):
        return self.data

    def clock(self):
        return self.now


def test_rates_need_a_baseline_then_are_computed_from_deltas():
    feed = Feed()
    sampler = netmon.InterfaceSampler(feed, feed.clock)
    feed.data = {"eth0": counters(1000, 500, 10, 5)}
    assert sampler.sample("eth0") is None  # no baseline yet: never invent a number
    feed.now, feed.data = 102.0, {"eth0": counters(3000, 1500, 30, 15)}
    s = sampler.sample("eth0")
    assert (s.rx_bps, s.tx_bps, s.rx_pps, s.tx_pps, s.interval_s) == (8000.0, 4000.0, 10.0, 5.0, 2.0)
    assert s.source == "interface counters (psutil)" and s.note is None
    assert sampler.history("eth0") == [s]


def test_counter_reset_is_reported_not_turned_into_a_rate():
    feed = Feed()
    sampler = netmon.InterfaceSampler(feed, feed.clock)
    feed.data = {"eth0": counters(5000, 5000, 50, 50)}
    sampler.sample("eth0")
    feed.now, feed.data = 101.0, {"eth0": counters(10, 10, 1, 1)}
    s = sampler.sample("eth0")
    assert s.rx_bps is None and s.note == "counter reset"


def test_unknown_interface_and_bounded_history():
    feed = Feed()
    sampler = netmon.InterfaceSampler(feed, feed.clock, history=3)
    feed.data = {"eth0": counters(0, 0, 0, 0)}
    assert sampler.sample("nope") is None
    sampler.sample("eth0")
    for i in range(1, 8):
        feed.now += 1
        feed.data = {"eth0": counters(i * 100, 0, i, 0)}
        sampler.sample("eth0")
    assert len(sampler.history("eth0")) == 3
    sampler.clear()
    assert sampler.history("eth0") == []


def test_metrics_unavailable_is_an_error_not_zero(monkeypatch):
    def broken():
        raise MetricsUnavailable("no counters")

    sampler = netmon.InterfaceSampler(broken)
    with pytest.raises(MetricsUnavailable):
        sampler.sample("eth0")


def test_real_psutil_lists_interfaces():
    ifaces = netmon.list_interfaces()
    assert ifaces and all(isinstance(i.name, str) for i in ifaces)


def test_format_rate():
    assert netmon.format_rate(None) == "n/a"
    assert netmon.format_rate(850) == "850 bit/s"
    assert netmon.format_rate(12_500) == "12.5 Kbit/s"
    assert netmon.format_rate(3_400_000) == "3.4 Mbit/s"
    assert netmon.format_rate(5_000_000_000) == "5.0 Gbit/s"
    assert netmon.format_rate(1200, "pkt/s") == "1.2 Kpkt/s"


def asset(i, ip, **kw):
    return AssetRow(i, ip, kw.get("mac"), None, kw.get("hostname"),
                    kw.get("first", T0 - timedelta(days=30)), T0, kw.get("sources", ("scan",)),
                    kw.get("uncertain", False), None)


def conn(i, src, dst, proto="tcp", port=443, pk=10, by=1000, last=T0, kind="observed", imp=1):
    return ConnectionRow(i, src, dst, proto, port, last - timedelta(minutes=5), last, pk, by, 1,
                         kind, imp)


@pytest.fixture
def topo():
    assets = [asset(1, "10.0.0.1", hostname="router.lan"), asset(2, "10.0.0.5"),
              asset(3, "10.0.0.7", first=T0 - timedelta(hours=1)), asset(4, "10.0.0.99")]
    conns = [conn(1, "10.0.0.5", "10.0.0.1", "udp", 53), conn(2, "10.0.0.5", "93.184.216.34"),
             conn(3, "10.0.0.5", "93.184.216.34", "udp", 443, 5, 50),
             conn(4, "10.0.0.7", "10.0.0.1", "tcp", 22, last=T0 - timedelta(days=2))]
    return build_topology(assets, conns)


def test_topology_marks_external_nodes_and_never_claims_completeness(topo):
    kinds = {n.id: n.kind for n in topo.nodes}
    assert kinds["93.184.216.34"] == "external" and kinds["10.0.0.5"] == "asset"
    assert topo.notice == PARTIAL_NOTICE and "complete" in topo.notice
    assert topo.components == 2  # 10.0.0.99 has no observed relationship
    edge = next(e for e in topo.edges if e.dst == "93.184.216.34")
    assert edge.protocols == ("tcp", "udp") and edge.packets == 15 and edge.bytes == 1050
    assert edge.kind == "observed" and edge.import_ids == (1,)


def test_filters_by_text_protocol_and_period(topo):
    assert {n.id for n in filter_topology(topo, text="router").nodes} == {
        "10.0.0.1", "10.0.0.5", "10.0.0.7"}
    udp = filter_topology(topo, protocol="udp")
    assert {(e.src, e.dst) for e in udp.edges} == {("10.0.0.5", "10.0.0.1"),
                                                   ("10.0.0.5", "93.184.216.34")}
    recent = filter_topology(topo, since=T0 - timedelta(hours=1))
    assert all(e.last_seen >= T0 - timedelta(hours=1) for e in recent.edges)
    assert "10.0.0.7" not in {n.id for n in recent.nodes}
    assert filter_topology(topo, text="zzz").nodes == () and recent.notice == PARTIAL_NOTICE


def test_new_assets_are_highlighted(topo):
    node = {n.id: n for n in topo.nodes}
    assert is_recent(node["10.0.0.7"], timedelta(hours=24), now=T0)
    assert not is_recent(node["10.0.0.5"], timedelta(hours=24), now=T0)
    assert not is_recent(node["93.184.216.34"], timedelta(hours=24), now=T0)


def test_layout_is_deterministic_and_covers_every_node(topo):
    a, b = circular_layout(topo), circular_layout(topo)
    assert a == b and set(a) == {n.id for n in topo.nodes}
    assert len(set(a.values())) == len(a)  # no two nodes on the same point
    assert circular_layout(build_topology([], [])) == {}


def test_integrations_report_honest_availability(fake_nmap, fake_tshark, tmp_path):
    items = {i.key: i for i in discover_integrations(fake_nmap, fake_tshark,
                                                     str(tmp_path / "no-wireshark"))}
    assert items["nmap"].available and items["nmap"].mode == "active" and items["nmap"].generates_traffic
    assert items["tshark"].available and items["tshark"].version == "4.2.2"
    assert not items["tshark"].generates_traffic
    assert not items["wireshark"].available
    assert items["suricata"].mode == "import" and items["zeek"].available
    assert not items["greenbone"].available and "not implemented" in items["greenbone"].status
    missing = {i.key: i for i in discover_integrations(str(tmp_path / "nope"), str(tmp_path / "nope"))}
    assert not missing["nmap"].available and not missing["tshark"].available
