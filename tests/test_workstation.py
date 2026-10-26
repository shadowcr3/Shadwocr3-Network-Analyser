import hashlib
import json
import shutil
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

pytest.importorskip("PySide6")

from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication, QInputDialog, QMessageBox  # noqa: E402

from helpers import wait_for  # noqa: E402
from pcapgen import SAMPLE, make_pcap  # noqa: E402
from shadowcr3_na.core.errors import MetricsUnavailable  # noqa: E402
from shadowcr3_na.core.importers.zeek import parse_zeek_conn  # noqa: E402
from shadowcr3_na.core.netmon import InterfaceInfo, InterfaceSampler  # noqa: E402
from shadowcr3_na.gui.charts import LineChart, nice_max  # noqa: E402
from shadowcr3_na.gui.pages import packets as packets_mod  # noqa: E402
from shadowcr3_na.gui.pages.alerts import AlertsPage  # noqa: E402
from shadowcr3_na.gui.pages.assets import AssetsPage  # noqa: E402
from shadowcr3_na.gui.pages.dashboard import DashboardPage  # noqa: E402
from shadowcr3_na.gui.pages.integrations import IntegrationsPage  # noqa: E402
from shadowcr3_na.gui.pages.investigations import InvestigationsPage  # noqa: E402
from shadowcr3_na.gui.pages.packets import PacketsPage  # noqa: E402
from shadowcr3_na.gui.pages.topology import NodeItem, TopologyPage  # noqa: E402
from shadowcr3_na.gui.theme import THEMES, apply_theme  # noqa: E402
from shadowcr3_na.gui.workstation import Workstation  # noqa: E402
from shadowcr3_na.storage import audit  # noqa: E402
from shadowcr3_na.storage import inventory as inv  # noqa: E402
from shadowcr3_na.storage import investigations as inves  # noqa: E402
from shadowcr3_na.storage.db import connect  # noqa: E402
from test_importers import ALERT, ZEEK_TSV, write_lines  # noqa: E402
from test_pdf_reports import pdf_text  # noqa: E402

YES, NO = QMessageBox.StandardButton.Yes, QMessageBox.StandardButton.No

# Pages that own background threads must be shut down before they are garbage-collected,
# exactly as Workstation.closeEvent does. Qt aborts if a running QThread's owner is destroyed.
_TRACKED: list = []


def track(page):
    _TRACKED.append(page)
    return page


@pytest.fixture(autouse=True)
def _shutdown_tracked_pages():
    yield
    for page in _TRACKED:
        page.shutdown()
        wait_for(lambda p=page: not p._tasks.busy, 10)
    _TRACKED.clear()


@pytest.fixture
def conn():
    c = connect(":memory:")
    yield c
    c.close()


@pytest.fixture
def zeek_log(tmp_path):
    path = tmp_path / "conn.log"
    path.write_text(ZEEK_TSV)
    return path


@pytest.fixture
def eve_file(tmp_path):
    sev = [json.dumps({**ALERT, "alert": {**ALERT["alert"], "severity": s, "signature": f"sig-{s}"}})
           for s in (3, 1, 2)]
    return write_lines(tmp_path, sev)


def events(conn):
    return [e.event for e in reversed(audit.list_events(conn))]


def answer_question(monkeypatch, button):
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: button)


def pick_investigation(monkeypatch, title):
    monkeypatch.setattr(QInputDialog, "getItem", lambda *a, **k: (title, True))


# ---- dashboard and chart ----------------------------------------------------------------


class Feed:
    def __init__(self):
        self.now, self.data = 10.0, {}

    def __call__(self):
        return self.data

    def clock(self):
        return self.now


def counters(rx, tx, prx, ptx):
    return SimpleNamespace(bytes_recv=rx, bytes_sent=tx, packets_recv=prx, packets_sent=ptx)


def test_nice_max_and_chart_paints(qapp):
    assert nice_max([]) == 1.0 and nice_max([None, 0]) == 1.0
    assert nice_max([3, 7]) == 10.0 and nice_max([120]) == 200.0 and nice_max([0.4]) == 0.5
    chart = LineChart("Throughput", lambda v: "n/a" if v is None else f"{v:.0f}", ("A", "B"))
    chart.resize(500, 200)
    chart.set_data([[1, None, 3, 4], [2, 2, 2, 2]])
    assert not chart.grab().isNull() and chart.message is None
    chart.set_message("Unavailable: nope")
    assert chart.message == "Unavailable: nope" and not chart.grab().isNull()


def test_dashboard_charts_tiles_and_honest_labels(qapp, conn, zeek_log):
    inv.save_connection_import(conn, "zeek_conn", str(zeek_log), parse_zeek_conn(zeek_log))
    feed = Feed()
    sampler = InterfaceSampler(feed, feed.clock)
    ifaces = lambda: [InterfaceInfo("lo", True, None, 65536), InterfaceInfo("eth0", True, 1000, 1500)]  # noqa: E731
    page = DashboardPage(conn, sampler, ifaces)
    assert page._iface_box.currentData() == "eth0"  # prefers a real interface over loopback
    assert page._tiles["assets"].text() == "3" and page._tiles["last_scan"].text() == "never"
    feed.data = {"eth0": counters(0, 0, 0, 0)}
    page.tick()
    feed.now, feed.data = 11.0, {"eth0": counters(125_000, 50_000, 100, 40)}
    page.tick()
    assert page._throughput.data[0] == [1_000_000.0] and page._throughput.data[1] == [400_000.0]
    status = page._status.text()
    assert "interface counters" in status and "not a packet capture" in status
    feed.now, feed.data = 12.0, {"eth0": counters(5, 5, 1, 1)}
    page.tick()
    assert "counter reset" in page._status.text() and page._throughput.data[0][-1] is None
    page._last_ok -= 60
    page._redraw()
    assert page._status.text().startswith("STALE")


def test_dashboard_reports_unavailable_metrics(qapp, conn):
    def broken():
        raise MetricsUnavailable("psutil missing")

    page = DashboardPage(conn, InterfaceSampler(broken), lambda: [InterfaceInfo("eth0", True, None, None)])
    page.tick()
    assert "unavailable" in page._status.text().lower() and "Unavailable" in (page._throughput.message or "")
    no_ifaces = DashboardPage(conn, interfaces_fn=lambda: (_ for _ in ()).throw(MetricsUnavailable("none")))
    assert "unavailable" in no_ifaces._status.text().lower()


def test_dashboard_samples_only_while_visible(qapp, conn):
    page = DashboardPage(conn, InterfaceSampler(lambda: {}), lambda: [])
    assert not page._timer.isActive()
    page.show()
    assert page._timer.isActive()
    page.hide()
    assert not page._timer.isActive()


# ---- topology -------------------------------------------------------------------------------


def test_topology_page_builds_filters_and_explains_evidence(qapp, conn, zeek_log, monkeypatch):
    inv.save_connection_import(conn, "zeek_conn", str(zeek_log), parse_zeek_conn(zeek_log))
    page = track(TopologyPage(conn))
    assert page._view.node_count() == 4 and page._view.edge_count() == 2
    assert "Partial view" in page._notice.text() and "complete map" in page._notice.text()
    assert page._proto.findData("tcp") >= 0
    page._search.setText("93.184")
    assert page._view.node_count() == 2
    page._search.setText("")
    assert page._view.select_node("10.0.0.5")
    assert "Asset: 10.0.0.5" in page._details.toPlainText() and page._add_btn.isEnabled()
    assert page._view.select_node("93.184.216.34")
    assert "External address" in page._details.toPlainText() and not page._add_btn.isEnabled()
    page._on_edge("10.0.0.5", "93.184.216.34")
    detail = page._details.toPlainText()
    assert "Observed relationship" in detail and "443" in detail and "zeek_conn" in detail
    pick_investigation(monkeypatch, "From topology")
    page._add_to_investigation()
    iid = inves.find_by_title(conn, "From topology")
    assert [i.kind for i in inves.list_items(conn, iid)] == ["connection"]


def test_new_assets_are_highlighted(qapp, conn):
    now = datetime.now(timezone.utc)
    with conn:
        inv.upsert_asset(conn, "10.0.0.5", source="x", first_seen=now - timedelta(minutes=5))
        inv.upsert_asset(conn, "10.0.0.6", source="x", first_seen=now - timedelta(days=30))
        conn.execute("INSERT INTO connections (src, dst, protocol, first_seen, last_seen, kind)"
                     " VALUES ('10.0.0.5','10.0.0.6','tcp',?,?,'observed')",
                     (now.isoformat(), now.isoformat()))
    page = track(TopologyPage(conn))
    page._highlight.setCurrentIndex(page._highlight.findData(24))
    widths = {i.node.id: i.pen().width() for i in page._view._scene.items() if isinstance(i, NodeItem)}
    assert widths["10.0.0.5"] == 4 and widths["10.0.0.6"] == 1


def test_zeek_import_runs_off_thread_and_is_audited(qapp, conn, zeek_log):
    page = track(TopologyPage(conn))
    assert page._view.node_count() == 0
    assert page.import_zeek(str(zeek_log))
    assert wait_for(lambda: page._view.node_count() == 4)
    assert "import_completed" in events(conn)
    done = audit.list_events(conn)[0]
    assert done.details["kind"] == "zeek_conn" and len(done.details["sha256"]) == 64


def test_bad_import_reports_failure_without_data(qapp, conn, tmp_path):
    page = track(TopologyPage(conn))
    assert page.import_zeek(str(tmp_path / "missing.log"))
    assert wait_for(lambda: "Import failed" in page._notice.text())
    assert inv.list_connections(conn) == []


# ---- assets -------------------------------------------------------------------------------------


def test_assets_page_sorts_numerically_flags_uncertainty_and_filters(qapp, conn, monkeypatch):
    t = datetime(2026, 10, 24, tzinfo=timezone.utc)
    with conn:
        for ip in ("10.0.0.100", "10.0.0.2", "10.0.0.30"):
            inv.upsert_asset(conn, ip, source="s", first_seen=t, hostname=f"h-{ip}")
        inv.upsert_asset(conn, "10.0.0.2", source="s2", first_seen=t, mac="AA")
        inv.upsert_asset(conn, "10.0.0.2", source="s3", first_seen=t, mac="BB")
    page = AssetsPage(conn)
    page._table.sortItems(0, Qt.SortOrder.AscendingOrder)
    assert [page._table.item(r, 0).text() for r in range(3)] == ["10.0.0.2", "10.0.0.30", "10.0.0.100"]
    assert page._table.item(0, 7).text() == "UNCERTAIN"
    page._table.selectRow(0)
    assert "UNCERTAIN" in page._details.toPlainText() and page._add_btn.isEnabled()
    page._search.setText("h-10.0.0.30")
    assert [page._table.isRowHidden(r) for r in range(3)] == [True, False, True]
    pick_investigation(monkeypatch, "Asset case")
    page._add_to_investigation()
    assert inves.list_items(conn, inves.find_by_title(conn, "Asset case"))[0].kind == "asset"


# ---- packets ---------------------------------------------------------------------------------------


@pytest.fixture
def pcap(tmp_path):
    return make_pcap(tmp_path / "sample.pcap", SAMPLE)


def fake_output(tmp_path, monkeypatch):
    out = tmp_path / "out.tsv"
    out.write_text("1\t1761300000.0\t10.0.0.5\t\t10.0.0.1\t\tDNS\t60\tquery\t\t53\n"
                   "2\t1761300001.0\t10.0.0.5\t\t93.184.216.34\t\tTCP\t60\tSYN\t443\t\n"
                   "3\t1761300002.0\t\t\t\t\tARP\t42\tWho has\t\t\n")
    monkeypatch.setenv("FAKE_TSHARK_OUTPUT", str(out))


def test_packets_page_offline_analysis_with_provenance(qapp, conn, pcap, fake_tshark, tmp_path, monkeypatch):
    fake_output(tmp_path, monkeypatch)
    page = track(PacketsPage(conn, tshark_path=fake_tshark, wireshark_path=str(tmp_path / "nope")))
    assert not page._ws_btn.isEnabled() and not page._topo_btn.isEnabled()
    assert page.open_capture(str(pcap))
    assert wait_for(lambda: page._model.rowCount() == 3)
    assert "no packets were captured" in page._status.text() and "SHA-256" in page._status.text()
    opened = audit.list_events(conn)[0]
    assert opened.event == "capture_opened" and opened.details["sha256"] == hashlib.sha256(
        pcap.read_bytes()).hexdigest()
    page._search.setText("DNS")
    assert page._proxy.rowCount() == 1
    page._search.setText("")
    assert page._topo_btn.isEnabled()
    page._add_to_topology()
    conns = inv.list_connections(conn)
    assert {(c.src, c.dst) for c in conns} == {("10.0.0.5", "10.0.0.1"), ("10.0.0.5", "93.184.216.34")}
    assert audit.list_events(conn)[0].details["kind"] == "pcap"
    assert {a.ip for a in inv.list_assets(conn)} == {"10.0.0.5", "10.0.0.1"}  # external stays external


def test_packets_page_rejects_non_captures_and_audits_it(qapp, conn, tmp_path, fake_tshark):
    bad = tmp_path / "evil.pcap"
    bad.write_text("not a capture")
    page = track(PacketsPage(conn, tshark_path=fake_tshark))
    page.open_capture(str(bad))
    assert wait_for(lambda: "Could not read" in page._status.text())
    assert "not a PCAP" in page._status.text() and "capture_failed" in events(conn)


def test_wireshark_launch_uses_an_argument_list(qapp, conn, pcap, fake_tshark, tmp_path, monkeypatch):
    fake_output(tmp_path, monkeypatch)
    viewer = tmp_path / "wireshark"
    viewer.write_text("")
    launched = []
    monkeypatch.setattr(packets_mod, "subprocess",
                        SimpleNamespace(Popen=lambda args, **k: launched.append(args)))
    page = track(PacketsPage(conn, tshark_path=fake_tshark, wireshark_path=str(viewer)))
    page.open_capture(str(pcap))
    assert wait_for(lambda: page._model.rowCount() == 3)
    assert page._ws_btn.isEnabled()
    page._ws_btn.click()
    assert launched == [[str(viewer), "-r", str(pcap)]] and "wireshark_opened" in events(conn)


@pytest.mark.skipif(shutil.which("tshark") is None, reason="real tshark not installed")
def test_packets_page_with_real_tshark_and_filter(qapp, conn, pcap):
    page = track(PacketsPage(conn))
    page._filter.setText("tcp")
    page.open_capture(str(pcap))
    assert wait_for(lambda: page._model.rowCount() == 3)
    assert "for filter tcp" in page._status.text()
    page._filter.setText("not a valid filter ((")
    page._reload()
    assert wait_for(lambda: "Could not read" in page._status.text())


# ---- alerts, investigations, integrations ----------------------------------------------------------------


def test_alerts_import_triage_and_evidence(qapp, conn, eve_file, monkeypatch):
    page = track(AlertsPage(conn))
    assert page.import_eve(str(eve_file))
    assert wait_for(lambda: page._table.rowCount() == 3)
    assert [page._table.item(r, 2).text() for r in range(3)] == ["sig-1", "sig-2", "sig-3"]  # severity order
    assert "not confirmation of an incident" in page._info.text()
    page._table.selectRow(0)
    detail = page._details.toPlainText()
    assert "indicator" in detail and "sha256" in detail and "Original event" in detail
    page.set_status("acknowledged")
    page.set_note(inv.list_alerts(conn)[0].id, "owner says it is their scanner")
    assert [e for e in events(conn) if e.startswith("alert_")] == ["alert_status_changed", "alert_note_changed"]
    changed = audit.list_events(conn)[1]
    assert changed.details["from_status"] == "new" and changed.details["to_status"] == "acknowledged"
    page._status_box.setCurrentIndex(page._status_box.findData("acknowledged"))
    assert page._table.rowCount() == 1
    pick_investigation(monkeypatch, "Alert case")
    page._table.selectRow(0)
    page._add_to_investigation()
    assert inves.list_items(conn, inves.find_by_title(conn, "Alert case"))[0].kind == "alert"


def test_alert_import_failure_and_partial_files_are_reported(qapp, conn, tmp_path):
    page = track(AlertsPage(conn))
    page.import_eve(str(tmp_path / "missing.json"))
    assert wait_for(lambda: "Import failed" in page._info.text())
    mixed = write_lines(tmp_path, [json.dumps(ALERT), "garbage", json.dumps({"event_type": "flow"})], "m.json")
    page.import_eve(str(mixed))
    assert wait_for(lambda: page._table.rowCount() == 1)
    assert "1 malformed" in page._info.text() and "1 non-alert" in page._info.text()


def test_investigation_lifecycle_and_report_export(qapp, conn, eve_file, tmp_path, monkeypatch):
    alerts = track(AlertsPage(conn))
    alerts.import_eve(str(eve_file))
    assert wait_for(lambda: alerts._table.rowCount() == 3)
    page = InvestigationsPage(conn)
    iid = page.create_investigation("Incident 7")
    inves.add_item(conn, iid, "alert", inv.list_alerts(conn)[0].id, "first look")
    page.refresh()
    assert page._items.rowCount() == 1 and "sig-1" in page._items.item(0, 2).text()
    page._notes.setPlainText("Concluded: benign scanner.")
    page._save_btn.click()
    page._status_box.setCurrentIndex(page._status_box.findData("closed"))
    page._status_box.activated.emit(page._status_box.currentIndex())
    assert inves.get_investigation(conn, iid).status == "closed"
    out = tmp_path / "report.pdf"
    page.export_to(str(out))
    text = pdf_text(out)
    assert "Concluded: benign scanner." in text and "indicators that require interpretation" in text
    done = audit.list_events(conn)[0]
    assert done.event == "report_exported" and done.details["sha256"] == hashlib.sha256(
        out.read_bytes()).hexdigest()
    page.export_to(str(tmp_path / "report.md"))
    assert "Export failed" in page._info.text()
    answer_question(monkeypatch, YES)
    page._delete_btn.click()
    assert inves.list_investigations(conn) == []


def test_integrations_page_is_honest_and_import_removal_is_audited(
        qapp, conn, zeek_log, fake_nmap, fake_tshark, tmp_path, monkeypatch):
    inv.save_connection_import(conn, "zeek_conn", str(zeek_log), parse_zeek_conn(zeek_log))
    page = IntegrationsPage(conn, fake_nmap, fake_tshark, str(tmp_path / "nope"))
    rows = {page._tools.item(r, 0).text(): r for r in range(page._tools.rowCount())}
    assert len(rows) == 7
    greenbone = rows["Greenbone Community Edition"]
    assert page._tools.item(greenbone, 4).text() == "no" and "not implemented" in page._tools.item(greenbone, 7).text()
    assert page._tools.item(rows["Nmap"], 4).text() == "yes" and page._tools.item(rows["Nmap"], 2).text() == "yes"
    assert "Nothing is uploaded" in page._health.text() and "Unfinished jobs" in page._health.text()
    assert page._imports.rowCount() == 1 and not page._remove_btn.isEnabled()
    page._imports.selectRow(0)
    answer_question(monkeypatch, NO)
    page._remove_btn.click()
    assert inv.list_connections(conn)
    answer_question(monkeypatch, YES)
    page._remove_btn.click()
    assert inv.list_connections(conn) == [] and audit.list_events(conn)[0].event == "import_deleted"


# ---- the unified shell -------------------------------------------------------------------------------------


@pytest.fixture
def station(qapp, conn, fake_nmap, fake_tshark, guard, tmp_path):
    feed = Feed()
    w = Workstation(conn, nmap_path=fake_nmap, tshark_path=fake_tshark,
                    wireshark_path=str(tmp_path / "nope"), guard=guard,
                    sampler=InterfaceSampler(feed, feed.clock))
    yield w
    w.close()


def test_navigation_shortcuts_and_pages(station):
    assert station._nav.count() == 8 and station._stack.count() == 8
    names = [station._nav.item(i).text().split("  ")[0] for i in range(8)]
    assert names == ["Dashboard", "Topology", "Assets", "Packets", "Alerts", "Reconnaissance",
                     "Investigations", "Integrations"]
    shortcuts = {a.shortcut().toString() for a in station.actions()}
    assert {f"Ctrl+{n}" for n in range(1, 9)} <= shortcuts
    station.show_page(4)
    assert station.current_page() is station.alerts
    station.show_page(5)
    assert station.current_page() is station.recon


def test_data_flows_between_workspaces(station, conn, eve_file, zeek_log):
    station.alerts.import_eve(str(eve_file))
    assert wait_for(lambda: station.dashboard._tiles["alerts_open"].text() == "3")
    station.topology.import_zeek(str(zeek_log))
    assert wait_for(lambda: station.topology._view.node_count() == 4)
    assert station.dashboard._tiles["connections"].text() == "2"
    assert station.assets._table.rowCount() >= 3


def test_a_scan_in_reconnaissance_feeds_assets_and_dashboard(station, conn):
    r = station.recon
    r._target_edit.setText("192.168.1.5")
    r._auth_box.setChecked(True)
    r._scan_btn.click()
    assert wait_for(lambda: r._thread is None and station.assets._table.rowCount() == 2)
    assert station.dashboard._tiles["assets"].text() == "2" and station.dashboard._tiles["scans"].text() == "1"
    assert "scan_completed" in events(conn)


def test_themes_apply_and_menus_exist(station, qapp, monkeypatch):
    for name in THEMES:
        station.set_theme(name)
    assert [m.title() for m in station.menuBar().findChildren(type(station.menuBar().addMenu("x")))][:1]
    shown = []
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: shown.append(a[2]))
    station._about()
    assert "authorised" in shown[0] and "indicators" in shown[0]
    with pytest.raises(ValueError):
        apply_theme(QApplication.instance(), "neon")
    apply_theme(QApplication.instance(), "system")


def test_closing_the_workstation_cancels_a_running_scan(station, conn, monkeypatch):
    monkeypatch.setenv("FAKE_NMAP_SLEEP", "30")
    r = station.recon
    r._target_edit.setText("192.168.1.5")
    r._auth_box.setChecked(True)
    r._scan_btn.click()
    assert r._thread is not None
    station.close()
    assert audit.list_events(conn)[0].details["reason"] == "window_closed"
