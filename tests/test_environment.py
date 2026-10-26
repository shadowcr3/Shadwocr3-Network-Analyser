from shadowcr3_na.core import runner
from shadowcr3_na.core.environment import check_environment, parse_version


def test_parse_version():
    assert parse_version("7.99") == (7, 99)
    assert parse_version("7.94SVN") == (7, 94)
    assert parse_version("garbage") is None and parse_version(None) is None


def test_ready_environment(fake_nmap):
    env = check_environment(fake_nmap)
    assert env.ready and env.nmap_version == "7.95" and env.problems == ()


def test_missing_nmap(tmp_path, monkeypatch):
    monkeypatch.setattr(runner.shutil, "which", lambda _: None)
    env = check_environment(None)
    assert not env.ready and "not found" in env.problems[0].lower()


def test_old_nmap_is_not_ready(fake_nmap, monkeypatch):
    monkeypatch.setenv("FAKE_NMAP_VERSION", "7.40")
    env = check_environment(fake_nmap)
    assert not env.ready and "older" in env.problems[0]
