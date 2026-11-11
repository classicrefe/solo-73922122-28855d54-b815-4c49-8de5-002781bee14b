"""采集功能的 FastAPI 接口测试。"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.collector import ingest
from app.collector.config import get_settings
from app.main import app


def record(seq: int, **overrides) -> dict:
    rec = {
        "ts": 1700000000 + seq,
        "src_ip": f"10.0.0.{seq + 1}",
        "dst_ip": "192.168.10.20",
        "dst_port": 443,
        "rule_id": "FW-DENY-101",
    }
    rec.update(overrides)
    return rec


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    log_dir = tmp_path / "logs"
    data_dir = tmp_path / "data"
    log_dir.mkdir()
    data_dir.mkdir()
    monkeypatch.setenv("DENY_LOG_DIR", str(log_dir))
    monkeypatch.setenv("DENY_DB_PATH", str(data_dir / "deny.db"))
    monkeypatch.setenv("DENY_LOCK_PATH", str(data_dir / "collector.lock"))
    return TestClient(app)


def write_log(log_dir: Path, name: str, rows: list[dict]) -> Path:
    p = log_dir / name
    with open(p, "ab") as fh:
        for r in rows:
            fh.write((json.dumps(r) + "\n").encode())
    return p


def test_collect_page_served(client: TestClient) -> None:
    resp = client.get("/deny")
    assert resp.status_code == 200
    assert "阻断连接采集" in resp.text


def test_collect_and_events_pagination(client: TestClient) -> None:
    settings = get_settings()
    write_log(settings.log_dir, "deny.log", [record(i) for i in range(25)])

    resp = client.post("/api/deny/collect")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["eventsInserted"] == 25

    resp = client.get("/api/deny/events?page=1&page_size=20")
    data = resp.json()
    assert data["total"] == 25 and data["totalPages"] == 2
    assert len(data["items"]) == 20
    item = data["items"][0]
    assert item["srcIp"] == "10.0.0.1"
    assert item["ruleId"] == "FW-DENY-101"
    assert item["tsIso"].endswith("Z")
    # 来源位置完整
    assert item["source"]["file"] == "deny.log"
    assert item["source"]["lineNo"] == 1
    assert item["source"]["lineOffset"] == 0

    resp2 = client.get("/api/deny/events?page=2&page_size=20")
    assert len(resp2.json()["items"]) == 5

    resp3 = client.get("/api/deny/events?page_size=10")
    assert len(resp3.json()["items"]) == 10
    assert resp3.json()["totalPages"] == 3


def test_events_filters(client: TestClient) -> None:
    settings = get_settings()
    rows = [
        record(0, rule_id="R1", src_ip="10.1.1.1"),
        record(1, rule_id="R2", src_ip="10.2.2.2"),
        record(2, rule_id="R1", src_ip="10.1.1.1", dst_ip="172.16.0.1"),
    ]
    write_log(settings.log_dir, "deny.log", rows)
    client.post("/api/deny/collect")

    assert client.get("/api/deny/events", params={"rule_id": "R1"}).json()["total"] == 2
    assert client.get("/api/deny/events", params={"src_ip": "10.2.2.2"}).json()["total"] == 1
    both = client.get("/api/deny/events",
                      params={"rule_id": "R1", "dst_ip": "172.16.0.1"}).json()
    assert both["total"] == 1


def test_status_reports_progress_and_identity(client: TestClient) -> None:
    settings = get_settings()
    p = write_log(settings.log_dir, "deny.log", [record(i) for i in range(3)])
    client.post("/api/deny/collect")

    resp = client.get("/api/deny/status")
    data = resp.json()
    assert data["totalEvents"] == 3 and data["totalErrors"] == 0
    f = data["files"][0]
    assert f["fileName"] == "deny.log"
    assert f["offsetBytes"] == p.stat().st_size
    assert f["lineCount"] == 3
    assert f["fileIno"] == p.stat().st_ino
    assert f["hasError"] is False


def test_bad_line_endpoint_and_clear(client: TestClient) -> None:
    settings = get_settings()
    p = settings.log_dir / "deny.log"
    p.write_bytes(
        (json.dumps(record(0)) + "\n").encode() + b"{broken json\n")

    resp = client.post("/api/deny/collect")
    assert resp.json()["stoppedOnBadLine"] is True

    errors = client.get("/api/deny/errors").json()["items"]
    assert len(errors) == 1
    assert errors[0]["fileName"] == "deny.log"
    assert errors[0]["lineNo"] == 2
    assert errors[0]["lineOffset"] == len((json.dumps(record(0)) + "\n"))

    status = client.get("/api/deny/status").json()
    assert status["totalErrors"] == 1
    assert status["files"][0]["hasError"] is True

    cleared = client.post("/api/deny/errors/clear").json()
    assert cleared["cleared"] == 1
    assert client.get("/api/deny/errors").json()["items"] == []


def test_concurrent_collect_returns_409(client: TestClient,
                                        monkeypatch: pytest.MonkeyPatch) -> None:
    settings = get_settings()
    write_log(settings.log_dir, "deny.log", [record(0)])

    import threading
    entered = threading.Event()
    release = threading.Event()

    def block_inside():
        entered.set()
        release.wait(timeout=5)

    monkeypatch.setattr(ingest, "_test_hook", block_inside)
    t = threading.Thread(
        target=lambda: client.post("/api/deny/collect"))
    t.start()
    assert entered.wait(timeout=5)
    try:
        resp = client.post("/api/deny/collect")
        assert resp.status_code == 409
        body = resp.json()
        assert body["ok"] is False and body["busy"] is True
    finally:
        release.set()
        t.join(timeout=5)


def test_cross_process_flock_excludes_second_process(
        client: TestClient) -> None:
    """独立子进程持有同一把文件锁时，本进程采集必须被拒绝。

    子进程只短时持锁后自行退出，避免在受限环境里发送信号。
    """
    settings = get_settings()
    write_log(settings.log_dir, "deny.log", [record(0)])

    holder = r"""
import fcntl, os, sys, time
lock = os.environ["DENY_LOCK_PATH"]
os.makedirs(os.path.dirname(lock), exist_ok=True)
fh = open(lock, "a+")
fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
sys.stdout.write("locked\n")
sys.stdout.flush()
time.sleep(3)
"""
    env = dict(os.environ)
    proc = subprocess.Popen(
        [sys.executable, "-I", "-c", holder],
        env=env, stdout=subprocess.PIPE, text=True)
    try:
        assert proc.stdout.readline().strip() == "locked"
        resp = client.post("/api/deny/collect")
        assert resp.status_code == 409
        assert resp.json()["busy"] is True
    finally:
        proc.wait(timeout=10)

    # 锁释放后同一进程可正常采集，数据不丢
    ok = client.post("/api/deny/collect")
    assert ok.status_code == 200 and ok.json()["eventsInserted"] == 1


def test_collect_empty_dir_returns_warning(client: TestClient) -> None:
    resp = client.post("/api/deny/collect")
    body = resp.json()
    assert body["ok"] is True
    assert body["eventsInserted"] == 0
    assert "deny.log" in body["warning"]


def test_rotation_shows_both_identities(client: TestClient) -> None:
    settings = get_settings()
    p = write_log(settings.log_dir, "deny.log", [record(i) for i in range(4)])
    client.post("/api/deny/collect")

    rotated = settings.log_dir / "deny.log.1"
    p.rename(rotated)
    p.touch()
    write_log(settings.log_dir, "deny.log", [record(10)])
    client.post("/api/deny/collect")

    status = client.get("/api/deny/status").json()
    by_name = {f["fileName"]: f for f in status["files"]}
    assert set(by_name) == {"deny.log", "deny.log.1"}
    assert by_name["deny.log.1"]["lineCount"] == 4
    assert by_name["deny.log"]["lineCount"] == 1
    assert by_name["deny.log"]["fileIno"] != by_name["deny.log.1"]["fileIno"]
    assert status["totalEvents"] == 5
