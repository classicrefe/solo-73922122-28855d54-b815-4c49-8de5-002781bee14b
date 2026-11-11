"""采集引擎单元测试：续采、半包、改名轮转、坏行停止、原子性、文件身份。"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path

import pytest

from app.collector import db, ingest
from app.collector.config import Settings


def make_record(seq: int, **overrides) -> dict:
    rec = {
        "ts": 1700000000 + seq,
        "src_ip": f"10.0.0.{(seq % 250) + 1}",
        "dst_ip": "192.168.10.20",
        "dst_port": 443,
        "rule_id": "FW-DENY-101",
    }
    rec.update(overrides)
    return rec


def line(seq: int, **overrides) -> bytes:
    return (json.dumps(make_record(seq, **overrides)) + "\n").encode("utf-8")


@pytest.fixture()
def settings(tmp_path: Path) -> Settings:
    log_dir = tmp_path / "logs"
    data_dir = tmp_path / "data"
    log_dir.mkdir()
    data_dir.mkdir()
    return Settings(
        log_dir=log_dir,
        db_path=data_dir / "deny.db",
        lock_path=data_dir / "collector.lock",
    )


def collect(settings: Settings) -> dict:
    return ingest.run_ingestion(settings)


def count_rows(settings: Settings) -> int:
    with db.connect(settings.db_path) as conn:
        return db.count_events(conn)


def progress_of(settings: Settings, path: Path) -> sqlite3.Row:
    st = path.stat()
    with db.connect(settings.db_path) as conn:
        return db.get_progress(conn, st.st_dev, st.st_ino)


# --------------------------------------------------------------------------- #
# 基础采集
# --------------------------------------------------------------------------- #
def test_basic_ingestion_and_idempotent_rerun(settings: Settings) -> None:
    p = settings.log_dir / "deny.log"
    p.write_bytes(b"".join(line(i) for i in range(5)))

    report = collect(settings)
    assert report["eventsInserted"] == 5
    assert count_rows(settings) == 5

    # 再次采集：无新增，不重记
    report2 = collect(settings)
    assert report2["eventsInserted"] == 0
    assert count_rows(settings) == 5

    prog = progress_of(settings, p)
    assert prog["offset_bytes"] == p.stat().st_size
    assert prog["line_count"] == 5


def test_duplicate_content_lines_are_all_kept(settings: Settings) -> None:
    same = line(0)
    (settings.log_dir / "deny.log").write_bytes(same * 3)
    collect(settings)
    assert count_rows(settings) == 3


def test_incremental_append_after_partial_run(settings: Settings) -> None:
    p = settings.log_dir / "deny.log"
    p.write_bytes(b"".join(line(i) for i in range(3)))
    collect(settings)

    with open(p, "ab") as fh:
        fh.write(b"".join(line(i) for i in range(3, 7)))
    collect(settings)
    assert count_rows(settings) == 7
    with db.connect(settings.db_path) as conn:
        rows = conn.execute(
            "SELECT line_no, line_offset, src_ip FROM deny_events ORDER BY id"
        ).fetchall()
    assert [r["line_no"] for r in rows] == [1, 2, 3, 4, 5, 6, 7]
    # 来源位置：第 4 行偏移等于前 3 行字节总长
    first_three = b"".join(line(i) for i in range(3))
    assert rows[3]["line_offset"] == len(first_three)


# --------------------------------------------------------------------------- #
# 末尾半包：未换行不入库，补全后不丢不重
# --------------------------------------------------------------------------- #
def test_trailing_partial_line_waits_for_completion(settings: Settings) -> None:
    p = settings.log_dir / "deny.log"
    full = line(0) + line(1)
    partial = line(2)
    # 末行只写一半，且没有换行符
    p.write_bytes(full + partial[: len(partial) // 2])

    collect(settings)
    assert count_rows(settings) == 2  # 半包不得提前入库
    prog = progress_of(settings, p)
    assert prog["offset_bytes"] == len(full)  # 进度停在半包之前

    # 补全半包
    with open(p, "ab") as fh:
        fh.write(partial[len(partial) // 2:])
    collect(settings)
    assert count_rows(settings) == 3
    assert progress_of(settings, p)["offset_bytes"] == p.stat().st_size


def test_partial_then_more_partials_then_complete(settings: Settings) -> None:
    p = settings.log_dir / "deny.log"
    p.write_bytes(line(0))
    collect(settings)
    piece = line(1)
    # 分三次补写同一行，前两次都没有换行
    thirds = [piece[: 10], piece[10:20], piece[20:]]
    for part in thirds[:-1]:
        with open(p, "ab") as fh:
            fh.write(part)
        collect(settings)
        assert count_rows(settings) == 1
    with open(p, "ab") as fh:
        fh.write(thirds[-1])
    collect(settings)
    assert count_rows(settings) == 2


# --------------------------------------------------------------------------- #
# 改名轮转：旧文件续写、新 deny.log 从头采
# --------------------------------------------------------------------------- #
def test_rename_rotation_old_file_resumes_new_file_starts_fresh(
        settings: Settings) -> None:
    p = settings.log_dir / "deny.log"
    p.write_bytes(b"".join(line(i) for i in range(4)))
    collect(settings)
    assert count_rows(settings) == 4
    old_identity = p.stat().st_ino

    # 仅改名轮转，源文件保留不截断；新 deny.log 从头建立
    rotated = settings.log_dir / "deny.log.1"
    p.rename(rotated)
    p.touch()
    assert rotated.stat().st_ino == old_identity

    # 旧文件继续追加（改名后仍可写），新文件也产生数据
    with open(rotated, "ab") as fh:
        fh.write(b"".join(line(i) for i in range(4, 6)))
    with open(p, "ab") as fh:
        fh.write(b"".join(line(i) for i in range(6, 9)))

    report = collect(settings)
    names = {f["file_name"] for f in report["files"]}
    assert names == {"deny.log", "deny.log.1"}
    assert count_rows(settings) == 9

    # 旧文件按原身份从偏移续写，而不是从头重采
    old_prog = progress_of(settings, rotated)
    assert old_prog["line_count"] == 6
    assert old_prog["offset_bytes"] == rotated.stat().st_size
    # 新文件是新身份，从偏移 0 采
    new_prog = progress_of(settings, p)
    assert new_prog["line_count"] == 3
    assert new_prog["offset_bytes"] == p.stat().st_size


def test_numeric_suffix_ordering(settings: Settings) -> None:
    for n in (1, 2, 10):
        f = settings.log_dir / f"deny.log.{n}"
        f.write_bytes(line(n))
    (settings.log_dir / "deny.log").write_bytes(line(0))
    found = [p.name for p in ingest.discover_files(settings.log_dir)]
    assert found == ["deny.log", "deny.log.1", "deny.log.2", "deny.log.10"]


# --------------------------------------------------------------------------- #
# 坏行：停止采集该文件，记录文件与位置，保留此前记录
# --------------------------------------------------------------------------- #
def test_bad_json_stops_file_and_keeps_prior_records(settings: Settings) -> None:
    p = settings.log_dir / "deny.log"
    good = b"".join(line(i) for i in range(3))
    bad = b'{"ts": 1, "src_ip": "1.1.1.1", broken\n'
    after = line(9)
    p.write_bytes(good + bad + after)

    report = collect(settings)
    assert report["stoppedOnBadLine"] is True
    assert count_rows(settings) == 3  # 坏行及其后内容不入库

    with db.connect(settings.db_path) as conn:
        err = db.all_errors(conn)[0]
    assert err["file_name"] == "deny.log"
    assert err["line_no"] == 4
    assert err["line_offset"] == len(good)  # 精确字节位置
    assert "JSON" in err["reason"]

    # 未清除坏行前持续跳过该文件，后续行仍不入库
    collect(settings)
    assert count_rows(settings) == 3

    # 清除标记后重新采集：坏行仍在，依旧停在同一位置（防止悄悄跳过坏数据）
    with db.connect(settings.db_path) as conn:
        db.clear_errors(conn)
    collect(settings)
    assert count_rows(settings) == 3

    # 修复文件（删掉坏行）再清除标记，剩余行正常入库
    p.write_bytes(good + after)
    with db.connect(settings.db_path) as conn:
        db.clear_errors(conn)
    collect(settings)
    assert count_rows(settings) == 4


@pytest.mark.parametrize("payload, marker", [
    (b'{"ts": "1700000000", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",'
     b' "dst_port": 80, "rule_id": "R1"}\n', "ts"),
    (b'{"ts": 1, "src_ip": "10.0.0.999", "dst_ip": "10.0.0.2",'
     b' "dst_port": 80, "rule_id": "R1"}\n', "src_ip"),
    (b'{"ts": 1, "src_ip": "10.0.0.1", "dst_ip": "::1",'
     b' "dst_port": 80, "rule_id": "R1"}\n', "dst_ip"),
    (b'{"ts": 1, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",'
     b' "dst_port": 70000, "rule_id": "R1"}\n', "dst_port"),
    (b'{"ts": 1, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",'
     b' "dst_port": 80, "rule_id": ""}\n', "rule_id"),
    (b'{"ts": 1, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",'
     b' "dst_port": 80}\n', "rule_id"),
    (b"not-a-json-object\n", "JSON"),
    (b"\xff\xfe\x00not-utf8\n", "UTF-8"),
    (b"\n", "空行"),
])
def test_various_bad_lines(settings: Settings, payload: bytes,
                           marker: str) -> None:
    (settings.log_dir / "deny.log").write_bytes(line(0) + payload)
    report = collect(settings)
    assert report["stoppedOnBadLine"] is True
    assert count_rows(settings) == 1
    with db.connect(settings.db_path) as conn:
        reason = db.all_errors(conn)[0]["reason"]
    assert marker in reason


def test_boolean_fields_rejected(settings: Settings) -> None:
    # bool 是 int 的子类，必须显式拒绝
    payload = json.dumps({
        "ts": True, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
        "dst_port": True, "rule_id": "R1",
    }).encode() + b"\n"
    (settings.log_dir / "deny.log").write_bytes(payload)
    report = collect(settings)
    assert report["stoppedOnBadLine"] is True


def test_line_over_4kib_stops_file(settings: Settings) -> None:
    p = settings.log_dir / "deny.log"
    good = line(0)
    # 4097 字节（含换行）的合法 JSON 行
    prefix = (b'{"ts": 1, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", '
              b'"dst_port": 80, "rule_id": "R1", "pad": "')
    big = prefix + b"x" * (4097 - len(prefix) - 3) + b'"}\n'
    assert len(big) == 4097
    p.write_bytes(good + big + line(2))
    report = collect(settings)
    assert report["stoppedOnBadLine"] is True
    assert count_rows(settings) == 1
    with db.connect(settings.db_path) as conn:
        err = db.all_errors(conn)[0]
    assert err["line_offset"] == len(good)
    assert "4096" in err["reason"]


def test_exactly_4kib_line_accepted(settings: Settings) -> None:
    # 恰好 4096 字节（含换行）是允许的上限
    prefix = (b'{"ts": 1, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", '
              b'"dst_port": 80, "rule_id": "R1", "pad": "')
    body = prefix + b"x" * (4096 - len(prefix) - 3) + b'"}\n'
    assert len(body) == 4096
    (settings.log_dir / "deny.log").write_bytes(body)
    collect(settings)
    assert count_rows(settings) == 1


def test_long_unterminated_line_stopped_without_partial_insert(
        settings: Settings) -> None:
    p = settings.log_dir / "deny.log"
    # 超过 4KiB 且没有换行符：按坏行处理，不能留成无限等待的半包
    p.write_bytes(line(0) + b"x" * 5000)
    report = collect(settings)
    assert report["stoppedOnBadLine"] is True
    assert count_rows(settings) == 1
    with db.connect(settings.db_path) as conn:
        err = db.all_errors(conn)[0]
    assert err["line_offset"] == len(line(0))


# --------------------------------------------------------------------------- #
# 原子性：每条记录与进度同事务提交
# --------------------------------------------------------------------------- #
def test_event_and_progress_commit_together_on_failure(
        settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    p = settings.log_dir / "deny.log"
    p.write_bytes(b"".join(line(i) for i in range(5)))

    calls = {"n": 0}
    real_upsert = db.upsert_progress

    def flaky_upsert(conn, dev, ino, name, offset, line_count):
        calls["n"] += 1
        if calls["n"] == 3:
            raise sqlite3.OperationalError("simulated crash during commit")
        return real_upsert(conn, dev, ino, name, offset, line_count)

    monkeypatch.setattr(ingest.db, "upsert_progress", flaky_upsert)
    with pytest.raises(sqlite3.OperationalError):
        collect(settings)

    # 第 3 行的事件与进度必须一起回滚：库里恰好 2 行，偏移停在第 2 行末
    assert count_rows(settings) == 2
    prog = progress_of(settings, p)
    expected = len(line(0)) + len(line(1))
    assert prog["offset_bytes"] == expected
    assert prog["line_count"] == 2

    # 恢复后重启采集：从偏移处继续，不漏不重
    monkeypatch.undo()
    collect(settings)
    assert count_rows(settings) == 5
    assert progress_of(settings, p)["offset_bytes"] == p.stat().st_size


# --------------------------------------------------------------------------- #
# 并发互斥
# --------------------------------------------------------------------------- #
def test_second_ingestion_in_same_process_rejected(
        settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    (settings.log_dir / "deny.log").write_bytes(line(0))
    import threading

    entered = threading.Event()
    release = threading.Event()

    def block_inside():
        entered.set()
        release.wait(timeout=5)

    monkeypatch.setattr(ingest, "_test_hook", block_inside)
    t = threading.Thread(target=collect, args=(settings,))
    t.start()
    assert entered.wait(timeout=5)
    try:
        with pytest.raises(ingest.AlreadyRunning):
            collect(settings)
    finally:
        release.set()
        t.join(timeout=5)


def test_missing_log_dir_reports_warning(settings: Settings) -> None:
    settings.log_dir.rmdir()
    report = collect(settings)
    assert report["eventsInserted"] == 0
    assert report["warning"] is not None
    assert "deny.log" in report["warning"]


def test_rotated_suffix_and_current_are_ingested(settings: Settings) -> None:
    (settings.log_dir / "deny.log").write_bytes(line(0))
    (settings.log_dir / "deny.log.1").write_bytes(line(1))
    report = collect(settings)
    assert report["eventsInserted"] == 2
    assert count_rows(settings) == 2
    # 来源文件可区分
    with db.connect(settings.db_path) as conn:
        files = {r["source_file"] for r in
                 conn.execute("SELECT DISTINCT source_file FROM deny_events")}
    assert files == {"deny.log", "deny.log.1"}


def test_ingestion_tolerates_empty_file(settings: Settings) -> None:
    (settings.log_dir / "deny.log").touch()
    report = collect(settings)
    assert report["eventsInserted"] == 0
    assert report["files"][0]["status"] == "up-to-date"


def test_timestamp_validation_bounds(settings: Settings) -> None:
    good = make_record(0, ts=0)  # 0 合法
    (settings.log_dir / "deny.log").write_bytes(
        (json.dumps(good) + "\n").encode())
    collect(settings)
    assert count_rows(settings) == 1

    bad = (json.dumps(make_record(1, ts=-1)) + "\n").encode()
    with open(settings.log_dir / "deny.log", "ab") as fh:
        fh.write(bad)
    report = collect(settings)
    assert report["stoppedOnBadLine"] is True
