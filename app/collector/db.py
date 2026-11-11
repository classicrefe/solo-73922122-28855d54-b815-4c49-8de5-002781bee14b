"""SQLite 持久层。

三张表：
  deny_events     被拒连接记录（同内容不同行各自保留，故无任何去重唯一约束）；
  ingest_progress 按文件身份（st_dev, st_ino）区分的字节级采集进度；
  ingest_errors   坏行错误（文件、字节位置、行号、原因），每文件保留首个错误。

每条事件与其进度更新放在同一事务内提交，保证“记录与进度一并提交”，
中断重启后既不会漏记也不会重记。
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Optional

SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS deny_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_utc      INTEGER NOT NULL,          -- UTC 整数秒
    src_ip      TEXT NOT NULL,             -- 源 IPv4
    dst_ip      TEXT NOT NULL,             -- 目的 IPv4
    dst_port    INTEGER NOT NULL,          -- 目的端口 0..65535
    rule_id     TEXT NOT NULL,             -- 命中规则 ID（整数规则 ID 也按文本存）
    source_file TEXT NOT NULL,             -- 来源文件名
    file_dev    INTEGER NOT NULL,          -- 文件身份：设备号
    file_ino    INTEGER NOT NULL,          -- 文件身份：inode
    line_no     INTEGER NOT NULL,          -- 文件内行号（1 起）
    line_offset INTEGER NOT NULL           -- 行首字节偏移
);

CREATE INDEX IF NOT EXISTS idx_events_rule ON deny_events(rule_id);
CREATE INDEX IF NOT EXISTS idx_events_src  ON deny_events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_dst  ON deny_events(dst_ip);

CREATE TABLE IF NOT EXISTS ingest_progress (
    file_dev      INTEGER NOT NULL,        -- 文件身份（st_dev, st_ino）
    file_ino      INTEGER NOT NULL,
    file_name     TEXT NOT NULL,
    offset_bytes  INTEGER NOT NULL,        -- 已确认采集到的字节偏移
    line_count    INTEGER NOT NULL,        -- 已入库行数
    updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (file_dev, file_ino)
);

CREATE TABLE IF NOT EXISTS ingest_errors (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    file_dev      INTEGER NOT NULL,
    file_ino      INTEGER NOT NULL,
    file_name     TEXT NOT NULL,
    line_no       INTEGER,                 -- 行号；无法定位行时为 NULL
    line_offset   INTEGER NOT NULL,        -- 坏行起始字节偏移
    reason        TEXT NOT NULL,
    raw_preview   TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_errors_identity
    ON ingest_errors(file_dev, file_ino);
"""


def connect(db_path: Path) -> sqlite3.Connection:
    """打开数据库连接；父目录自动创建，WAL 模式支持两进程并发读写。"""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Path) -> None:
    with connect(db_path) as conn:
        conn.executescript(SCHEMA)


# --------------------------------------------------------------------------- #
# 进度
# --------------------------------------------------------------------------- #
def get_progress(conn: sqlite3.Connection, dev: int, ino: int
                 ) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM ingest_progress WHERE file_dev=? AND file_ino=?",
        (dev, ino)).fetchone()


def upsert_progress(conn: sqlite3.Connection, dev: int, ino: int, name: str,
                    offset: int, line_count: int) -> None:
    conn.execute(
        """
        INSERT INTO ingest_progress
            (file_dev, file_ino, file_name, offset_bytes, line_count, updated_at)
        VALUES (?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        ON CONFLICT(file_dev, file_ino) DO UPDATE SET
            file_name=excluded.file_name,
            offset_bytes=excluded.offset_bytes,
            line_count=excluded.line_count,
            updated_at=excluded.updated_at
        """,
        (dev, ino, name, offset, line_count))


def all_progress(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return list(conn.execute(
        "SELECT * FROM ingest_progress ORDER BY file_name"))


# --------------------------------------------------------------------------- #
# 事件
# --------------------------------------------------------------------------- #
def insert_event(conn: sqlite3.Connection, record: dict[str, Any], name: str,
                 dev: int, ino: int, line_no: int, line_offset: int) -> None:
    conn.execute(
        """
        INSERT INTO deny_events
            (ts_utc, src_ip, dst_ip, dst_port, rule_id,
             source_file, file_dev, file_ino, line_no, line_offset)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (record["ts"], record["src_ip"], record["dst_ip"],
         record["dst_port"], record["rule_id"],
         name, dev, ino, line_no, line_offset))


def count_events(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM deny_events").fetchone()[0]


def query_events(conn: sqlite3.Connection, page: int, page_size: int,
                 rule_id: Optional[str] = None,
                 src_ip: Optional[str] = None,
                 dst_ip: Optional[str] = None) -> tuple[list[sqlite3.Row], int]:
    where: list[str] = []
    params: list[Any] = []
    if rule_id:
        where.append("rule_id = ?")
        params.append(rule_id)
    if src_ip:
        where.append("src_ip = ?")
        params.append(src_ip)
    if dst_ip:
        where.append("dst_ip = ?")
        params.append(dst_ip)
    clause = (" WHERE " + " AND ".join(where)) if where else ""

    total = conn.execute(
        f"SELECT COUNT(*) FROM deny_events{clause}", params).fetchone()[0]
    page = max(1, page)
    page_size = min(200, max(1, page_size))
    rows = conn.execute(
        f"SELECT * FROM deny_events{clause} ORDER BY id ASC LIMIT ? OFFSET ?",
        params + [page_size, (page - 1) * page_size]).fetchall()
    return list(rows), total


# --------------------------------------------------------------------------- #
# 坏行错误
# --------------------------------------------------------------------------- #
def insert_error(conn: sqlite3.Connection, dev: int, ino: int, name: str,
                 line_no: Optional[int], line_offset: int, reason: str,
                 raw_preview: str) -> None:
    conn.execute(
        """
        INSERT INTO ingest_errors
            (file_dev, file_ino, file_name, line_no, line_offset,
             reason, raw_preview)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (dev, ino, name, line_no, line_offset, reason, raw_preview))


def get_error(conn: sqlite3.Connection, dev: int, ino: int
              ) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM ingest_errors WHERE file_dev=? AND file_ino=? "
        "ORDER BY id ASC LIMIT 1", (dev, ino)).fetchone()


def all_errors(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return list(conn.execute(
        "SELECT * FROM ingest_errors ORDER BY id ASC"))


def count_errors(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM ingest_errors").fetchone()[0]


def clear_errors(conn: sqlite3.Connection) -> int:
    cur = conn.execute("DELETE FROM ingest_errors")
    return cur.rowcount
