"""deny.log 采集引擎。

关键语义（与需求逐条对应）：
  * 仅采集固定目录下的 deny.log 与其数字后缀改名轮转文件（deny.log.1 …）；
  * 以文件身份 (st_dev, st_ino) 区分文件并保存字节进度：改名不改变身份，
    因此改名后的旧文件可继续从上次偏移续写；新 deny.log 是新 inode，从头采；
  * 每行最多 4KiB（含换行）；UTF-8 JSONL；
  * 末尾没有换行符的半包数据不入库、不推进进度，留待下次补全；
  * 一条事件与其字节进度在同一事务提交，中断重启不漏不重；
  * 坏行（超长、非 UTF-8、非法 JSON、字段缺失/非法）立即停止采集该文件，
    记录文件与字节位置，此前已入库记录全部保留；
  * 同内容的不同行没有任何去重约束，各自保留；
  * fcntl 文件锁 + 进程内线程锁，保证两个 Web 进程不会并发采集。
"""

from __future__ import annotations

import fcntl
import ipaddress
import json
import re
import threading
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional

from . import db
from .config import Settings, get_settings

#: 读取块大小；按块读取，任意大小文件都不会一次性载入内存
READ_CHUNK = 64 * 1024

_ROTATED_RE = re.compile(r"^deny\.log\.(\d+)$")
_thread_lock = threading.Lock()

# 测试钩子：在持有采集锁、执行实际采集前调用（生产环境保持为 None）
_test_hook = None


class AlreadyRunning(Exception):
    """已有采集任务在执行（本进程线程锁或跨进程文件锁被占用）。"""


@dataclass
class FileResult:
    file_name: str
    file_dev: int
    file_ino: int
    status: str                 # ingested / up-to-date / bad-line / error-skipped / missing
    start_offset: int
    end_offset: int
    file_size: int
    line_count: int             # 累计已入库行数
    events_inserted: int
    line_no: Optional[int]
    line_offset: Optional[int]
    reason: Optional[str]


# --------------------------------------------------------------------------- #
# 文件发现
# --------------------------------------------------------------------------- #
def discover_files(log_dir: Path) -> list[Path]:
    """返回有序文件列表：deny.log 在前，deny.log.N 按数字后缀升序。"""
    if not log_dir.is_dir():
        return []
    current: list[Path] = []
    rotated: list[tuple[int, Path]] = []
    for entry in log_dir.iterdir():
        if not entry.is_file():
            continue
        if entry.name == "deny.log":
            current.append(entry)
        else:
            m = _ROTATED_RE.match(entry.name)
            if m:
                rotated.append((int(m.group(1)), entry))
    rotated.sort(key=lambda item: item[0])
    return current + [p for _, p in rotated]


# --------------------------------------------------------------------------- #
# 单行校验
# --------------------------------------------------------------------------- #
def _ipv4(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    try:
        addr = ipaddress.IPv4Address(value)
    except (ipaddress.AddressValueError, ValueError):
        return None
    if addr.version != 4:
        return None
    return str(addr)


def validate_line(raw_line: bytes) -> tuple[bool, Any]:
    """校验一行（含结尾换行）。成功返回 (True, record)，否则 (False, 原因)。"""
    payload = raw_line.rstrip(b"\r\n")
    if not payload:
        return False, "空行不是合法的 JSON 记录"
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        return False, f"不是合法的 UTF-8 文本：{exc}"
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as exc:
        return False, f"JSON 解析失败（第 {exc.lineno} 行第 {exc.colno} 列）：{exc.msg}"
    if not isinstance(obj, dict):
        return False, f"每行必须是 JSON 对象，当前是 {type(obj).__name__}"

    ts = obj.get("ts")
    if isinstance(ts, bool) or not isinstance(ts, int):
        return False, "字段 ts 必须是 UTC 整数秒（int）"
    if ts < 0:
        return False, "字段 ts 不能为负数"

    src = _ipv4(obj.get("src_ip"))
    if src is None:
        return False, f"字段 src_ip 不是合法 IPv4 地址：{obj.get('src_ip')!r}"

    dst = _ipv4(obj.get("dst_ip"))
    if dst is None:
        return False, f"字段 dst_ip 不是合法 IPv4 地址：{obj.get('dst_ip')!r}"

    port = obj.get("dst_port")
    if isinstance(port, bool) or not isinstance(port, int) \
            or not (0 <= port <= 65535):
        return False, "字段 dst_port 必须是 0-65535 的整数端口"

    rule_id = obj.get("rule_id")
    if isinstance(rule_id, bool) or not isinstance(rule_id, (int, str)):
        return False, "字段 rule_id 必须是整数或非空字符串"
    if isinstance(rule_id, str) and not rule_id.strip():
        return False, "字段 rule_id 不能是空字符串"

    return True, {
        "ts": ts,
        "src_ip": src,
        "dst_ip": dst,
        "dst_port": port,
        "rule_id": str(rule_id),
    }


# --------------------------------------------------------------------------- #
# 单文件采集
# --------------------------------------------------------------------------- #
def ingest_file(conn, path: Path, settings: Settings) -> FileResult:
    """按字节偏移增量采集一个文件；任何坏行都立即停止该文件。"""
    try:
        st = path.stat()
    except FileNotFoundError:
        return FileResult(path.name, 0, 0, "missing", 0, 0, 0, 0, 0,
                          None, None, "采集前文件已消失")

    dev, ino = st.st_dev, st.st_ino
    size = st.st_size
    progress = db.get_progress(conn, dev, ino)
    offset = int(progress["offset_bytes"]) if progress else 0
    line_count = int(progress["line_count"]) if progress else 0
    start_offset = offset
    inserted = 0

    def result(status: str, end: int, reason: Optional[str] = None,
               line_no: Optional[int] = None,
               line_offset: Optional[int] = None) -> FileResult:
        return FileResult(path.name, dev, ino, status, start_offset, end,
                          size, line_count, inserted, line_no, line_offset,
                          reason)

    # 已有坏行记录的文件：停止采集该文件，保留此前记录
    existing_error = db.get_error(conn, dev, ino)
    if existing_error is not None:
        return result("error-skipped", offset,
                      f"该文件存在未清除的坏行（字节偏移 "
                      f"{existing_error['line_offset']}），已跳过")

    if offset > size:
        # 非轮转场景下文件被截断，继续采会重复入库：按坏文件处理
        reason = f"文件被截断：已保存偏移 {offset} 大于当前大小 {size}，为避免重记已停止"
        with conn:
            db.insert_error(conn, dev, ino, path.name, None, offset,
                            reason, "")
        return result("bad-line", offset, reason, None, offset)

    if offset == size:
        return result("up-to-date", offset)

    def fail(reason: str, line_no: Optional[int], line_start: int,
             raw: bytes) -> FileResult:
        preview = raw[:500].decode("utf-8", errors="replace")
        with conn:
            db.insert_error(conn, dev, ino, path.name, line_no, line_start,
                            reason, preview)
        return result("bad-line", buf_start, reason, line_no, line_start)

    with open(path, "rb") as fh:
        fh.seek(offset)
        # buf_start 是 buffer[0] 在文件中的绝对字节偏移
        buffer = b""
        buf_start = offset

        while True:
            nl = buffer.find(b"\n")
            if nl == -1:
                # 整个 buffer 都没有换行：超长部分只可能属于当前这一行，
                # 此时判定坏行不会误伤已确认的前序行
                if len(buffer) > settings.max_line_bytes:
                    reason = (f"单行超过 {settings.max_line_bytes} 字节"
                              "（4KiB）且未遇到换行符")
                    return fail(reason, line_count + 1, buf_start, buffer)
                chunk = fh.read(READ_CHUNK)
                if chunk:
                    buffer += chunk
                    continue
                # EOF：仍有未以换行结束的数据
                if buffer:
                    if len(buffer) > settings.max_line_bytes:
                        reason = (f"单行超过 {settings.max_line_bytes} 字节"
                                  "（4KiB）且文件结束仍无换行符")
                        return fail(reason, line_count + 1, buf_start, buffer)
                    # 半包：留待补全，不推进进度、不入库
                    break
                break

            line = buffer[:nl + 1]
            line_start = buf_start
            line_no = line_count + 1
            if len(line) > settings.max_line_bytes:
                reason = f"单行 {len(line)} 字节，超过 {settings.max_line_bytes} 字节（4KiB）上限"
                return fail(reason, line_no, line_start, line)

            ok, payload = validate_line(line)
            if not ok:
                return fail(payload, line_no, line_start, line)

            # 记录与进度在同一事务内一并提交
            with conn:
                db.insert_event(conn, payload, path.name, dev, ino,
                                line_no, line_start)
                db.upsert_progress(conn, dev, ino, path.name,
                                   line_start + len(line), line_count + 1)

            buffer = buffer[nl + 1:]
            buf_start += nl + 1
            line_count += 1
            inserted += 1

    return result("ingested", buf_start)


# --------------------------------------------------------------------------- #
# 采集入口（互斥）
# --------------------------------------------------------------------------- #
def run_ingestion(settings: Optional[Settings] = None) -> dict[str, Any]:
    """执行一轮全量增量采集。被其他采集占用时抛 AlreadyRunning。"""
    settings = settings or get_settings()
    db.init_db(settings.db_path)
    settings.lock_path.parent.mkdir(parents=True, exist_ok=True)

    if not _thread_lock.acquire(blocking=False):
        raise AlreadyRunning("本进程已有采集任务在执行")
    try:
        with open(settings.lock_path, "a+") as lock_fh:
            try:
                fcntl.flock(lock_fh.fileno(),
                            fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise AlreadyRunning(
                    "另一个 Web 进程正在执行采集，本次触发被拒绝") from exc
            try:
                if _test_hook is not None:
                    _test_hook()
                return _run_locked(settings)
            finally:
                fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)
    finally:
        _thread_lock.release()


def _run_locked(settings: Settings) -> dict[str, Any]:
    files = discover_files(settings.log_dir)
    results: list[FileResult] = []
    counters = {"ingested": 0, "up-to-date": 0, "bad-line": 0,
                "error-skipped": 0, "missing": 0}
    events_inserted = 0
    warning: Optional[str] = None

    if not files:
        warning = f"目录 {settings.log_dir} 不存在或没有 deny.log / deny.log.N 文件"

    with db.connect(settings.db_path) as conn:
        for path in files:
            r = ingest_file(conn, path, settings)
            results.append(r)
            counters[r.status] += 1
            events_inserted += r.events_inserted
            # 坏行：停止采集该文件，后续文件本轮不再处理
            if r.status == "bad-line":
                break

    return {
        "ok": True,
        "logDir": str(settings.log_dir),
        "dbPath": str(settings.db_path),
        "filesScanned": len(files),
        "filesProcessed": len(results),
        "eventsInserted": events_inserted,
        "statusCounts": counters,
        "stoppedOnBadLine": any(r.status == "bad-line" for r in results),
        "warning": warning,
        "files": [asdict(r) for r in results],
    }
