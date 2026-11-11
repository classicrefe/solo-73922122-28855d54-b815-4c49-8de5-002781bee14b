"""采集器配置。

生产环境从固定本地目录读取（/var/lib/firewall-deny 下），
允许用环境变量覆盖，方便测试与容器编排：
  DENY_LOG_DIR   deny.log 及其数字后缀轮转文件所在目录
  DENY_DB_PATH   SQLite 数据库文件路径
  DENY_LOCK_PATH 跨进程采集互斥锁文件路径（默认与数据库同目录）
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

#: 日志规范：每行最多 4KiB（含结尾换行符）
MAX_LINE_BYTES = 4096

#: 配置固定的本地基准目录
DEFAULT_BASE_DIR = Path("/var/lib/firewall-deny")


@dataclass(frozen=True)
class Settings:
    log_dir: Path
    db_path: Path
    lock_path: Path
    max_line_bytes: int = MAX_LINE_BYTES


def get_settings() -> Settings:
    """每次调用重新读取环境变量，测试可通过 monkeypatch 切换目录。"""
    log_dir = Path(os.environ.get("DENY_LOG_DIR", DEFAULT_BASE_DIR / "logs"))
    db_path = Path(os.environ.get(
        "DENY_DB_PATH", DEFAULT_BASE_DIR / "data" / "deny.db"))
    lock_path = Path(os.environ.get(
        "DENY_LOCK_PATH", db_path.parent / "collector.lock"))
    return Settings(log_dir=log_dir, db_path=db_path, lock_path=lock_path)
