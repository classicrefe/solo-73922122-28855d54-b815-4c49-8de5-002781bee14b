"""本地 deny.log 日志源（演示与测试用）。

刻意把“写一行”拆成多个小片段并在片段之间休眠，以制造末尾不带换行符的
半包数据，验证采集器不会提前入库或丢数据。支持仅改名轮转（源文件保留、
不截断），并能在轮转后继续向旧文件追加，模拟真实防火墙日志的行为。

用法：
  python tools/log_source.py once [--count N] [--segments S] [--gap SEC]
  python tools/log_source.py rotate
  python tools/log_source.py append-old [--count N]
  python tools/log_source.py bad [--kind json|ip]
  python tools/log_source.py daemon [--interval SEC] [--rotate-after N]
                                  [--old-append-cycles N]
日志目录由环境变量 DENY_LOG_DIR 决定，默认 /var/lib/firewall-deny/logs。
"""

from __future__ import annotations

import argparse
import json
import os
import random
import time
from pathlib import Path

STATE_FILE_NAME = ".log_source_state.json"
CURRENT = "deny.log"

RULE_IDS = ["FW-DENY-101", "FW-DENY-102", "FW-DENY-201", "R-DEFAULT-DENY"]
SRC_IPS = ["10.0.1.5", "10.0.2.17", "172.16.4.9", "192.168.3.42", "10.9.0.11"]
DST_IPS = ["192.168.10.20", "192.168.10.30", "8.8.8.8", "203.0.113.7"]
PORTS = [22, 80, 443, 3389, 8443]


def log_dir() -> Path:
    return Path(os.environ.get(
        "DENY_LOG_DIR", "/var/lib/firewall-deny/logs"))


def load_state(directory: Path) -> dict:
    path = directory / STATE_FILE_NAME
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {"seq": 0, "lines_since_rotation": 0, "old_append_left": 0}


def save_state(directory: Path, state: dict) -> None:
    (directory / STATE_FILE_NAME).write_text(
        json.dumps(state), encoding="utf-8")


def make_record(seq: int) -> dict:
    rng = random.Random(20261111 + seq)
    return {
        "ts": int(time.time()),
        "src_ip": rng.choice(SRC_IPS),
        "dst_ip": rng.choice(DST_IPS),
        "dst_port": rng.choice(PORTS),
        "rule_id": rng.choice(RULE_IDS),
    }


def segmented_write(path: Path, line: bytes, segments: int, gap: float) -> None:
    """把一整行拆成多个片段追加，片段间休眠；最后一个片段带换行。"""
    segments = max(1, segments)
    edge = max(1, len(line) // segments)
    pieces = [line[i:i + edge] for i in range(0, len(line), edge)]
    with open(path, "ab") as fh:
        for i, piece in enumerate(pieces):
            fh.write(piece)
            fh.flush()
            os.fsync(fh.fileno())
            if i < len(pieces) - 1 and gap > 0:
                time.sleep(gap)


def write_lines(directory: Path, target: str, count: int,
                segments: int, gap: float, state: dict | None = None) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / target
    st = state if state is not None else load_state(directory)
    for _ in range(count):
        st["seq"] += 1
        record = make_record(st["seq"])
        line = (json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8")
        segmented_write(path, line, segments, gap)
    if state is None:
        save_state(directory, st)


def rotate(directory: Path, state: dict | None = None) -> None:
    """仅改名轮转：deny.log → deny.log.1 → deny.log.2 …，源文件保留不截断。"""
    st = state if state is not None else load_state(directory)
    current = directory / CURRENT
    if not current.exists():
        print(f"[rotate] {current} 不存在，无需轮转")
        return
    n = 1
    while (directory / f"{CURRENT}.{n}").exists():
        n += 1
    target = directory / f"{CURRENT}.{n}"
    current.rename(target)
    # 新 deny.log 从头建立（空文件，等待后续写入）
    current.touch()
    st["lines_since_rotation"] = 0
    print(f"[rotate] {current.name} -> {target.name}，新 {CURRENT} 已建立")
    if state is None:
        save_state(directory, st)


def write_bad(directory: Path, kind: str) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    if kind == "json":
        line = b'{"ts": 1700000000, "src_ip": "10.0.0.1", broken json\n'
    else:
        line = (json.dumps({
            "ts": int(time.time()),
            "src_ip": "999.1.1.1",            # 非法 IPv4
            "dst_ip": "192.168.0.1",
            "dst_port": 443,
            "rule_id": "FW-DENY-101",
        }) + "\n").encode("utf-8")
    with open(directory / CURRENT, "ab") as fh:
        fh.write(line)
    print(f"[bad] 已向 {CURRENT} 注入坏行（{kind}）：{line!r}")


def cmd_once(args: argparse.Namespace) -> None:
    directory = log_dir()
    write_lines(directory, CURRENT, args.count, args.segments, args.gap)
    print(f"[once] 向 {directory / CURRENT} 分段写入 {args.count} 行")


def cmd_rotate(_args: argparse.Namespace) -> None:
    rotate(log_dir())


def cmd_append_old(args: argparse.Namespace) -> None:
    directory = log_dir()
    rotated = sorted(directory.glob(f"{CURRENT}.*"),
                     key=lambda p: int(p.name.rsplit(".", 1)[1]))
    if not rotated:
        print("[append-old] 没有轮转文件，改写入 deny.log")
        write_lines(directory, CURRENT, args.count, 1, 0)
        return
    target = rotated[-1].name
    write_lines(directory, target, args.count, 1, 0)
    print(f"[append-old] 向旧文件 {target} 续写 {args.count} 行")


def cmd_bad(args: argparse.Namespace) -> None:
    write_bad(log_dir(), args.kind)


def cmd_daemon(args: argparse.Namespace) -> None:
    directory = log_dir()
    directory.mkdir(parents=True, exist_ok=True)
    state = load_state(directory)
    if not (directory / CURRENT).exists():
        (directory / CURRENT).touch()
    print(f"[daemon] 启动，目录 {directory}，间隔 {args.interval}s，"
          f"每 {args.rotate_after} 行轮转一次")
    while True:
        # 轮转后的若干周期内，向改名后的旧文件也追加数据（旧文件仍可追加）
        if state.get("old_append_left", 0) > 0:
            rotated = sorted(directory.glob(f"{CURRENT}.*"),
                             key=lambda p: int(p.name.rsplit(".", 1)[1]))
            if rotated:
                write_lines(directory, rotated[-1].name, 1, 1, 0, state)
                print(f"[daemon] 旧文件 {rotated[-1].name} 续写 1 行")
            state["old_append_left"] -= 1

        write_lines(directory, CURRENT, 1, args.segments, args.gap, state)
        state["lines_since_rotation"] += 1
        print(f"[daemon] 写入 1 行（序号 {state['seq']}）")

        if state["lines_since_rotation"] >= args.rotate_after:
            rotate(directory, state)
            state["old_append_left"] = args.old_append_cycles

        save_state(directory, state)
        time.sleep(args.interval)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="本地 deny.log 日志源")
    sub = parser.add_subparsers(dest="command", required=True)

    p_once = sub.add_parser("once", help="向 deny.log 分段写入若干合法行")
    p_once.add_argument("--count", type=int, default=5)
    p_once.add_argument("--segments", type=int, default=3)
    p_once.add_argument("--gap", type=float, default=0.2)
    p_once.set_defaults(func=cmd_once)

    p_rot = sub.add_parser("rotate", help="改名轮转（不截断，保留源文件）")
    p_rot.set_defaults(func=cmd_rotate)

    p_old = sub.add_parser("append-old", help="向最近的轮转旧文件续写")
    p_old.add_argument("--count", type=int, default=3)
    p_old.set_defaults(func=cmd_append_old)

    p_bad = sub.add_parser("bad", help="注入一行坏数据")
    p_bad.add_argument("--kind", choices=["json", "ip"], default="json")
    p_bad.set_defaults(func=cmd_bad)

    p_d = sub.add_parser("daemon", help="持续产生日志并周期性轮转")
    p_d.add_argument("--interval", type=float, default=2.0)
    p_d.add_argument("--rotate-after", type=int, default=12)
    p_d.add_argument("--old-append-cycles", type=int, default=2)
    p_d.add_argument("--segments", type=int, default=2)
    p_d.add_argument("--gap", type=float, default=0.1)
    p_d.set_defaults(func=cmd_daemon)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
