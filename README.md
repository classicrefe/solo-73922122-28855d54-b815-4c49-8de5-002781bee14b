# 防火墙运维台（规则差分 + deny.log 阻断连接采集）

两个相互配合的运维工具：

1. **规则变更差分台**（`GET /`）：上线前比对两份有序 IPv4/TCP 规则集，精确列出
   新增放行 / 新增阻断的全部流量区域（不做抽样）；
2. **阻断连接采集页**（`GET /deny`）：从固定本地目录读取防火墙 `deny.log`
   及其数字后缀轮转文件，把实际被拒连接与命中规则入库，支持字节级断点续采、
   双进程并发互斥、坏行定位与分页排查。

---

## 一、阻断连接采集

### 日志格式与目录

* 固定目录（容器内）：`/var/lib/firewall-deny/logs`，可用环境变量 `DENY_LOG_DIR` 覆盖；
* 只采集 `deny.log` 与改名轮转文件 `deny.log.1`、`deny.log.2` …（按数字后缀排序）；
* UTF-8 JSONL，每行最多 **4KiB**（含换行），字段：

```json
{"ts": 1700000000, "src_ip": "10.0.0.5", "dst_ip": "192.168.10.20",
 "dst_port": 443, "rule_id": "FW-DENY-101"}
```

| 字段 | 含义 | 校验 |
| --- | --- | --- |
| `ts` | UTC 整数秒 | 非负整数（布尔值拒绝） |
| `src_ip` / `dst_ip` | 源 / 目的 IPv4 | 合法 IPv4，拒绝 IPv6 |
| `dst_port` | 目的端口 | 0–65535 整数 |
| `rule_id` | 命中规则 ID | 整数或非空字符串 |

### 可靠性语义（逐条对应实现）

* **按文件身份续采**：以 `(st_dev, st_ino)` 标识文件并保存字节偏移。改名轮转
  不改变 inode，所以改名后的旧文件继续从上次偏移**续写采集**；新 `deny.log`
  是新 inode，**从头采集**。
* **半包不丢不提前入库**：末尾没有换行符的数据视为半包，既不入库也不推进进度，
  等下次补全后再采。
* **逐行事务**：每条事件与该文件的字节进度更新放在**同一个 SQLite 事务**提交。
  中断重启后，已提交的不重采、未提交的不丢失；同内容的不同行无去重约束，全部保留。
* **并发互斥**：进程内线程锁 + `fcntl` 文件锁（`collector.lock`）。两个 Web 进程
  同时触发时，第二个立即得到 **HTTP 409**，不会并发写库。
* **坏行停止该文件**：超长行、非 UTF-8、非法 JSON、字段缺失或非法都会立即停止
  采集该文件，并记录**文件名、行号、字节偏移、原因与原始预览**；此前已入库记录
  全部保留。清除坏行标记（页面按钮或 API）并修复文件后才能继续。
* **只支持改名轮转**：源文件保留且不截断。若检测到非轮转的文件截断
  （已存偏移大于当前大小），为避免重记按坏文件停止。

### 网页与接口

| 方法 / 路径 | 说明 |
| --- | --- |
| `GET /deny` | 采集页：触发采集、文件进度、坏行面板、分页查询、来源位置 |
| `POST /api/deny/collect` | 触发一轮增量采集；并发占用时返回 409 `{ok:false, busy:true}` |
| `GET /api/deny/status` | 日志目录、每文件身份/大小/偏移/行数、坏行标记、历史文件身份 |
| `GET /api/deny/events?page=&page_size=&rule_id=&src_ip=&dst_ip=` | 分页查询被拒连接 |
| `GET /api/deny/errors` | 坏行列表（文件、行号、字节偏移、原因、预览） |
| `POST /api/deny/errors/clear` | 清除坏行标记（修复日志后使用） |

每条事件都带来源位置：`source.file`（文件名）、`lineNo`（行号）、
`lineOffset`（行首字节偏移）、`fileIno`（文件身份）。

### 本地日志源工具 `tools/log_source.py`

用于演示与造数，刻意把每一行拆成多个片段写入并在片段间休眠，以制造半包：

```bash
python tools/log_source.py once --count 5 --segments 4   # 分段写 5 行
python tools/log_source.py rotate                        # 仅改名轮转（不截断）
python tools/log_source.py append-old --count 2          # 轮转后向旧文件续写
python tools/log_source.py bad --kind json               # 注入坏行（json / ip）
python tools/log_source.py daemon --interval 2 \
    --rotate-after 12 --old-append-cycles 2              # 守护进程：周期轮转 + 旧文件续写
```

---

## 二、Docker Compose 一键演示

```bash
docker compose up --build
```

启动三个服务、共享同一个命名卷 `firewall-deny-data`：

| 服务 | 作用 | 入口 |
| --- | --- | --- |
| `firewall-deny-web-a` | Web 进程 A（uvicorn） | http://127.0.0.1:8000 （首页 `/`，采集页 `/deny`） |
| `firewall-deny-web-b` | Web 进程 B，独立 uvicorn，共享同一日志目录与 SQLite | http://127.0.0.1:8001/deny |
| `firewall-deny-log-source` | 本地日志源守护进程，持续分段写行、周期改名轮转、轮转后续写旧文件 | — |

端口默认只绑定宿主机回环地址；对局域网开放需把 `127.0.0.1:8000:8000` 改为 `"8000:8000"`。

### 建议演示步骤

1. 打开 http://127.0.0.1:8000/deny ，点**立即采集**，观察日志源持续写入的被拒连接入库；
2. 在 A（8000）与 B（8001）几乎同时点采集，其中一个返回「已有采集任务在执行」（409）；
3. 等待日志源自动轮转（默认每 12 行），状态页会同时出现 `deny.log` 与 `deny.log.1`
   两个不同 inode 的文件，旧文件偏移继续推进、新文件从 0 开始；
4. 手动注入坏行：
   `docker compose exec firewall-deny-log-source python tools/log_source.py bad`，
   再点采集，坏行面板显示文件、行号与字节偏移，该文件停止采集、此前记录保留；
5. 修复后点**清除坏行标记**，再采集即可继续。

健康检查：`GET /api/health`。

---

## 三、规则变更差分台（原有功能）

* 仅 IPv4 + TCP；规则含 `id`、`source`/`destination`（严格 IPv4 CIDR）、
  `portRange`（0–65535 闭区间）、`action`（`allow`/`deny`），每份最多 20 条；
* 按数组顺序首条命中，全部未命中即默认拒绝；
* `POST /api/analyze` 输出互不重叠、恰好覆盖全部差异的三维区域，含代表报文与
  旧/新命中规则；`GET /api/example` 返回内置示例。
* 精确性原理与输出解读见 `app/engine.py` 顶部文档与 `tests/test_engine.py`。

---

## 本地直接运行（无需 Docker）

```bash
pip install -r requirements.txt
export DENY_LOG_DIR=/var/lib/firewall-deny/logs
export DENY_DB_PATH=/var/lib/firewall-deny/data/deny.db
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

## 目录结构

```
app/
├── collector/
│   ├── config.py        # 固定目录配置（环境变量可覆盖）
│   ├── db.py            # SQLite：事件 / 字节进度 / 坏行
│   ├── ingest.py        # 文件发现、字节续采、逐行校验、逐行事务、文件锁互斥
│   └── routes.py        # /api/deny/* 路由与采集页
├── static/
│   ├── index.html       # 规则差分页
│   └── collect.html     # 阻断连接采集页
├── engine.py            # 规则差分引擎
├── example_data.py
└── main.py              # FastAPI 入口
tools/
└── log_source.py        # 本地日志源（分段写、改名轮转、旧文件续写、坏行注入）
tests/                   # pytest：差分引擎、采集引擎、采集 API
Dockerfile
docker-compose.yml       # 2 个 Web 进程 + 1 个日志源，共享命名卷
```

## 运行测试

```bash
pip install -r requirements.txt pytest httpx
pytest
```

测试覆盖：增量续采与幂等、半包等待与补全、改名轮转后旧文件续写/新文件从头采、
4KiB 边界、各类坏行停止与精确定位、逐行事务回滚（模拟中断不漏不重）、
同进程线程锁与跨进程 `flock` 互斥（409）、分页与过滤、来源位置。
