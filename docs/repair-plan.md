# ACE 修复思路 — 2026-08-12

综合 [engineering-roadmap](engineering-roadmap.md) 和 [project-assessment](project-assessment-2026-08-12.md)
的分析结论，提出从当前工程原型向可验证 QUIC 实现的收敛路径。

## 核心判断

**需要的是架构收敛，不是架构重建。** 当前底层运行模型（service 线程独占 QUIC engine/event loop，callback 驱动
transport，task 作为上层业务单元，Unix socket 本地控制）基本正确，应保留。

真正的问题是五个：边界模糊、协议与业务耦合、对象所有权分散、client/server 生命周期不对称、TLS 身份验证缺失。

以下 12 个阶段按优先级排序，TLS 认证为绝对最高优先（当前无对端身份验证，不可用于非受控网络）。

## 阶段执行计划

### P0：TLS 身份验证

**问题**：TLS 1.3 加密激活，但证书验证在永久 false 分支后面。客户端无法认证服务端，中间人可替换证书。

**目标**：
- 默认启用服务端证书验证
- 加入 hostname/SNI 验证
- 支持可配置 CA file / CA directory
- 开发/测试显式 insecure 模式
- 未知 CA / 过期证书 / hostname 不匹配的负面集成测试

**迁移方式**：创建 `tls_context.[ch]`，把 SSL_CTX、证书、CA、SNI、ALPN、keylog 从 `service.c` 中拆出。

**当前状态（2026-08-13）**：除 SNI 外全部完成。默认证书验证、hostname 验证（`X509_check_host`）、可配置
CA、insecure 模式、负面集成测试（未知 CA / 过期证书 / hostname 不匹配）均已落地并有 CI 覆盖。

残留缺口：client 不发送 SNI —— `service_connect()` / `service_connect_nop()` 把 `hostname=NULL` 传给
`lsquic_engine_connect()`，server 侧 `service_lookup_cert()` 对任意 SNI 返回单张证书（多证书 SNI 标为
future work）。单证书部署下不削弱安全性（hostname 验证直接对呈现证书校验），仅是多证书按域名选证的
完整性缺口。修复方向：client 侧把 hostname 传给 `lsquic_engine_connect()`，server 侧多证书时按 SNI 选证。

---

### P1：固定宽度版本化协议 codec

**问题**：当前协议直接使用 native C struct，含 `size_t` 字段（`task_protocol.h:43`），依赖 native pointer
width、字节序、padding、编译器 ABI。

**帧头设计**（所有多字节字段 network byte order）：

```
magic       uint32    // 快速拒绝旧格式 / 随机数据
version     uint8     // 协议版本
header_len  uint8     // 允许以后扩展帧头
flags       uint16    // 逐帧标志
theme       uint16    // 主题
stream_id   uint16    // 流标识
payload_len uint32    // 固定宽度，脱离 size_t
```

**分两层**：
- 帧级：以上固定头
- 连接级：首个 control frame 交换 capabilities、最大帧、最大流数

**新增模块**：`protocol_codec.[ch]` — 只做 wire ↔ domain object 转换，不碰业务逻辑。独立于 transport
层，可单独 fuzz、可跨架构 golden vector 测试。

**迁移策略**：直接切换到 v1，删除 legacy decoder。当前无外部部署，无向后兼容负担。

---

### P2：connection 状态机 + close/result 时序修复

**问题**：service 可能在 engine destroy 触发 late connection-close callback 之前计算并记录成功结果，
导致最终结果被改为 failure 时与已记录不符。

**目标**：
- 定义明确状态：CREATED → CONNECTING → HANDSHAKING → ACTIVE → DRAINING → CLOSED / FAILED
- 关闭原因独立记录（USER_REQUEST / PEER_GRACEFUL / IDLE_TIMEOUT / NO_PROGRESS / RESET /
  TLS_FAILURE / TRANSPORT_ERROR / RESOURCE_LIMIT / INTERNAL_ERROR）
- 最终 service 结果在所有 connection callback 完成后确定
- 稳定 peer-loss fault injection 测试并加入 CI

**新增模块**：`quic_connection.[ch]` — 连接状态机，从 `service.c` 拆出。

---

### P3：分层内存预算

**问题**：LSan 回答"对象最终是否释放"，运行时预算回答"释放前是否能把服务拖垮"。QUIC 框架的真正威胁不是
leak，是一个慢对端拖住 connection 导致 stream buffer 无界增长。

**分层结构**：

```
process budget
└── service budget
    └── connection budget
        ├── stream RX
        ├── stream TX
        ├── queued frames
        ├── task metadata
        └── file-transfer buffers
```

**接口**：

```c
int  ace_mem_charge(struct ace_mem_budget *, size_t);
void ace_mem_release(struct ace_mem_budget *, size_t);
```

charge 必须在分配前执行，失败时不分配。覆盖：整数溢出、double release、allocation failure
rollback、task 转移所有权、connection teardown、多级拒绝。

**超预算动作**：
- 单 stream 超限 → reset stream
- connection 总预算超限 → close connection
- service/process 压力 → 拒绝新任务或新连接
- 日志记录 current / limit / high-water mark / rejection count / close count

**注意**：ACE 无法精确统计 lsquic 和 BoringSSL 内部内存，计数器应明确标注
"ACE-owned accounted bytes"。

---

### P4：peer abort + queue saturation + 连接隔离测试

- 明确的 peer abort 集成测试（对端发 RESET_STREAM / CONNECTION_CLOSE）
- queue saturation 测试（填充 RX/TX 到上限，验证 backpressure）
- 连接隔离测试（一个失败连接不终止或破坏无关连接）

---

### P5：模块边界约定（持续执行）

**约定，不是一次性的 PR。** 后续新代码直接进入新模块，旧代码随修改逐步迁移。

**目标模块划分**：

```
Transport 层：
  quic_engine.[ch]        — 引擎配置、初始化、tick、调度、destroy
  quic_connection.[ch]    — 连接状态机
  quic_stream.[ch]        — stream context、RX/TX、backpressure
  quic_session.[ch]       — session resume 数据读写
  packet_io.[ch]          — UDP socket、zerocopy、ECN、pktinfo

TLS 层：
  tls_context.[ch]        — SSL context、证书、CA、SNI、ALPN
  tls_identity.[ch]       — hostname verification、secure/insecure policy

Protocol 层：
  protocol_types.h        — 固定宽度 wire 类型定义
  protocol_codec.[ch]     — wire ↔ domain object 转换
  protocol_limits.h       — 帧/流/连接上限

Task 层：
  task_dispatch.[ch]      — 任务调度
  task_sendfile.[ch]      — send-file 任务
  task_perf.[ch]          — 性能任务

Control 层：
  control_socket.[ch]     — Unix domain socket 控制接口
  control_command.[ch]    — 请求解析与结构化响应
  config.[ch]             — 配置管理
  runner.[ch]             — 事件循环与信号处理
```

**新模块规则**：
- 公开 API 前缀统一（`ace_protocol_*`、`ace_stream_*` 等）
- 模块负责释放自身创建的对象
- public/private header 分离
- 禁止跨模块直接访问内部 struct 字段
- 新模块必须带 focused test

**client/server 角色**：只提供角色策略（listen vs connect、不同 upstream 行为），不再各自实现底层生命周期。

---

### P6：对象所有权审计 + LSan

**固定规则**：
- runner owns services
- service owns engine and connections
- connection owns streams and active task
- stream owns RX/TX queues
- task owns task-specific buffers and file handles
- queue owns every enqueued sk_buff
- codec never owns caller buffers

每个对象只允许一个 destroy 入口，保证幂等或明确禁止重复调用。

LSan 在不受 ptrace 限制的环境中运行完整可执行文件和集成测试套件。修复并记录每个确认的 leak。

**当前状态（2026-08-13）**：第一轮所有权审计 + LSan 已完成。

- 修复 echo 生命周期：`upstream_echo_delete()` 统一为单一 destroy 入口（摘链 + 关 fd + 释放 rbuf/队列/自身），
  消除三处缺陷——accept/read_char 失败路径 free 未摘链导致的悬空指针、read_char/write_char ERROR 路径摘链未
  free 导致的泄漏、fd 关闭分散。删除死函数 `upstream_destroy_echo()`。
- LSan 全量（`ACE_SANITIZER=leak` 构建 + `smoke-test.sh` 跑 server/client 握手 + probe + SIGTERM 优雅关闭）：
  修复 `service_func()` 重复 `service_init_cert_hash()` 导致的 cert_hash 泄漏（272 B）；修复后 server 退出码 0、
  无泄漏报告。单元 + 契约测试 28/28 无泄漏。
- LSan 运行方式：`cmake -S . -B build/lsan -DACE_SANITIZER=leak` → build → `ACE_BUILD_DIR=build/lsan
  LSAN_OPTIONS=exitcode=23 bash scripts/smoke-test.sh`。

**剩余所有权项**（未审计）：connection/task/stream 的销毁幂等性（`quic_connection.c`、`service_on_read/write`
 的 TASK_EXIT/FAIL 路径、`lconn_ctx` 释放）尚待逐一核对；LSan 尚未接入 CI（P7 分解时加）。

**集成路径 sanitizer 覆盖缺口**（后续改进项，暂不改 CI）：

ASan/UBSan 当前只跑单元 + 契约测试，两个集成测试（TLS 握手、连接隔离）经 `-LE '^integration$'` 排除，
避免 stdbuf、预加载、超时和 QUIC 时序与 sanitizer 互相干扰。代价是 service.c / quic_engine.c /
quic_stream.c 的真实网络路径缺内存检测，这些路径只靠 Debug/Release 的功能性验证兜底。

后续：新增一个不使用 stdbuf、范围更小、可独立运行的 sanitizer QUIC smoke test，
覆盖一次最小握手 + probe 往返，补上这块空白。

---

### P7：CI 分解

当前 `ci.yml` 约 137 行。在 peer-loss、ARM64、性能测试加入前拆分为：

```
.github/workflows/
├── build.yml          — GCC/Clang × Debug/Release × architecture
├── sanitizer.yml      — ASan/UBSan，后续 LSan
├── fuzz.yml           — push/PR 短跑，schedule 长跑
└── integration.yml    — IPv4/IPv6、peer loss、abort、queue pressure
```

先完成 fault integration，再拆分（确保拆分不丢失覆盖）。缓存 key 必须包含
runner OS + architecture + compiler + dependency 脚本 hash。

---

### P8：性能观测（非硬门禁）

**PR 轻量检查**（仅明显退化检测）：
- 32–64 MB localhost 数据
- 预热后 3–5 次重复
- 使用中位数
- 记录 wall time、CPU time、吞吐、峰值 RSS
- 阈值宽松（低于固定最低吞吐才失败）
- 独立 `scripts/benchmark.sh`，不往 smoke test 堆逻辑

**定时基准**（稳定/自托管 runner）：
- 256 MB 或更大
- 单流 + 多流
- p50/p95
- 连续两次退化才报警
- 初期只告警，不阻断 PR

---

### P9：文档分层

```
README.md                    — 身份、快速开始、当前能力
docs/architecture.md         — 模块、线程、所有权、数据流
docs/protocol.md             — wire format、字节序、状态机、版本协商
docs/engineering-roadmap.md  — 未来任务与当前基线（唯一）
docs/assessments/            — 不可变历史快照（YYYY-MM-DD.md）
```

- assessment 发布后不再修改，文首标 `Status: snapshot` + `Superseded by: ...`
- `protocol.md` 与 codec 同步落地，golden vectors 同时作为协议文档示例
- 持续渐进执行，无需一次性完成全部迁移

---

### P10：ARM64 CI + 跨架构 golden vectors

- 协议 codec 的 golden vector 测试独立于 ARM64 binary 支持（在 P1 codec 阶段即可开始）
- ARM64 编译/单元/集成 CI 作为 build matrix 维度加入
- runner 选择：`ubuntu-24.04-arm` label
- ARM64 目前是 prepared code path，不是 supported platform；CI 通过后才能声称支持

---

### P11：发布 v0.1.0

**前置条件**（全部满足后再打 tag）：
1. TLS 默认认证
2. v1 fixed-width codec
3. peer-loss 状态机稳定
4. CI 全绿

**规则**：
- v0.x：允许协议和配置不兼容，changelog 必须明示
- annotated tag
- GitHub Release 附：功能摘要、已知限制、构建依赖 commit、测试矩阵、协议版本
- 维护手写 `CHANGELOG.md`
- 不承诺稳定 C API/ABI
- v1.0.0 才承诺协议兼容策略

---

## 已知死代码与遗留清理项

P5 控制面拆分时发现，暂未处理，记录待办：

- `src/upstream.c` 的 `upstream_accept_un()`（static，约 40 行）是死代码：`upstream_listen()` 注册的是
  `upstream_accept()`，后者同时处理 TCP 与 Unix socket 的 accept。`upstream_accept_un` 从未被引用。
  附带问题：`upstream_accept()` 对 Unix socket 连接仍用 `struct sockaddr_in` 读取对端地址，类型不匹配
  （仅影响 `inet_ntoa` 日志，不影响 accept 结果）。处理选项：删除死函数；或把 accept 地址类型改为
  `sockaddr_storage` 统一处理。
- `src/upstream.c` 的 `upstream_write_char()` 内有原作者遗留的未使用局部变量 `unsigned int *length`
  （`(unsigned int*)skb->head`），无任何读取，可直接删除。

另有一项独立功能债（非死代码，已在 P1「client/server 生命周期不对称」项下记录）：SEND 侧 `task->data`
仍是 native `upstream_skb_head` 布局、client upstream 仍发 native 结构，与 RECV 侧 wire codec 不对称，
端到端文件传输尚未打通。作为独立问题处理，不在死代码清理范围。

---

## 不做的

以下设计改动**不建议**当前阶段执行：

- 切换语言（C 合适当前需求）
- 替换 lsquic 或 libev（无证据需要）
- 引入 actor framework 或复杂线程模型
- 大重构 PR（按业务改动逐步建立新边界）
- 为 CI 分解引入 reusable workflow（项目逻辑不复杂，过早引入增加调试成本）

---

## 迁移规则

1. 每次改动只涉及一类问题（协议 / 生命周期 / 所有权，不混改）
2. 行为不变或行为变化有明确测试
3. 新模块有 focused unit test
4. IPv4/IPv6 smoke test 继续通过
5. ASan/UBSan 回归通过
6. 旧代码随相关修改迁移，不做无目的搬运

---

## 目标架构

```
Application / CLI
      │
      ▼
Control Plane           ← 配置、Unix socket、命令解析、生命周期
      │
      ▼
Task Layer              ← 调度、send-file、perf、内存预算
      │
      ▼
Protocol Layer          ← 版本协商、frame codec、capabilities
      │
      ▼
QUIC Transport          ← engine、connection 状态机、stream I/O
      │
      ▼
Platform I/O            ← UDP、pktinfo/ECN、地址处理、文件 I/O

横向能力：Resource accounting │ Observability │ TLS identity
```
