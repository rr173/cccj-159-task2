# API 契约

基础路径 `http://<host>:8080`，全部 JSON。错误响应统一为：

```json
{ "error": "CODE", "message": "可读说明", "detail": { "reason": "..." } }
```

## 状态与原因码

- **ECO 状态**：`DRAFT / FROZEN / QUEUED / REBASE_REQUIRED / RELEASING / RELEASED / MERGED / ABORTED`
- **检查状态**：`PENDING / BLOCKED / PASS / FAIL / SUPERSEDED`（门洁面可能显示 `MISSING`）
- **拒收原因 reason**：
  - `FINGERPRINT_MISMATCH` 结果指纹与冻结输入不符（拿错基线/输入被改）
  - `STALE_SUPERSEDED` run 已因纪元变化作废，结果迟到
  - `ALREADY_SUBMITTED` 同一 run 重复提交
  - `DEPENDENCY_BLOCKED` 依赖前置尚未全部 PASS
  - `ECO_NOT_ACTIVE` ECO 不在 FROZEN 态
  - `BASE_CONSTRAINT_CHANGED` 基础约束更新导致在验单整体作废（系统事件留痕）

## 端点

### 基线与目录
| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/baselines` | 发布基线列表 |
| GET | `/api/baselines/{id}` | 基线完整不可变快照 |
| GET | `/api/baselines/diff?from=&to=` | 结构化差异包 |
| GET | `/api/baselines/diff.zip?from=&to=` | ZIP 差异包（before/after/diff/矩阵/结果/签核）|
| GET | `/api/catalog` | 验证矩阵目录（必需性、依赖、指纹作用域）|
| GET | `/api/constraints` | 当前发布基线与工作约束版本 |
| GET | `/api/workbench` | 工作台聚合视图 |
| GET | `/api/rejected-results` | 全部拒收/作废留痕 |

### ECO
| 方法 | 路径 | Body / 说明 |
|---|---|---|
| POST | `/api/ecos` | `{title, owner, affected_modules[], edits:{m:{netlist}}}` → 201 |
| POST | `/api/ecos/{id}/edits` | `{edits, by}` 仅 DRAFT/REBASE_REQUIRED |
| POST | `/api/ecos/{id}/freeze` | `{by}` 冲突时转 QUEUED，否则冻结+触发矩阵 |
| POST | `/api/ecos/{id}/abort` | `{by}` 释放锁并推动排队单晋升 |
| GET | `/api/ecos` / `/api/ecos/{id}` | 列表（含门禁摘要）/ 详情（含 gate/queue/release）|

### 验证（Runner 协议）
| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/ecos/{id}/checks/{type}/inputs` | 拉冻结输入包（含 expected_fingerprint 供核对）|
| POST | `/api/ecos/{id}/checks/{type}/results` | `{run_id, fingerprint, verdict:PASS|FAIL, result, runner_id}` |
| POST | `/api/ecos/{id}/checks/{type}/rerun` | `{by}` 仅 FAIL 可重跑；旧尝试 SUPERSEDED，新 run 绑当前指纹 |

Runner **必须**对 `inputs` 自行按作用域计算 SHA-256 摘要（紧凑规范 JSON：
键排序、无空白、`ensure_ascii`），服务端不接受缺失/不符指纹。

### 签核与发布
| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/ecos/{id}/signoff` | `{role: TIMING_LEAD|METHODOLOGY_LEAD, user}` 门禁红时 409；同一人双签 409 |
| POST | `/api/ecos/{id}/release` | `{by, failpoint?}` 门禁/双签不满足 409 且状态不变；`failpoint=AFTER_PHASE1` 注入崩溃 |
| POST | `/api/ecos/{id}/release/resume` | 从中断点幂等恢复 |

### 冲突与基础约束
| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/ecos/{src}/merge-into/{tgt}` | `{by, module_winners:{m:TARGET_WINS|SOURCE_WINS}}`；src 须 QUEUED、tgt 须 FROZEN 且确有未决阻塞；合并后 tgt 纪元+1 整轮重跑 |
| POST | `/api/constraints` | `{delta:{...}, by, note}` 存在 RELEASING 单时 409；否则在验 FROZEN 单全部转 REBASE_REQUIRED |
| POST | `/api/admin/reset` | 重置为种子数据 |

## 典型时序（一次合规发布）

```
create → freeze → (Runner: inputs→自算指纹→results) ×依赖图
       → TIMING_LEAD signoff → METHODOLOGY_LEAD signoff(不同人)
       → release(阶段1锁状态 → 阶段2原子写 B-R{n}、推进 trunk)
```

## 典型时序（迟到结果）

```
ECO FROZEN 全绿 → POST /api/constraints 收紧时钟
  → ECO=REBASE_REQUIRED, 旧 run 全 SUPERSEDED, 旧签核失效
迟到 Runner 回传旧 run_id → 409 STALE_SUPERSEDED（rejected_result 留痕）
工程师 freeze(refreeze, epoch=2) → 矩阵重跑 → 双签 → 才能发布
```
