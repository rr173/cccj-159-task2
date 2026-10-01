"""核心领域服务：ECO 冻结、验证矩阵依赖调度、签核门禁、基线发布与差异包。

关键不变量：
1. 每条 check_run 绑定冻结时按作用域计算的指纹；迟到结果指纹不符一律拒收并留痕，
   绝不与其他基线的旧结果拼接。
2. 冻结纪元(freeze_epoch)变化（基础约束刷新 / 合并扩张 / rebase）即作废旧结果与签核。
3. 模块锁互斥；重叠 ECO 要么排队(QUEUED)，要么经裁决合并(MERGED)。
4. 发布是可恢复的两阶段事务；只有全部必需检查针对同一基线通过且双角色不同人签核，
   才能形成新发布基线。
"""
from __future__ import annotations

import copy
import hashlib
import io
import json
import sqlite3
import zipfile
from collections import defaultdict
from datetime import datetime, timezone
from difflib import unified_diff

from .store import CHECKS, Store, utcnow

ROLE_TIMING = "TIMING_LEAD"
ROLE_METHOD = "METHODOLOGY_LEAD"
SIGNOFF_ROLES = [ROLE_TIMING, ROLE_METHOD]


class ECOError(Exception):
    def __init__(self, code: str, message: str, http_status: int = 409, extra=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status
        self.extra = extra or {}


# ---------------------------------------------------------------- 指纹与快照

def canon(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def fp_json(obj) -> str:
    return hashlib.sha256(canon(obj)).hexdigest()[:16]


def parse_ts(s, field="time") -> datetime:
    """解析 ISO-8601 时间（naive 视为 UTC），返回 aware datetime。"""
    if not isinstance(s, str) or not s.strip():
        raise ECOError("BAD_TIME", f"{field} 缺失或不是字符串", 400)
    try:
        dt = datetime.fromisoformat(s.strip().replace("Z", "+00:00"))
    except ValueError:
        raise ECOError("BAD_TIME", f"{field} 时间格式非法: {s!r}（需 ISO-8601）", 400)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def canon_ts(dt: datetime) -> str:
    """统一规范化为 UTC 秒精度字符串，保证词法序 == 时序。"""
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def matrix_catalog():
    return [
        {"type": t, "label": c["label"], "required": c["required"],
         "depends_on": list(c["depends_on"]), "scopes": list(c["scopes"])}
        for t, c in CHECKS.items()
    ]


def build_snapshot(modules: dict, constraints: dict, affected: list[str], note: str = ""):
    """构造不可变冻结快照：网表 + 约束 + 受影响模块 + 验证矩阵。"""
    return {
        "schema": "chip-eco-baseline/1",
        "note": note,
        "frozen_at": utcnow(),
        "affected_modules": sorted(affected),
        "constraints": constraints,
        "modules": copy.deepcopy(modules),
        "verification_matrix": matrix_catalog(),
    }


def snapshot_fingerprint(snap: dict) -> str:
    return fp_json({
        "affected_modules": snap["affected_modules"],
        "constraints": snap["constraints"],
        "modules": snap["modules"],
        "verification_matrix": snap["verification_matrix"],
    })


def scope_fingerprint(snap: dict, scopes: list[str]) -> str:
    """检查只对其作用域内的冻结输入负责；矩阵恒为输入的一部分。"""
    obj: dict = {"verification_matrix": snap["verification_matrix"]}
    if "netlist" in scopes:
        obj["modules"] = {
            m: {"netlist": d["netlist"], "version": d["version"]}
            for m, d in sorted(snap["modules"].items())
        }
    if "sdc" in scopes:
        obj["constraints"] = snap["constraints"]
    if "modules" in scopes:
        obj["affected_modules"] = snap["affected_modules"]
    return fp_json(obj)


# ---------------------------------------------------------------- 数据整形

def _baseline_dict(row):
    d = dict(row)
    d["snapshot"] = json.loads(d.pop("snapshot_json"))
    return d


def _eco_dict(row):
    d = dict(row)
    for k in ("affected_modules_json", "edits_json", "snapshot_json", "merge_of_json"):
        d[k.removesuffix("_json")] = json.loads(d.pop(k)) if d[k] is not None else None
    return d


# ---------------------------------------------------------------- 服务

class ECOService:
    def __init__(self, store: Store):
        self.s = store

    # ===== 通用 =====
    def _audit(self, c, action: str, entity=None, actor=None, detail=None):
        c.execute("INSERT INTO audit_log(actor,action,entity,at,detail_json) VALUES(?,?,?,?,?)",
                  (actor, action, entity, utcnow(), json.dumps(detail or {}, ensure_ascii=False)))

    def _reject(self, reason, run=None, detail=None):
        self.s.conn.execute(
            "INSERT INTO rejected_result(run_id,eco_id,check_type,reason,detail_json,received_at)"
            " VALUES(?,?,?,?,?,?)",
            (run["id"] if run else None, run["eco_id"] if run else None,
             run["check_type"] if run else None, reason,
             json.dumps(detail or {}, ensure_ascii=False), utcnow()))

    def _get_eco(self, eco_id: str):
        row = self.s.q_one("SELECT * FROM eco WHERE id=?", (eco_id,))
        if not row:
            raise ECOError("ECO_NOT_FOUND", f"ECO {eco_id} 不存在", 404)
        return row

    def _get_baseline(self, bid: str):
        row = self.s.q_one("SELECT * FROM baseline WHERE id=?", (bid,))
        if not row:
            raise ECOError("BASELINE_NOT_FOUND", f"基线 {bid} 不存在", 404)
        return _baseline_dict(row)

    def _trunk(self, c):
        return c.execute("SELECT * FROM trunk WHERE id=1").fetchone()

    def _base_snapshot(self, c):
        t = self._trunk(c)
        return _baseline_dict(c.execute(
            "SELECT * FROM baseline WHERE id=?", (t["base_id"],)).fetchone())["snapshot"]

    # ===== 基线查询 =====
    def list_baselines(self):
        rows = self.s.q_all("SELECT * FROM baseline ORDER BY revision")
        out = []
        for r in rows:
            d = _baseline_dict(r)
            snap = d["snapshot"]
            out.append({
                "id": d["id"], "revision": d["revision"], "parent_id": d["parent_id"],
                "eco_id": d["eco_id"], "created_at": d["created_at"],
                "fingerprint": d["fingerprint"],
                "affected_modules": snap["affected_modules"],
                "constraints_version_note": snap.get("note", ""),
                "module_count": len(snap["modules"]),
            })
        return out

    def baseline_detail(self, bid):
        return self._get_baseline(bid)

    def check_catalog(self):
        return {"checks": matrix_catalog()}

    # ===== ECO 生命周期 =====
    def create_eco(self, title: str, owner: str, affected_modules: list[str],
                   edits: dict | None = None) -> dict:
        if not title or not owner:
            raise ECOError("BAD_REQUEST", "title/owner 必填", 400)
        with self.s.tx() as c:
            base = self._base_snapshot(c)
            unknown = [m for m in affected_modules if m not in base["modules"]]
            if unknown:
                raise ECOError("UNKNOWN_MODULE", f"模块不存在: {unknown}", 400)
            if not affected_modules:
                raise ECOError("EMPTY_SCOPE", "至少选择一个受影响模块", 400)
            edits = edits or {}
            bad = [m for m in edits if m not in affected_modules]
            if bad:
                raise ECOError("EDIT_OUT_OF_SCOPE", f"编辑了未声明受影响的模块: {bad}", 400)
            for m, e in edits.items():
                if not isinstance(e, dict) or not isinstance(e.get("netlist"), str):
                    raise ECOError("BAD_EDIT", f"模块 {m} 的编辑必须形如 {{'netlist': '...'}}", 400)
            n = c.execute("SELECT COUNT(*) k FROM eco").fetchone()["k"]
            eco_id = f"ECO-{n + 1:03d}"
            c.execute(
                "INSERT INTO eco(id,title,owner,status,affected_modules_json,edits_json,created_at)"
                " VALUES(?,?,?,?,?,?,?)",
                (eco_id, title, owner, "DRAFT",
                 json.dumps(sorted(affected_modules)), json.dumps(edits, ensure_ascii=False),
                 utcnow()))
            self._audit(c, "eco.create", eco_id, owner, {"title": title})
            return self.eco_detail(eco_id, c)

    def update_edits(self, eco_id, edits: dict, by: str):
        with self.s.tx() as c:
            eco = self._get_eco(eco_id)
            if eco["status"] not in ("DRAFT", "REBASE_REQUIRED"):
                raise ECOError("NOT_EDITABLE",
                               f"状态 {eco['status']} 下不可修改编辑（需先中止或刷新）", 409)
            modules = json.loads(eco["affected_modules_json"])
            bad = [m for m in edits if m not in modules]
            if bad:
                raise ECOError("EDIT_OUT_OF_SCOPE", f"模块超出受影响范围: {bad}", 400)
            merged = {**json.loads(eco["edits_json"]), **edits}
            c.execute("UPDATE eco SET edits_json=? WHERE id=?",
                      (json.dumps(merged, ensure_ascii=False), eco_id))
            self._audit(c, "eco.edit", eco_id, by, {"keys": sorted(edits)})
            return self.eco_detail(eco_id, c)

    def _effective_modules(self, base_modules: dict, affected, edits):
        mods = copy.deepcopy(base_modules)
        for m in affected:
            if m in edits:
                mods[m] = {"netlist": edits[m]["netlist"],
                           "version": base_modules[m]["version"] + 1}
        return mods

    def _dispatch(self, c, eco):
        """按依赖图创建新一轮检查：无依赖 PENDING，其余 BLOCKED 等待前置通过。

        run id 带冻结纪元：纪元变化后旧 run 全部 SUPERSEDED，新 run 重新绑定
        当前冻结输入的指纹，杜绝跨基线结果拼接。
        """
        snap = json.loads(eco["snapshot_json"])
        epoch = eco["freeze_epoch"]
        for t, spec in CHECKS.items():
            attempt = c.execute(
                "SELECT COALESCE(MAX(attempt),0)+1 a FROM check_run WHERE eco_id=? AND check_type=?",
                (eco["id"], t)).fetchone()["a"]
            c.execute(
                "INSERT INTO check_run(id,eco_id,check_type,attempt,status,required,"
                "depends_on_json,expected_fp) VALUES(?,?,?,?,?,?,?,?)",
                (f"{eco['id']}:{t}:e{epoch}:a{attempt}", eco["id"], t, attempt,
                 "PENDING" if not spec["depends_on"] else "BLOCKED",
                 int(spec["required"]), json.dumps(spec["depends_on"]),
                 scope_fingerprint(snap, spec["scopes"])))

    def _supersede_runs(self, c, eco_id, reason: str):
        """纪元变化：该 ECO 全部既有检查作废（含已 PASS），迟到提交将被拒收。"""
        cur = c.execute(
            "SELECT * FROM check_run WHERE eco_id=? AND status!='SUPERSEDED'", (eco_id,))
        rows = cur.fetchall()
        for r in rows:
            c.execute("UPDATE check_run SET status='SUPERSEDED' WHERE id=?", (r["id"],))
        return len(rows)

    def _void_signoffs(self, c, eco_id, reason=""):
        """纪元变化使既有签核失效：不删除记录，仅标记作废——已完成的签核保留
        当时身份与代理链用于审计，但不再计入门禁。"""
        rows = c.execute(
            "SELECT * FROM signoff WHERE eco_id=? AND voided_at IS NULL",
            (eco_id,)).fetchall()
        if not rows:
            return 0
        c.execute("UPDATE signoff SET voided_at=?, void_reason=? "
                  "WHERE eco_id=? AND voided_at IS NULL", (utcnow(), reason, eco_id))
        self._audit(c, "eco.signoff.void", eco_id, "system", {
            "reason": reason,
            "voided": [{"role": r["role"], "user": r["user"],
                        "delegator": r["delegator"], "delegation_id": r["delegation_id"],
                        "epoch": r["epoch"]} for r in rows]})
        return len(rows)

    def _lock_conflicts(self, c, modules, exclude_eco=None):
        q = ("SELECT module, eco_id FROM module_lock WHERE module IN (%s)"
             % ",".join("?" * len(modules)))
        args = list(modules)
        rows = c.execute(q, args).fetchall()
        return [dict(r) for r in rows if r["eco_id"] != exclude_eco]

    def freeze_eco(self, eco_id: str, by: str) -> dict:
        """提交 ECO：冻结网表/约束/受影响模块/验证矩阵并触发检查。

        模块被占用时不冻结，转入 QUEUED 排队并登记阻塞关系。
        """
        with self.s.tx() as c:
            eco = self._get_eco(eco_id)
            if eco["status"] not in ("DRAFT", "REBASE_REQUIRED"):
                raise ECOError("NOT_FREEZABLE",
                               f"状态 {eco['status']} 不可冻结", 409)
            modules = json.loads(eco["affected_modules_json"])
            edits = json.loads(eco["edits_json"])
            conflicts = self._lock_conflicts(c, modules, exclude_eco=eco_id)
            if conflicts:
                c.execute("UPDATE eco SET status='QUEUED' WHERE id=?", (eco_id,))
                for cf in conflicts:
                    exists = c.execute(
                        "SELECT 1 FROM queue_entry WHERE eco_id=? AND blocker_eco_id=? "
                        "AND module=? AND resolved_at IS NULL",
                        (eco_id, cf["eco_id"], cf["module"])).fetchone()
                    if not exists:
                        c.execute(
                            "INSERT INTO queue_entry(eco_id,blocker_eco_id,module,created_at)"
                            " VALUES(?,?,?,?)",
                            (eco_id, cf["eco_id"], cf["module"], utcnow()))
                self._audit(c, "eco.queue", eco_id, by, {"conflicts": conflicts})
                return self.eco_detail(eco_id, c)

            trunk = self._trunk(c)
            base_snap = self._base_snapshot(c)
            constraints = json.loads(trunk["working_constraints_json"])
            eff_mods = self._effective_modules(base_snap["modules"], modules, edits)
            snap = build_snapshot(eff_mods, constraints, modules,
                                 note=f"{eco_id} 冻结于 {trunk['base_id']}")
            fp = snapshot_fingerprint(snap)
            epoch = eco["freeze_epoch"] + 1
            c.execute(
                "UPDATE eco SET status='FROZEN',submitted_at=COALESCE(submitted_at,?),"
                "frozen_at=?,parent_baseline_id=?,base_revision_at_freeze=?,"
                "constraints_version_at_freeze=?,snapshot_json=?,fingerprint=?,freeze_epoch=?"
                " WHERE id=?",
                (utcnow(), utcnow(), trunk["base_id"], trunk["base_revision"],
                 trunk["constraints_version"], json.dumps(snap, ensure_ascii=False), fp,
                 epoch, eco_id))
            self._supersede_runs(c, eco_id, "refreeze")
            self._void_signoffs(c, eco_id, "refreeze")
            for m in modules:
                # 重冻结（rebase/合并后）时锁可能仍属于本 ECO
                c.execute("INSERT OR IGNORE INTO module_lock(module,eco_id,acquired_at)"
                          " VALUES(?,?,?)", (m, eco_id, utcnow()))
            eco = self._get_eco(eco_id)
            self._dispatch(c, eco)
            self._audit(c, "eco.freeze", eco_id, by,
                        {"fingerprint": fp, "epoch": epoch, "modules": modules})
            return self.eco_detail(eco_id, c)

    def abort_eco(self, eco_id, by):
        with self.s.tx() as c:
            eco = self._get_eco(eco_id)
            if eco["status"] in ("RELEASED", "MERGED", "RELEASING"):
                raise ECOError("NOT_ABORTABLE", f"状态 {eco['status']} 不可中止", 409)
            c.execute("UPDATE eco SET status='ABORTED' WHERE id=?", (eco_id,))
            c.execute("DELETE FROM module_lock WHERE eco_id=?", (eco_id,))
            c.execute("UPDATE queue_entry SET resolved_at=?, resolution='ABORT' "
                      "WHERE blocker_eco_id=? AND resolved_at IS NULL", (utcnow(), eco_id))
            c.execute("UPDATE queue_entry SET resolved_at=?, resolution='ABORT' "
                      "WHERE eco_id=? AND resolved_at IS NULL", (utcnow(), eco_id))
            self._audit(c, "eco.abort", eco_id, by)
            self._promote_waiting(c)
            return self.eco_detail(eco_id, c)

    # ===== 验证矩阵调度 =====
    def _active_runs(self, c, eco_id):
        return c.execute(
            "SELECT * FROM check_run WHERE eco_id=? AND status!='SUPERSEDED'",
            (eco_id,)).fetchall()

    def _advance(self, c, eco_id):
        """前置全部 PASS 后解除 BLOCKED；前置 FAIL 则继续阻塞（依赖图不调度）。"""
        runs = {r["check_type"]: r for r in self._active_runs(c, eco_id)}
        for t, r in runs.items():
            if r["status"] != "BLOCKED":
                continue
            deps = json.loads(r["depends_on_json"])
            if deps and all(runs.get(d) and runs[d]["status"] == "PASS" for d in deps):
                c.execute("UPDATE check_run SET status='PENDING' WHERE id=?", (r["id"],))

    def check_inputs(self, eco_id, check_type):
        """Runner 拉取冻结输入包，并据其内容自行计算/核对指纹。"""
        if check_type not in CHECKS:
            raise ECOError("UNKNOWN_CHECK", f"未知检查类型 {check_type}", 400)
        with self.s.lock:
            run = self.s.q_one(
                "SELECT * FROM check_run WHERE eco_id=? AND check_type=? AND status!='SUPERSEDED'",
                (eco_id, check_type))
            if not run:
                raise ECOError("RUN_NOT_FOUND", "检查不存在或已作废", 404)
            eco = self._get_eco(eco_id)
            snap = json.loads(eco["snapshot_json"])
            spec = CHECKS[check_type]
            inputs = {"verification_matrix": snap["verification_matrix"]}
            if "netlist" in spec["scopes"]:
                inputs["modules"] = snap["modules"]
            if "sdc" in spec["scopes"]:
                inputs["constraints"] = snap["constraints"]
            if "modules" in spec["scopes"]:
                inputs["affected_modules"] = snap["affected_modules"]
            return {
                "run_id": run["id"], "eco_id": eco_id, "check_type": check_type,
                "status": run["status"], "expected_fingerprint": run["expected_fp"],
                "scopes": spec["scopes"], "inputs": inputs,
            }

    def submit_result(self, run_id, fingerprint, verdict, result=None, runner_id="runner-0"):
        """提交验证结果。指纹不符 / 已作废 / 前置未过 / 重复提交一律拒收，绝不复用。

        拒收记录在独立事务中持久化：校验事务回滚不影响审计留痕。
        """
        result = result or {}
        try:
            with self.s.tx() as c:
                run = c.execute("SELECT * FROM check_run WHERE id=?", (run_id,)).fetchone()
                if not run:
                    raise ECOError("RUN_NOT_FOUND", f"运行 {run_id} 不存在", 404)
                eco = c.execute("SELECT * FROM eco WHERE id=?", (run["eco_id"],)).fetchone()

                def reject(reason, detail):
                    raise ECOError("RESULT_REJECTED",
                                   f"结果拒收: {reason}（旧结果不得拼接复用）", 409,
                                   {"reason": reason, **detail})

                if run["status"] == "SUPERSEDED":
                    reject("STALE_SUPERSEDED",
                           {"run_id": run_id, "eco_freeze_epoch": eco["freeze_epoch"]})
                if eco["status"] != "FROZEN":
                    reject("ECO_NOT_ACTIVE", {"eco_status": eco["status"]})
                if verdict not in ("PASS", "FAIL"):
                    reject("BAD_VERDICT", {"verdict": verdict})
                if not fingerprint:
                    reject("MISSING_FINGERPRINT", {})
                if fingerprint != run["expected_fp"]:
                    reject("FINGERPRINT_MISMATCH",
                           {"submitted_fp": fingerprint, "expected_fp": run["expected_fp"],
                            "check_type": run["check_type"]})
                if run["status"] == "BLOCKED":
                    reject("DEPENDENCY_BLOCKED",
                           {"depends_on": json.loads(run["depends_on_json"])})
                if run["status"] in ("PASS", "FAIL"):
                    reject("ALREADY_SUBMITTED", {"existing": run["status"]})

                c.execute(
                    "UPDATE check_run SET status=?,result_fp=?,result_json=?,submitted_at=?,"
                    "runner_id=? WHERE id=?",
                    (verdict, fingerprint, json.dumps(result, ensure_ascii=False), utcnow(),
                     runner_id, run_id))
                self._audit(c, "check.result", run_id, runner_id,
                            {"verdict": verdict, "check": run["check_type"]})
                self._advance(c, run["eco_id"])
                return self.eco_detail(run["eco_id"], c)
        except ECOError as e:
            if e.code == "RESULT_REJECTED":
                with self.s.tx() as c:
                    r = c.execute("SELECT * FROM check_run WHERE id=?", (run_id,)).fetchone()
                    self._reject(e.extra.get("reason", "REJECTED"), r,
                                 {k: v for k, v in e.extra.items() if k != "reason"})
            raise

    def rerun_check(self, eco_id, check_type, by):
        """FAIL 的检查可重跑：旧尝试标记 SUPERSEDED，新尝试重新绑定当前冻结指纹。"""
        if check_type not in CHECKS:
            raise ECOError("UNKNOWN_CHECK", f"未知检查类型 {check_type}", 400)
        with self.s.tx() as c:
            eco = self._get_eco(eco_id)
            if eco["status"] != "FROZEN":
                raise ECOError("NOT_FROZEN", "仅 FROZEN 状态可重跑检查", 409)
            run = c.execute(
                "SELECT * FROM check_run WHERE eco_id=? AND check_type=? AND status!='SUPERSEDED'",
                (eco_id, check_type)).fetchone()
            if not run:
                raise ECOError("RUN_NOT_FOUND", "检查不存在", 404)
            if run["status"] != "FAIL":
                raise ECOError("NOT_RERUNNABLE",
                               f"当前状态 {run['status']}，仅 FAIL 可重跑", 409)
            attempt = run["attempt"] + 1
            c.execute("UPDATE check_run SET status='SUPERSEDED' WHERE id=?", (run["id"],))
            snap = json.loads(eco["snapshot_json"])
            spec = CHECKS[check_type]
            deps = json.loads(run["depends_on_json"])
            active = {r["check_type"]: r for r in self._active_runs(c, eco_id)}
            unblocked = all(active.get(d) and active[d]["status"] == "PASS" for d in deps) if deps else True
            c.execute(
                "INSERT INTO check_run(id,eco_id,check_type,attempt,status,required,"
                "depends_on_json,expected_fp) VALUES(?,?,?,?,?,?,?,?)",
                (f"{eco_id}:{check_type}:e{eco['freeze_epoch']}:a{attempt}", eco_id, check_type, attempt,
                 "PENDING" if unblocked else "BLOCKED", int(spec["required"]),
                 json.dumps(deps), scope_fingerprint(snap, spec["scopes"])))
            self._audit(c, "check.rerun", f"{eco_id}:{check_type}", by, {"attempt": attempt})
            return self.eco_detail(eco_id, c)

    # ===== 临时代理签核 =====
    @staticmethod
    def _delegation_status(d, now: str) -> str:
        if d["revoked_at"]:
            return "REVOKED"
        if now < d["effective_from"]:
            return "PENDING"
        if now > d["effective_to"]:
            return "EXPIRED"
        return "ACTIVE"

    def _delegation_dict(self, row, now: str | None = None):
        d = dict(row)
        d["status"] = self._delegation_status(d, now or utcnow())
        return d

    def configure_delegation(self, role, delegator, delegate,
                             effective_from, effective_to, by):
        """管理员配置临时代理：代理人在 [生效,失效] 窗口内可代被代理人行使签核角色。

        幂等：同一配置（角色/被代理人/代理人/窗口）已存在未撤销记录时直接返回，
        不生成重复有效记录；已撤销的同配置允许重新创建。
        """
        if role not in SIGNOFF_ROLES:
            raise ECOError("BAD_ROLE", f"角色须为 {SIGNOFF_ROLES}", 400)
        if not delegator or not delegate:
            raise ECOError("BAD_REQUEST", "delegator/delegate 必填", 400)
        if delegator == delegate:
            raise ECOError("BAD_DELEGATION", "代理人与被代理人不能是同一自然人", 400)
        frm = canon_ts(parse_ts(effective_from, "effective_from"))
        to = canon_ts(parse_ts(effective_to, "effective_to"))
        if frm >= to:
            raise ECOError("BAD_TIME_WINDOW", "生效时间必须早于失效时间", 400)
        with self.s.tx() as c:
            dup = c.execute(
                "SELECT * FROM delegation WHERE role=? AND delegator=? AND delegate=?"
                " AND effective_from=? AND effective_to=? AND revoked_at IS NULL",
                (role, delegator, delegate, frm, to)).fetchone()
            if dup:
                out = self._delegation_dict(dup)
                out["deduplicated"] = True
                return out
            try:
                cur = c.execute(
                    "INSERT INTO delegation(role,delegator,delegate,effective_from,"
                    "effective_to,created_by,created_at) VALUES(?,?,?,?,?,?,?)",
                    (role, delegator, delegate, frm, to, by, utcnow()))
            except sqlite3.IntegrityError:
                # 并发重复提交撞上部分唯一索引：按幂等返回既有记录
                dup = c.execute(
                    "SELECT * FROM delegation WHERE role=? AND delegator=? AND delegate=?"
                    " AND effective_from=? AND effective_to=? AND revoked_at IS NULL",
                    (role, delegator, delegate, frm, to)).fetchone()
                out = self._delegation_dict(dup)
                out["deduplicated"] = True
                return out
            did = cur.lastrowid
            self._audit(c, "delegation.create", f"delegation:{did}", by,
                        {"id": did, "role": role, "delegator": delegator,
                         "delegate": delegate, "effective_from": frm, "effective_to": to})
            return self._delegation_dict(c.execute(
                "SELECT * FROM delegation WHERE id=?", (did,)).fetchone())

    def revoke_delegation(self, delegation_id, by):
        """随时撤销代理：撤销即刻生效，此后的代理签核一律拒绝（已完成的签核保留）。"""
        with self.s.tx() as c:
            d = c.execute("SELECT * FROM delegation WHERE id=?",
                          (delegation_id,)).fetchone()
            if not d:
                raise ECOError("DELEGATION_NOT_FOUND",
                               f"代理记录 {delegation_id} 不存在", 404)
            if d["revoked_at"]:
                raise ECOError("DELEGATION_ALREADY_REVOKED", "该代理已撤销", 409)
            c.execute("UPDATE delegation SET revoked_at=?, revoked_by=? WHERE id=?",
                      (utcnow(), by, delegation_id))
            self._audit(c, "delegation.revoke", f"delegation:{delegation_id}", by,
                        {"role": d["role"], "delegator": d["delegator"],
                         "delegate": d["delegate"]})
            return self._delegation_dict(c.execute(
                "SELECT * FROM delegation WHERE id=?", (delegation_id,)).fetchone())

    def list_delegations(self):
        with self.s.lock:
            now = utcnow()
            return [self._delegation_dict(r, now) for r in self.s.q_all(
                "SELECT * FROM delegation ORDER BY id DESC")]

    def current_signers(self):
        """各签核角色当前时刻可签人员：角色负责人本人 + 生效中的临时代理（含来源与有效期）。"""
        out = {r: {"role": r, "delegates": []} for r in SIGNOFF_ROLES}
        for d in self.list_delegations():
            if d["status"] == "ACTIVE":
                out[d["role"]]["delegates"].append({
                    "delegation_id": d["id"], "delegate": d["delegate"],
                    "delegator": d["delegator"],
                    "effective_from": d["effective_from"],
                    "effective_to": d["effective_to"]})
        return out

    def _check_delegation(self, c, role, delegator, delegate):
        """按签核动作发生时刻校验代理授权：未生效/已过期/已撤销一律拒绝。"""
        d = c.execute(
            "SELECT * FROM delegation WHERE role=? AND delegator=? AND delegate=?"
            " ORDER BY id DESC LIMIT 1", (role, delegator, delegate)).fetchone()
        if not d:
            raise ECOError("DELEGATION_NOT_FOUND",
                           f"不存在 {delegator} 授权 {delegate} 行使 {role} 的代理记录", 403)
        now = utcnow()
        if d["revoked_at"]:
            raise ECOError("DELEGATION_REVOKED",
                           f"代理已于 {d['revoked_at']} 被 {d['revoked_by']} 撤销", 403,
                           {"delegation_id": d["id"], "revoked_at": d["revoked_at"]})
        if now < d["effective_from"]:
            raise ECOError("DELEGATION_NOT_YET_EFFECTIVE",
                           f"代理 {d['effective_from']} 才生效，当前时刻无权签核", 403,
                           {"delegation_id": d["id"],
                            "effective_from": d["effective_from"]})
        if now > d["effective_to"]:
            raise ECOError("DELEGATION_EXPIRED",
                           f"代理已于 {d['effective_to']} 失效", 403,
                           {"delegation_id": d["id"], "effective_to": d["effective_to"]})
        return d

    # ===== 门禁与签核 =====
    def gate(self, eco_row, c):
        eco_id = eco_row["id"]
        runs = c.execute(
            "SELECT * FROM check_run r WHERE eco_id=? AND attempt=("
            "SELECT MAX(attempt) FROM check_run WHERE eco_id=r.eco_id AND check_type=r.check_type)"
            " ORDER BY check_type", (eco_id,)).fetchall()
        checks_out, required_pass = [], True
        for t, spec in CHECKS.items():
            r = next((x for x in runs if x["check_type"] == t), None)
            status = r["status"] if r else "MISSING"
            fp_ok = bool(r and r["result_fp"] and r["result_fp"] == r["expected_fp"])
            satisfied = status == "PASS" and fp_ok
            if spec["required"] and not satisfied:
                required_pass = False
            deps = json.loads(r["depends_on_json"]) if r else []
            dep_status = {d: next((x["status"] for x in runs if x["check_type"] == d), "MISSING")
                          for d in deps}
            checks_out.append({
                "type": t, "label": spec["label"], "required": spec["required"],
                "status": status, "fingerprint_ok": fp_ok, "satisfied": satisfied,
                "depends_on": deps, "dep_status": dep_status,
                "submitted_at": r["submitted_at"] if r else None,
                "runner_id": r["runner_id"] if r else None,
                "result": json.loads(r["result_json"]) if r and r["result_json"] else None,
            })
        signoffs = [dict(r) for r in c.execute(
            "SELECT * FROM signoff WHERE eco_id=? ORDER BY role", (eco_id,)).fetchall()]
        epoch = eco_row["freeze_epoch"]
        valid_sigs = [s for s in signoffs if s["voided_at"] is None
                      and s["epoch"] == epoch
                      and s["overall_fp"] == eco_row["fingerprint"]]
        roles = {s["role"]: s["user"] for s in valid_sigs}
        dual = all(r in roles for r in SIGNOFF_ROLES) and len(set(roles.values())) == 2
        return {
            "checks": checks_out,
            "required_all_pass": required_pass,
            "signoffs": signoffs,
            "valid_signoffs": valid_sigs,
            "dual_role_complete": dual,
            "green": required_pass,
            "releasable": required_pass and dual,
        }

    def signoff(self, eco_id, role, user, on_behalf_of=None):
        """签核。on_behalf_of 非空时为代理签核：user 是实际操作人（自然人），
        必须存在动作发生时刻生效的代理授权；签核记录保留当时身份与代理链。"""
        if role not in SIGNOFF_ROLES:
            raise ECOError("BAD_ROLE", f"角色须为 {SIGNOFF_ROLES}", 400)
        if not user:
            raise ECOError("BAD_REQUEST", "user 必填", 400)
        if on_behalf_of and on_behalf_of == user:
            raise ECOError("BAD_DELEGATION", "代理人与被代理人不能是同一自然人", 400)
        with self.s.tx() as c:
            eco = self._get_eco(eco_id)
            if eco["status"] != "FROZEN":
                raise ECOError("NOT_FROZEN", f"状态 {eco['status']} 不可签核", 409)
            delegator, delegation_id = None, None
            if on_behalf_of:
                d = self._check_delegation(c, role, on_behalf_of, user)
                delegator, delegation_id = on_behalf_of, d["id"]
            g = self.gate(eco, c)
            if not g["green"]:
                raise ECOError("GATE_RED", "必需检查未全部针对当前基线通过，禁止签核", 409,
                               {"checks": [{"type": x["type"], "status": x["status"]}
                                           for x in g["checks"] if x["required"]
                                           and not x["satisfied"]]})
            # 双角色必须是两个不同自然人：直接签与代理签均按实际操作人计
            other = next((s for s in g["valid_signoffs"]
                          if s["role"] != role and s["user"] == user), None)
            if other:
                raise ECOError("DUAL_ROLE_CONFLICT",
                               "两个签核角色必须由不同人承担（禁止同一人双签）", 409)
            c.execute("DELETE FROM signoff WHERE eco_id=? AND role=? AND epoch=?",
                      (eco_id, role, eco["freeze_epoch"]))
            c.execute(
                "INSERT INTO signoff(eco_id,role,user,delegator,delegation_id,epoch,"
                "overall_fp,at) VALUES(?,?,?,?,?,?,?,?)",
                (eco_id, role, user, delegator, delegation_id,
                 eco["freeze_epoch"], eco["fingerprint"], utcnow()))
            self._audit(c, "eco.signoff", eco_id, user,
                        {"role": role, "delegator": delegator,
                         "delegation_id": delegation_id})
            return self.eco_detail(eco_id, c)

    # ===== 基础约束刷新 =====
    def update_base_constraints(self, delta: dict, by: str, note: str = ""):
        if not delta:
            raise ECOError("BAD_REQUEST", "delta 为空", 400)
        with self.s.tx() as c:
            if c.execute("SELECT 1 FROM eco WHERE status='RELEASING'").fetchone():
                raise ECOError("RELEASE_IN_PROGRESS",
                               "存在发布中的 ECO，为保证原子性拒绝约束更新", 409)
            trunk = self._trunk(c)
            cur = json.loads(trunk["working_constraints_json"])
            new = {**cur, **delta}
            version = trunk["constraints_version"] + 1
            c.execute("UPDATE trunk SET working_constraints_json=?, constraints_version=?",
                      (json.dumps(new, ensure_ascii=False, sort_keys=True), version))
            c.execute(
                "INSERT INTO constraint_event(base_id,version,delta_json,by,at,note)"
                " VALUES(?,?,?,?,?,?)",
                (trunk["base_id"], version, json.dumps(delta, ensure_ascii=False), by,
                 utcnow(), note))
            affected_ecos = []
            for eco in c.execute("SELECT * FROM eco WHERE status='FROZEN'").fetchall():
                snap = json.loads(eco["snapshot_json"])
                if snap["constraints"] != new:
                    c.execute("UPDATE eco SET status='REBASE_REQUIRED' WHERE id=?", (eco["id"],))
                    c.execute(
                        "INSERT INTO rejected_result(run_id,eco_id,check_type,reason,detail_json,"
                        "received_at) VALUES(?,?,?,?,?,?)",
                        (None, eco["id"], None, "BASE_CONSTRAINT_CHANGED",
                         json.dumps({"old": snap["constraints"], "new": new,
                                     "constraints_version": version}, ensure_ascii=False),
                         utcnow()))
                    self._supersede_runs(c, eco["id"], "constraint-bump")
                    self._void_signoffs(c, eco["id"], "constraint-bump")
                    affected_ecos.append(eco["id"])
            self._audit(c, "constraint.update", trunk["base_id"], by,
                        {"delta": delta, "version": version, "rebased_ecos": affected_ecos})
            return {"constraints_version": version, "constraints": new,
                    "rebased_ecos": affected_ecos}

    # ===== 排队与合并裁决 =====
    def _promote_waiting(self, c):
        """阻塞全部解除的排队 ECO → REBASE_REQUIRED（必须基于新基线重新冻结，不得直接沿用）。"""
        promoted = []
        for eco in c.execute("SELECT id FROM eco WHERE status='QUEUED'").fetchall():
            eco_id = eco["id"]
            open_blockers = c.execute(
                "SELECT COUNT(*) k FROM queue_entry WHERE eco_id=? AND resolved_at IS NULL",
                (eco_id,)).fetchone()["k"]
            if open_blockers == 0:
                c.execute("UPDATE eco SET status='REBASE_REQUIRED' WHERE id=?", (eco_id,))
                self._audit(c, "eco.promote", eco_id, "system",
                            {"reason": "blockers cleared; rebasing onto newest base"})
                promoted.append(eco_id)
        return promoted

    def adjudicate_merge(self, source_eco_id, target_eco_id, by: str,
                         module_winners: dict | None = None):
        """合并裁决：将排队中的 source ECO 并入已冻结 target ECO。

        module_winners: {module: "TARGET_WINS"|"SOURCE_WINS"}，同模块双改默认 TARGET_WINS。
        合并使 target 冻结范围扩张 → 纪元 +1，旧结果与签核全部作废重跑。
        """
        module_winners = module_winners or {}
        with self.s.tx() as c:
            src = self._get_eco(source_eco_id)
            tgt = self._get_eco(target_eco_id)
            if src["status"] != "QUEUED":
                raise ECOError("SOURCE_NOT_QUEUED",
                               f"被合并方状态须为 QUEUED，实际 {src['status']}", 409)
            if tgt["status"] != "FROZEN":
                raise ECOError("TARGET_NOT_FROZEN",
                               f"并入方状态须为 FROZEN，实际 {tgt['status']}", 409)
            blocked = c.execute(
                "SELECT 1 FROM queue_entry WHERE eco_id=? AND blocker_eco_id=? "
                "AND resolved_at IS NULL",
                (source_eco_id, target_eco_id)).fetchone()
            if not blocked:
                raise ECOError("NOT_BLOCKING", "两个 ECO 不存在未决的模块阻塞关系", 409)

            src_mods = set(json.loads(src["affected_modules_json"]))
            tgt_mods = set(json.loads(tgt["affected_modules_json"]))
            added = src_mods - tgt_mods
            conflicts = self._lock_conflicts(c, list(added), exclude_eco=target_eco_id)
            if conflicts:
                raise ECOError("MERGE_STILL_BLOCKED",
                               "合并后仍与其他进行中 ECO 冲突，请先排队/裁决剩余冲突", 409,
                               {"conflicts": conflicts})

            src_edits = json.loads(src["edits_json"])
            tgt_edits = json.loads(tgt["edits_json"])
            merged_edits = dict(tgt_edits)
            overlap = src_mods & tgt_mods
            for m, e in src_edits.items():
                if m in overlap:
                    # 重叠模块由裁决决定：SOURCE_WINS 采用排队方编辑；TARGET_WINS（默认）
                    # 维持占用方对该模块的冻结内容（占用方未编辑即保留基线版本，丢弃源编辑）
                    if module_winners.get(m, "TARGET_WINS") == "SOURCE_WINS":
                        merged_edits[m] = e
                else:
                    merged_edits[m] = e
            merged_modules = sorted(tgt_mods | src_mods)

            # 在 target 的冻结基线之上重建快照（保持同一父基线与约束版本）
            parent = c.execute("SELECT * FROM baseline WHERE id=?",
                               (tgt["parent_baseline_id"],)).fetchone()
            base_snap = json.loads(parent["snapshot_json"])
            constraints = json.loads(tgt["snapshot_json"])["constraints"]
            eff = self._effective_modules(base_snap["modules"], merged_modules, merged_edits)
            snap = build_snapshot(eff, constraints, merged_modules,
                                 note=f"{target_eco_id} 合并 {source_eco_id} 后重新冻结")
            fp = snapshot_fingerprint(snap)
            epoch = tgt["freeze_epoch"] + 1
            c.execute(
                "UPDATE eco SET affected_modules_json=?,edits_json=?,snapshot_json=?,"
                "fingerprint=?,freeze_epoch=? WHERE id=?",
                (json.dumps(merged_modules), json.dumps(merged_edits, ensure_ascii=False),
                 json.dumps(snap, ensure_ascii=False), fp, epoch, target_eco_id))
            self._supersede_runs(c, target_eco_id, "merge")
            self._void_signoffs(c, target_eco_id, "merge")
            for m in added:
                c.execute("INSERT INTO module_lock(module,eco_id,acquired_at) VALUES(?,?,?)",
                          (m, target_eco_id, utcnow()))
            c.execute(
                "INSERT INTO adjudication(source_eco_id,target_eco_id,decision,"
                "merged_modules_json,merged_edits_json,by,at) VALUES(?,?,?,?,?,?,?)",
                (source_eco_id, target_eco_id, "MERGE", json.dumps(merged_modules),
                 json.dumps(merged_edits, ensure_ascii=False), by, utcnow()))
            c.execute("UPDATE eco SET status='MERGED', merge_of_json=? WHERE id=?",
                      (json.dumps({"into": target_eco_id, "at": utcnow()}), source_eco_id))
            c.execute("DELETE FROM module_lock WHERE eco_id=?", (source_eco_id,))
            c.execute("UPDATE queue_entry SET resolved_at=?, resolution='MERGED' "
                      "WHERE blocker_eco_id=? AND resolved_at IS NULL",
                      (utcnow(), source_eco_id))
            c.execute("UPDATE queue_entry SET resolved_at=?, resolution='MERGED' "
                      "WHERE eco_id=? AND resolved_at IS NULL",
                      (utcnow(), source_eco_id))
            tgt = self._get_eco(target_eco_id)
            self._dispatch(c, tgt)
            self._audit(c, "eco.merge", target_eco_id, by,
                        {"source": source_eco_id, "modules": merged_modules, "epoch": epoch})
            self._promote_waiting(c)
            return self.eco_detail(target_eco_id, c)

    # ===== 发布（两阶段、可恢复） =====
    def release_start(self, eco_id, by, failpoint=None):
        with self.s.tx() as c:
            eco = self._get_eco(eco_id)
            existing = c.execute("SELECT * FROM release WHERE eco_id=?", (eco_id,)).fetchone()
            if existing and existing["state"] == "PUBLISHED":
                return {"status": "ALREADY_PUBLISHED",
                        "new_baseline_id": existing["new_baseline_id"]}
            if existing and existing["state"] == "RELEASING":
                raise ECOError("RELEASE_PENDING",
                               "发布处于中断态，请调用 resume 完成或恢复", 409)
            if eco["status"] != "FROZEN":
                raise ECOError("NOT_FROZEN", f"状态 {eco['status']} 不可发布", 409)
            g = self.gate(eco, c)
            if not g["releasable"]:
                raise ECOError("NOT_RELEASABLE",
                               "门禁未全绿或双角色签核不全，拒绝发布", 409,
                               {"green": g["green"], "dual": g["dual_role_complete"]})
            c.execute("UPDATE eco SET status='RELEASING' WHERE id=?", (eco_id,))
            c.execute(
                "INSERT INTO release(eco_id,state,started_at,failpoint) VALUES(?,?,?,?)",
                (eco_id, "RELEASING", utcnow(), failpoint))
            c.execute(
                "INSERT INTO release_journal(eco_id,event,at,detail_json) VALUES(?,?,?,?)",
                (eco_id, "PHASE1_LOCKED", utcnow(),
                 json.dumps({"fingerprint": eco["fingerprint"], "epoch": eco["freeze_epoch"],
                             "failpoint": failpoint}, ensure_ascii=False)))
            self._audit(c, "release.start", eco_id, by, {"failpoint": failpoint})
        # 阶段1已提交（RELEASING 持久化）。此处故障 = 真实崩溃：阶段2未执行，可 resume。
        if failpoint == "AFTER_PHASE1":
            raise ECOError("RELEASE_INTERRUPTED",
                           "模拟发布在阶段1提交后崩溃：RELEASING 已持久化，可 resume 恢复", 500,
                           {"eco_id": eco_id, "resume": f"/api/ecos/{eco_id}/release/resume"})
        return self.release_finish(eco_id, by)

    def release_finish(self, eco_id, by="system"):
        with self.s.tx() as c:
            rel = c.execute("SELECT * FROM release WHERE eco_id=?", (eco_id,)).fetchone()
            if not rel:
                raise ECOError("NO_RELEASE", "该 ECO 没有进行中的发布", 409)
            if rel["state"] == "PUBLISHED":
                return {"status": "ALREADY_PUBLISHED", "new_baseline_id": rel["new_baseline_id"]}
            eco = self._get_eco(eco_id)
            if eco["status"] != "RELEASING":
                raise ECOError("BAD_STATE", f"ECO 状态 {eco['status']} 异常", 409)
            # 恢复时重新验证：中断期间不允许任何变更（约束更新/中止均被拒绝），这里是纵深防御
            g = self.gate(eco, c)
            if not g["releasable"]:
                raise ECOError("NOT_RELEASABLE", "恢复时校验失败，基线不再满足发布条件", 409)

            snap = json.loads(eco["snapshot_json"])
            rev = c.execute("SELECT COALESCE(MAX(revision),0)+1 r FROM baseline").fetchone()["r"]
            new_id = f"B-R{rev}"
            c.execute(
                "INSERT INTO baseline(id,revision,parent_id,created_at,eco_id,snapshot_json,"
                "fingerprint,published_by) VALUES(?,?,?,?,?,?,?,?)",
                (new_id, rev, eco["parent_baseline_id"], utcnow(), eco_id,
                 json.dumps(snap, ensure_ascii=False), eco["fingerprint"], by))
            c.execute("UPDATE trunk SET base_id=?, base_revision=? WHERE id=1",
                      (new_id, rev))
            c.execute("UPDATE eco SET status='RELEASED' WHERE id=?", (eco_id,))
            c.execute("UPDATE release SET state='PUBLISHED',new_baseline_id=?,finished_at=? "
                      "WHERE eco_id=?", (new_id, utcnow(), eco_id))
            c.execute("DELETE FROM module_lock WHERE eco_id=?", (eco_id,))
            c.execute("UPDATE queue_entry SET resolved_at=?, resolution='AUTO_PROMOTE' "
                      "WHERE blocker_eco_id=? AND resolved_at IS NULL",
                      (utcnow(), eco_id))
            # 其他仍在验证的 FROZEN 单：其父基线已不是最新 trunk，冻结快照中含
            # 旧版模块（即使模块不重叠），必须 rebase 到新基线后重跑，绝不带旧内容发布。
            stale = c.execute("SELECT id FROM eco WHERE status='FROZEN'").fetchall()
            for r in stale:
                sid = r["id"]
                c.execute("UPDATE eco SET status='REBASE_REQUIRED' WHERE id=?", (sid,))
                c.execute(
                    "INSERT INTO rejected_result(run_id,eco_id,check_type,reason,detail_json,"
                    "received_at) VALUES(?,?,?,?,?,?)",
                    (None, sid, None, "BASELINE_PUBLISHED",
                     json.dumps({"published_baseline": new_id, "by_eco": eco_id},
                                ensure_ascii=False), utcnow()))
                self._supersede_runs(c, sid, "new-baseline-published")
                self._void_signoffs(c, sid, "new-baseline-published")
                self._audit(c, "eco.rebase_required", sid, "system",
                            {"reason": "newer baseline published", "baseline": new_id})
            c.execute(
                "INSERT INTO release_journal(eco_id,event,at,detail_json) VALUES(?,?,?,?)",
                (eco_id, "PUBLISHED", utcnow(), json.dumps({"new_baseline_id": new_id})))
            self._audit(c, "release.publish", eco_id, by, {"baseline": new_id})
            self._promote_waiting(c)
            return {"status": "PUBLISHED", "new_baseline_id": new_id, "revision": rev}

    def resume_release(self, eco_id, by="system"):
        return self.release_finish(eco_id, by)

    # ===== 详情 / 工作台 =====
    def eco_detail(self, eco_id, c=None):
        def q(conn):
            eco = conn.execute("SELECT * FROM eco WHERE id=?", (eco_id,)).fetchone()
            if not eco:
                raise ECOError("ECO_NOT_FOUND", f"ECO {eco_id} 不存在", 404)
            d = _eco_dict(eco)
            d["gate"] = self.gate(eco, conn)
            d["queue"] = [dict(r) for r in conn.execute(
                "SELECT * FROM queue_entry WHERE eco_id=? AND resolved_at IS NULL",
                (eco_id,)).fetchall()]
            d["blocks"] = [dict(r) for r in conn.execute(
                "SELECT * FROM queue_entry WHERE blocker_eco_id=? AND resolved_at IS NULL",
                (eco_id,)).fetchall()]
            rel = conn.execute("SELECT * FROM release WHERE eco_id=?", (eco_id,)).fetchone()
            d["release"] = dict(rel) if rel else None
            return d
        if c is not None:
            return q(c)
        with self.s.lock:
            return q(self.s.conn)

    def list_ecos(self):
        with self.s.lock:
            rows = self.s.q_all("SELECT * FROM eco ORDER BY id")
            out = []
            for r in rows:
                d = _eco_dict(r)
                d.pop("snapshot", None)
                g = self.gate(r, self.s.conn)
                d["green"] = g["green"]
                d["releasable"] = g["releasable"]
                d["required_all_pass"] = g["required_all_pass"]
                d["dual_role_complete"] = g["dual_role_complete"]
                d["check_summary"] = {x["type"]: x["status"] for x in g["checks"]}
                out.append(d)
            return out

    def workbench(self):
        with self.s.lock:
            return {
                "baselines": self.list_baselines(),
                "ecos": self.list_ecos(),
                "catalog": matrix_catalog(),
                "roles": SIGNOFF_ROLES,
                "locks": [dict(r) for r in self.s.q_all("SELECT * FROM module_lock")],
                "rejected_results": [dict(r) for r in self.s.q_all(
                    "SELECT * FROM rejected_result ORDER BY seq DESC LIMIT 20")],
                "recent_audit": [dict(r) for r in self.s.q_all(
                    "SELECT seq,actor,action,entity,at FROM audit_log ORDER BY seq DESC LIMIT 30")],
                "constraints": self.current_constraints(),
                "delegations": self.list_delegations(),
                "current_signers": self.current_signers(),
            }

    def current_constraints(self):
        with self.s.lock:
            t = self.s.q_one("SELECT * FROM trunk WHERE id=1")
            return {"base_id": t["base_id"], "base_revision": t["base_revision"],
                    "constraints_version": t["constraints_version"],
                    "constraints": json.loads(t["working_constraints_json"])}

    # ===== 基线差异包 =====
    def _diff_constraints(self, old, new):
        keys = sorted(set(old) | set(new))
        items = []
        for k in keys:
            if k not in old:
                items.append({"key": k, "change": "ADDED", "new": new[k]})
            elif k not in new:
                items.append({"key": k, "change": "REMOVED", "old": old[k]})
            elif old[k] != new[k]:
                items.append({"key": k, "change": "CHANGED", "old": old[k], "new": new[k]})
        return items

    def _diff_modules(self, old, new):
        names = sorted(set(old) | set(new))
        items = []
        for m in names:
            if m not in old:
                items.append({"module": m, "change": "ADDED",
                              "after": new[m], "unified_diff": None})
            elif m not in new:
                items.append({"module": m, "change": "REMOVED",
                              "before": old[m], "unified_diff": None})
            elif old[m].get("netlist") != new[m].get("netlist") or \
                    old[m].get("version") != new[m].get("version"):
                before, after = old[m]["netlist"].splitlines(), new[m]["netlist"].splitlines()
                diff = "\n".join(unified_diff(
                    before, after, fromfile=f"{m}.v.before", tofile=f"{m}.v.after", lineterm=""))
                items.append({"module": m, "change": "CHANGED",
                              "before": old[m], "after": new[m], "unified_diff": diff})
        return items

    def diff_package(self, from_id, to_id):
        b_old, b_new = self._get_baseline(from_id), self._get_baseline(to_id)
        s_old, s_new = b_old["snapshot"], b_new["snapshot"]
        mod_diff = self._diff_modules(s_old["modules"], s_new["modules"])
        sdc_diff = self._diff_constraints(s_old["constraints"], s_new["constraints"])
        eco = None
        signoffs, check_results = [], []
        if b_new["eco_id"]:
            with self.s.lock:
                er = self.s.q_one("SELECT * FROM eco WHERE id=?", (b_new["eco_id"],))
                if er:
                    eco = {"id": er["id"], "title": er["title"], "owner": er["owner"]}
                    signoffs = [dict(r) for r in self.s.q_all(
                        "SELECT role,user,delegator,delegation_id,epoch,overall_fp,at "
                        "FROM signoff WHERE eco_id=? AND voided_at IS NULL",
                        (b_new["eco_id"],))]
                    check_results = [dict(r) for r in self.s.q_all(
                        "SELECT check_type,attempt,status,required,result_fp,expected_fp,"
                        "runner_id,submitted_at FROM check_run WHERE eco_id=? "
                        "AND status!='SUPERSEDED' ORDER BY check_type", (b_new["eco_id"],))]
        changed = [d["module"] for d in mod_diff if d["change"] == "CHANGED"]
        added = [d["module"] for d in mod_diff if d["change"] == "ADDED"]
        removed = [d["module"] for d in mod_diff if d["change"] == "REMOVED"]
        return {
            "format": "chip-eco-baseline-diff/1",
            "created_at": utcnow(),
            "from": {"id": b_old["id"], "revision": b_old["revision"],
                     "fingerprint": b_old["fingerprint"]},
            "to": {"id": b_new["id"], "revision": b_new["revision"],
                   "fingerprint": b_new["fingerprint"], "eco": eco},
            "summary": {"modules_changed": changed, "modules_added": added,
                        "modules_removed": removed,
                        "constraints_changed": [d["key"] for d in sdc_diff
                                                if d["change"] == "CHANGED"],
                        "affected_in_new": s_new["affected_modules"]},
            "modules": mod_diff,
            "constraints": sdc_diff,
            "verification": {
                "matrix": s_new["verification_matrix"],
                "results": check_results,
                "signoffs": signoffs,
                "dual_role_distinct_users": len({s["role"] for s in signoffs}) == 2
                    and len({s["user"] for s in signoffs}) == 2,
            },
        }

    def diff_zip(self, from_id, to_id) -> bytes:
        pkg = self.diff_package(from_id, to_id)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("manifest.json", json.dumps(pkg, ensure_ascii=False, indent=2))
            z.writestr("constraints/sdc.before.json",
                       json.dumps(self._get_baseline(from_id)["snapshot"]["constraints"],
                                  ensure_ascii=False, indent=2, sort_keys=True))
            z.writestr("constraints/sdc.after.json",
                       json.dumps(self._get_baseline(to_id)["snapshot"]["constraints"],
                                  ensure_ascii=False, indent=2, sort_keys=True))
            for d in pkg["modules"]:
                if d["change"] == "CHANGED":
                    z.writestr(f"modules/{d['module']}.before.v", d["before"]["netlist"])
                    z.writestr(f"modules/{d['module']}.after.v", d["after"]["netlist"])
                    z.writestr(f"modules/{d['module']}.diff", d["unified_diff"] or "")
            z.writestr("verification/matrix.json",
                       json.dumps(pkg["verification"]["matrix"], ensure_ascii=False, indent=2))
            z.writestr("verification/results.json",
                       json.dumps(pkg["verification"]["results"], ensure_ascii=False, indent=2))
            z.writestr("verification/signoffs.json",
                       json.dumps(pkg["verification"]["signoffs"], ensure_ascii=False, indent=2))
            readme = (
                f"基线差异包 {pkg['from']['id']} -> {pkg['to']['id']}\n\n"
                f"变更模块: {pkg['summary']['modules_changed'] or '无'}\n"
                f"新增模块: {pkg['summary']['modules_added'] or '无'}\n"
                f"约束变更: {pkg['summary']['constraints_changed'] or '无'}\n"
                f"双角色签核: {'满足(不同人)' if pkg['verification']['dual_role_distinct_users'] else '不满足'}\n"
                f"目标基线指纹: {pkg['to']['fingerprint']}\n")
            z.writestr("README.txt", readme)
        return buf.getvalue()

    def rejected_results(self):
        with self.s.lock:
            return [dict(r) for r in self.s.q_all(
                "SELECT * FROM rejected_result ORDER BY seq DESC")]
