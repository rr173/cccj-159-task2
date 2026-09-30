"""HTTP 端到端测试：真实启动 ThreadingHTTPServer，经 socket 调用 REST API。"""
import io
import json
import socket
import unittest
import zipfile
import threading
from http.server import ThreadingHTTPServer
from urllib.request import Request, urlopen
from urllib.error import HTTPError

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.api import _make_handler
from app.runner import compute_input_fingerprint
from app.service import ECOService
from app.store import Store


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class ApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.svc = ECOService(Store(":memory:"))
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", free_port()), _make_handler(cls.svc))
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        cls.t = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.t.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def call(self, path, method="GET", body=None, raw=False):
        data = json.dumps(body).encode() if body is not None else None
        req = Request(self.base + path, data=data, method=method,
                      headers={"Content-Type": "application/json"})
        try:
            with urlopen(req, timeout=5) as r:
                payload = r.read()
                if raw:
                    return r.status, payload, dict(r.headers)
                return r.status, json.loads(payload)
        except HTTPError as e:
            return e.code, json.loads(e.read())

    def test_full_flow_via_http(self):
        s, d = self.call("/api/ecos", "POST", {
            "title": "HTTP 流", "owner": "net.eng", "affected_modules": ["alu"],
            "edits": {"alu": {"netlist": "MODULE alu; CELL HTTP_FIX; ENDMODULE"}}})
        self.assertEqual(s, 201)
        eid = d["id"]

        s, d = self.call(f"/api/ecos/{eid}/freeze", "POST", {"by": "net.eng"})
        self.assertEqual(s, 200)
        self.assertEqual(d["status"], "FROZEN")

        # Runner：拉输入 → 自算指纹 → 提交；按依赖图循环直到无 PENDING
        for _ in range(20):
            s, d = self.call(f"/api/ecos/{eid}")
            pending = [c["type"] for c in d["gate"]["checks"] if c["status"] == "PENDING"]
            if not pending:
                break
            for t in pending:
                s, pkt = self.call(f"/api/ecos/{eid}/checks/{t}/inputs")
                fp = compute_input_fingerprint(t, pkt["inputs"])
                s, resp = self.call(f"/api/ecos/{eid}/checks/{t}/results", "POST",
                                    {"run_id": pkt["run_id"], "fingerprint": fp,
                                     "verdict": "PASS", "runner_id": "ci-runner"})
                self.assertEqual(s, 200, resp)

        s, _ = self.call(f"/api/ecos/{eid}/signoff", "POST",
                         {"role": "TIMING_LEAD", "user": "t.u"})
        self.assertEqual(s, 200)
        # 同一人第二签 → 409
        s, err = self.call(f"/api/ecos/{eid}/signoff", "POST",
                           {"role": "METHODOLOGY_LEAD", "user": "t.u"})
        self.assertEqual(s, 409)
        self.assertEqual(err["error"], "DUAL_ROLE_CONFLICT")
        s, _ = self.call(f"/api/ecos/{eid}/signoff", "POST",
                         {"role": "METHODOLOGY_LEAD", "user": "m.u"})
        self.assertEqual(s, 200)

        s, rel = self.call(f"/api/ecos/{eid}/release", "POST", {"by": "net.eng"})
        self.assertEqual(s, 200)
        new_b = rel["new_baseline_id"]

        s, pkg = self.call(f"/api/baselines/diff?from=B-R0&to={new_b}")
        self.assertEqual(s, 200)
        self.assertEqual(pkg["summary"]["modules_changed"], ["alu"])

        s, data, headers = self.call(f"/api/baselines/diff.zip?from=B-R0&to={new_b}", raw=True)
        self.assertEqual(s, 200)
        self.assertIn("zip", headers.get("Content-Type", ""))
        z = zipfile.ZipFile(io.BytesIO(data))
        self.assertIn("manifest.json", z.namelist())

    def test_stale_result_rejected_via_http(self):
        s, d = self.call("/api/ecos", "POST", {
            "title": "迟到流", "owner": "o", "affected_modules": ["l2c"],
            "edits": {"l2c": {"netlist": "MODULE l2c; CELL LATE_FIX; ENDMODULE"}}})
        eid = d["id"]
        self.call(f"/api/ecos/{eid}/freeze", "POST", {"by": "o"})
        s, pkt = self.call(f"/api/ecos/{eid}/checks/TIMING_STA/inputs")
        fp = compute_input_fingerprint("TIMING_STA", pkt["inputs"])
        old_run = pkt["run_id"]
        self.call("/api/constraints", "POST",
                  {"delta": {"clk_period_ns": 1.00}, "by": "sdc"})
        s, err = self.call(f"/api/ecos/{eid}/checks/TIMING_STA/results", "POST",
                           {"run_id": old_run, "fingerprint": fp, "verdict": "PASS"})
        self.assertEqual(s, 409)
        self.assertEqual(err["detail"]["reason"], "STALE_SUPERSEDED")
        s, rej = self.call("/api/rejected-results")
        self.assertTrue(any(r["reason"] == "STALE_SUPERSEDED" for r in rej["rejected"]))

    def test_overlap_queue_via_http(self):
        s, a = self.call("/api/ecos", "POST", {
            "title": "占用", "owner": "a", "affected_modules": ["noc"],
            "edits": {"noc": {"netlist": "MODULE noc; CELL A_FIX; ENDMODULE"}}})
        self.call(f"/api/ecos/{a['id']}/freeze", "POST", {"by": "a"})
        s, b = self.call("/api/ecos", "POST", {
            "title": "后来", "owner": "b", "affected_modules": ["noc"],
            "edits": {"noc": {"netlist": "MODULE noc; CELL B_FIX; ENDMODULE"}}})
        s, bq = self.call(f"/api/ecos/{b['id']}/freeze", "POST", {"by": "b"})
        self.assertEqual(bq["status"], "QUEUED")
        self.assertEqual(bq["queue"][0]["module"], "noc")
        s, m = self.call(f"/api/ecos/{b['id']}/merge-into/{a['id']}", "POST",
                         {"by": "ccb", "module_winners": {"noc": "SOURCE_WINS"}})
        self.assertEqual(s, 200)
        self.assertEqual(m["freeze_epoch"], 2)
        self.assertIn("B_FIX", m["edits"]["noc"]["netlist"])

    def test_static_index(self):
        s, data, _ = self.call("/", raw=True)
        self.assertEqual(s, 200)
        self.assertIn("ECO".encode(), data)

    def test_404(self):
        s, err = self.call("/api/nope")
        self.assertEqual(s, 404)


if __name__ == "__main__":
    unittest.main(verbosity=2)
