import time

from fastapi.testclient import TestClient

from penumbra.server import app


def test_api_end_to_end(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with TestClient(app) as c:
        assert c.get("/").status_code == 200
        r = c.post("/api/investigations", json={"pace": 0}).json()
        for _ in range(100):
            s = c.get("/api/state").json()
            if s["status"] == "awaiting_approval":
                break
            time.sleep(0.05)
        assert s["status"] == "awaiting_approval" and s["id"] == r["id"]
        cards = [x for x in s["cards"] if x["status"] == "pending"]
        dual = next(x for x in cards if x["tier"] == "DUAL")
        for x in cards:
            assert c.post(f"/api/cards/{x['id']}/approve", json={"approver": "lena.fischer"}).status_code == 200
        dup = c.post(f"/api/cards/{dual['id']}/approve", json={"approver": "lena.fischer"})
        assert dup.status_code == 400 and "two-person" in dup.json()["detail"]
        assert c.post(f"/api/cards/{dual['id']}/approve", json={"approver": "alex.morgan"}).status_code == 200
        assert c.get("/api/state").json()["status"] == "closed"
        assert "After-Action Brief" in c.get("/api/report").text
        assert c.get("/api/audit").json()["verify"]["ok"]
        t = c.post("/api/audit/tamper-test").json()
        assert t["verify"]["ok"] is False
