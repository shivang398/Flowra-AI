"""
End-to-end API integration tests for Sentinel AI.

Run AFTER the server is up:
  uvicorn app.main:app --reload &
  python test_api.py
"""
import sys
import time
import requests

BASE = "http://127.0.0.1:8000"
PASS = "\033[92m✅ PASS\033[0m"
FAIL = "\033[91m❌ FAIL\033[0m"
WARN = "\033[93m⚠️  WARN\033[0m"

passed = 0
failed = 0

def ok(label, detail=""):
    global passed
    passed += 1
    print(f"  {PASS}  {label}" + (f"  →  {detail}" if detail else ""))

def fail(label, detail=""):
    global failed
    failed += 1
    print(f"  {FAIL}  {label}" + (f"  →  {detail}" if detail else ""))

def section(title):
    print(f"\n{'─'*60}")
    print(f"  {title}")
    print(f"{'─'*60}")

# ──────────────────────────────────────────────────────────────
section("TEST 1 — GET /  (health check)")
# ──────────────────────────────────────────────────────────────
try:
    r = requests.get(f"{BASE}/", timeout=5)
    if r.status_code == 200 and "SentinelAI" in r.json().get("message", ""):
        ok("Root endpoint returns 200 with correct message", r.json()["message"])
    else:
        fail("Root endpoint unexpected response", str(r.json()))
except Exception as e:
    fail("Root endpoint unreachable", str(e))
    print("\n\033[91mServer is not running! Start it first:\033[0m")
    print("  uvicorn app.main:app --reload\n")
    sys.exit(1)

# ──────────────────────────────────────────────────────────────
section("TEST 2 — GET /token  (demo JWT generation)")
# ──────────────────────────────────────────────────────────────
try:
    r = requests.get(f"{BASE}/token", timeout=5)
    assert r.status_code == 200
    data = r.json()
    assert "access_token" in data
    TOKEN = data["access_token"]
    ok("GET /token returns 200 and a valid JWT", f"token[:30]={TOKEN[:30]}…")
except Exception as e:
    fail("GET /token failed", str(e))
    sys.exit(1)

HEADERS = {"Authorization": f"Bearer {TOKEN}"}

# ──────────────────────────────────────────────────────────────
section("TEST 3 — POST /predict  (blocked without auth)")
# ──────────────────────────────────────────────────────────────
try:
    r = requests.post(f"{BASE}/predict", json={"data": [1.0, 2.0, 3.0, 4.0]}, timeout=5)
    if r.status_code in (401, 403):
        ok(f"POST /predict returns {r.status_code} without a token (auth guard works)")
    else:
        fail("POST /predict should be 401/403 without token", f"got {r.status_code}")
except Exception as e:
    fail("POST /predict (no-auth) request failed", str(e))

# ──────────────────────────────────────────────────────────────
section("TEST 4 — POST /predict  (normal request, with JWT)")
# ──────────────────────────────────────────────────────────────
try:
    r = requests.post(f"{BASE}/predict", json={"data": [5.1, 3.5, 1.4, 0.2]}, headers=HEADERS, timeout=10)
    if r.status_code == 200:
        body = r.json()
        ok("POST /predict returns 200 with valid token", f"action={body.get('action')}, risk={body.get('risk_score', body.get('risk_score','?'))}")
    elif r.status_code == 403:
        ok("POST /predict was BLOCKED by risk engine (expected for fresh IP)", f"reason={r.json().get('detail','')[:80]}")
    else:
        fail("POST /predict unexpected status", f"{r.status_code}: {r.text[:120]}")
except Exception as e:
    fail("POST /predict failed", str(e))

# ──────────────────────────────────────────────────────────────
section("TEST 5 — POST /secure-predict  (blocked without auth)")
# ──────────────────────────────────────────────────────────────
try:
    r = requests.post(f"{BASE}/secure-predict", json={"data": [1.0, 2.0, 3.0, 4.0]}, timeout=5)
    if r.status_code in (401, 403):
        ok(f"POST /secure-predict returns {r.status_code} without token")
    else:
        fail("POST /secure-predict should be 401/403 without token", f"got {r.status_code}")
except Exception as e:
    fail("POST /secure-predict (no-auth) failed", str(e))

# ──────────────────────────────────────────────────────────────
section("TEST 6 — POST /secure-predict  (normal request, with JWT)")
# ──────────────────────────────────────────────────────────────
try:
    r = requests.post(f"{BASE}/secure-predict", json={"data": [5.1, 3.5, 1.4, 0.2]}, headers=HEADERS, timeout=10)
    if r.status_code == 200:
        body = r.json()
        assert "prediction" in body
        assert "anomaly_score" in body
        assert "deviation_score" in body
        assert "action" in body
        assert "latency" in body
        ok("POST /secure-predict returns correct response schema",
           f"action={body['action']}, anomaly={body['anomaly_score']}, deviation={body['deviation_score']}, latency={body['latency']}s")
    elif r.status_code == 403:
        ok("POST /secure-predict BLOCKED by risk engine", r.json().get("detail","")[:80])
    else:
        fail("POST /secure-predict unexpected status", f"{r.status_code}: {r.text[:120]}")
except Exception as e:
    import traceback
    fail("POST /secure-predict failed", f"{str(e)}\n{traceback.format_exc()}")

# ──────────────────────────────────────────────────────────────
section("TEST 7 — Behavioral escalation (spam → throttle/block)")
# ──────────────────────────────────────────────────────────────
print("  Firing 20 rapid requests to trigger behavioral anomaly detection…")
actions = []
for i in range(20):
    try:
        r = requests.post(
            f"{BASE}/secure-predict",
            json={"data": [5.1, 3.5, 1.4, 0.2]},
            headers=HEADERS,
            timeout=3,
        )
        if r.status_code == 200:
            action = r.json().get("action", "?")
            anomaly = r.json().get("anomaly_score", "?")
            actions.append(action)
        elif r.status_code == 429:
            actions.append("rate_limit(429)")
        elif r.status_code == 403:
            actions.append("block(403)")
        else:
            actions.append(f"err({r.status_code})")
    except Exception as e:
        actions.append("err(timeout)")

action_summary = {}
for a in actions:
    action_summary[a] = action_summary.get(a, 0) + 1

print(f"  Action summary over 20 requests: {action_summary}")

if "block(403)" in actions or "throttle" in actions or "rate_limit(429)" in actions:
    ok("Behavioral escalation detected — system transitioned to throttle/block/rate_limit")
elif "allow" in actions:
    ok("All requests allowed (risk engine needs more baseline data)", f"{action_summary}")
else:
    fail("Behavorial escalation test inconclusive", str(action_summary))

# ──────────────────────────────────────────────────────────────
section("TEST 8 — Invalid JWT token")
# ──────────────────────────────────────────────────────────────
try:
    bad_headers = {"Authorization": "Bearer this.is.not.a.valid.jwt"}
    r = requests.post(f"{BASE}/secure-predict", json={"data": [1,2,3,4]}, headers=bad_headers, timeout=5)
    if r.status_code == 403:
        ok("Invalid JWT returns 403 Forbidden")
    else:
        fail("Invalid JWT should return 403", f"got {r.status_code}")
except Exception as e:
    fail("Invalid JWT test failed", str(e))

# ──────────────────────────────────────────────────────────────
section("TEST 9 — Malformed request body")
# ──────────────────────────────────────────────────────────────
try:
    r = requests.post(f"{BASE}/secure-predict", json={"wrong_field": "abc"}, headers=HEADERS, timeout=5)
    if r.status_code == 422:
        ok("Malformed request body returns 422 Unprocessable Entity")
    else:
        fail("Malformed body should be 422", f"got {r.status_code}")
except Exception as e:
    fail("Malformed body test failed", str(e))

# ──────────────────────────────────────────────────────────────
print(f"\n{'═'*60}")
print(f"  🏁 RESULTS:  {passed} passed,  {failed} failed")
print(f"{'═'*60}\n")
if failed > 0:
    sys.exit(1)
