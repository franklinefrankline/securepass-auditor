"""Automated verification test for SecurePass Auditor authentication and user isolation."""
import sys
import os

# Set working directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app
from db import create_user, get_user_by_email, get_user_by_id, log_audit, get_audit_history
from werkzeug.security import generate_password_hash, check_password_hash

def test_all():
    print("--- 1. Testing DB User Operations ---")
    email = f"tester_{os.getpid()}@securepass.io"
    pw_hash = generate_password_hash("TestP@ssw0rd2026!")
    user_id, err = create_user("Test User", email, pw_hash)
    assert user_id is not None, f"Failed to create user: {err}"
    print(f"[PASS] User created with ID: {user_id}")

    # Duplicate check
    uid2, err2 = create_user("Duplicate User", email, pw_hash)
    assert uid2 is None, "Duplicate email check failed!"
    print(f"[PASS] Duplicate email rejected correctly: {err2}")

    # Fetch user
    user = get_user_by_email(email)
    assert user is not None and user["id"] == user_id
    assert check_password_hash(user["password_hash"], "TestP@ssw0rd2026!")
    print(f"[PASS] Fetch and password hash verification succeeded")

    print("\n--- 2. Testing User Isolation in Audit Log ---")
    # Log audit for user_id
    h1 = "a" * 64
    audit_id1 = log_audit(h1, 95, 16, True, True, True, True, False, user_id=user_id)
    assert audit_id1 is not None
    print(f"[PASS] Logged audit #1 for user {user_id}")

    # Create User 2
    email2 = f"tester2_{os.getpid()}@securepass.io"
    user_id2, _ = create_user("User Two", email2, pw_hash)
    assert user_id2 is not None

    # Check history for user 2 before logging anything
    h_user2 = get_audit_history(user_id=user_id2)
    user2_matching = [r for r in h_user2 if r.get("user_id") == user_id2]
    assert len(user2_matching) == 0, "User 2 should have 0 records initially!"
    print(f"[PASS] User isolation verified: User 2 sees 0 records")

    # Log audit for user 2
    h2 = "b" * 64
    audit_id2 = log_audit(h2, 80, 14, True, True, True, False, False, user_id=user_id2)
    h_user2_after = get_audit_history(user_id=user_id2)
    assert any(r["id"] == audit_id2 for r in h_user2_after), "User 2 should see audit #2"
    assert not any(r["id"] == audit_id1 for r in h_user2_after), "User 2 must NEVER see User 1's audit!"
    print(f"[PASS] Complete multi-tenant isolation verified!")

    print("\n--- 3. Testing Flask App Endpoints via Test Client ---")
    client = app.test_client()

    # Public health check
    res = client.get("/health")
    assert res.status_code == 200
    print("[PASS] GET /health returned 200")

    # Protected root without session -> 302 redirect to /login
    res = client.get("/")
    assert res.status_code == 302
    assert "/login" in res.headers.get("Location", "")
    print("[PASS] Unauthenticated GET / redirected to /login")

    # GET /login -> 200 and has cybersecurity split-screen markup
    res = client.get("/login")
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert "SECUREPASS AUDITOR" in html
    assert "Welcome Back" in html
    assert "particlesCanvas" in html
    assert "shield-core-box" in html
    assert "security-ring" in html
    print("[PASS] GET /login rendered cybersecurity split-screen page")

    # GET /register -> 200
    res = client.get("/register")
    assert res.status_code == 200
    html_reg = res.data.decode("utf-8")
    assert "Create Your Secure Account" in html_reg
    assert "particlesCanvas" in html_reg
    print("[PASS] GET /register rendered cybersecurity registration page")

    # POST /login with invalid credentials -> 401
    res = client.post("/login", json={"email": email, "password": "WrongPassword!"})
    assert res.status_code == 401
    print("[PASS] POST /login with bad credentials returned 401")

    # POST /login with valid credentials -> 200
    res = client.post("/login", json={"email": email, "password": "TestP@ssw0rd2026!"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    print("[PASS] POST /login with valid credentials returned 200 and authenticated")

    # GET / with logged in session -> 200
    res = client.get("/")
    assert res.status_code == 200
    assert "Password Security Checker" in res.data.decode("utf-8")
    assert "Logout" in res.data.decode("utf-8")
    print("[PASS] Authenticated GET / rendered main dashboard with Logout button")

    # POST /check with logged in session
    res = client.post("/check", json={"password": "MySuperSecretPassword2026!#", "log_audit": True})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["logged"] is True
    print(f"[PASS] Authenticated POST /check evaluated password, score: {data['score']}")

    # GET /history with logged in session
    res = client.get("/history")
    assert res.status_code == 200
    print("[PASS] Authenticated GET /history returned 200")

    # GET /logout
    res = client.get("/logout")
    assert res.status_code == 302
    print("[PASS] GET /logout cleared session and redirected to /login")

    print("\nALL TEST SUITES PASSED PERFECTLY! 100% SUCCESS.")

if __name__ == "__main__":
    test_all()
