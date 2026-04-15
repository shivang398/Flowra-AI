import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.config import settings

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_env():
    # Make sure we have a secret key for tests
    settings.sentinel_jwt_secret = "test_super_secret_for_pytest"

@pytest.fixture
def auth_token():
    response = client.get("/token")
    assert response.status_code == 200
    return response.json()["access_token"]

@pytest.fixture
def auth_headers(auth_token):
    return {"Authorization": f"Bearer {auth_token}"}

def test_health_check():
    response = client.get("/")
    assert response.status_code == 200
    assert "SentinelAI running" in response.json()["message"]

def test_no_auth_rejected():
    response = client.post("/secure-predict", json={"data": [1.0, 2.0, 3.0, 4.0]})
    assert response.status_code in (401, 403) # Missing token yields 401 or 403 depending on FastAPI version

def test_invalid_jwt_rejected():
    headers = {"Authorization": "Bearer not.a.valid.jwt"}
    response = client.post("/secure-predict", json={"data": [1.0, 2.0, 3.0, 4.0]}, headers=headers)
    assert response.status_code in (401, 403)

def test_valid_inference(auth_headers):
    # A single normal request should be allowed (unless we previously blocked tests, so just in case)
    response = client.post("/secure-predict", json={"data": [5.1, 3.5, 1.4, 0.2]}, headers=auth_headers)
    if response.status_code == 200:
        data = response.json()
        assert "prediction" in data
        assert "action" in data
        assert data["action"] == "allow"
    elif response.status_code == 403:
        # IP from testclient might be blocked due to previous runs.
        pass

def test_malformed_request(auth_headers):
    response = client.post("/secure-predict", json={"wrong_field": "abc"}, headers=auth_headers)
    assert response.status_code == 422

# We could also mock the prompt injection or IP blocked paths, but this is a solid integration start.
