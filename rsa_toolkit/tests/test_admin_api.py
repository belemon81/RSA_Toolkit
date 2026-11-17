from fastapi.testclient import TestClient

from rsa_toolkit.server.app import app, scenario_manager
from rsa_toolkit.server.scenario_manager import ScenarioType


def test_admin_scenario_returns_full_parameters_to_localhost():
    scenario = scenario_manager.create_scenario(ScenarioType.SMALL_MODULUS, seed=12345)
    key = scenario.keys["user1"]

    with TestClient(app, client=("127.0.0.1", 50000)) as client:
        response = client.get(f"/admin/scenarios/{scenario.scenario_id}")

    assert response.status_code == 200
    data = response.json()
    assert data["scenario_id"] == scenario.scenario_id
    assert data["scenario_type"] == ScenarioType.SMALL_MODULUS.value
    assert data["seed"] == scenario.seed
    assert data["users"]["user1"] == {
        "n": key.n,
        "e": key.e,
        "d": key.d,
        "p": key.p,
        "q": key.q,
        "message": scenario.messages["user1"],
        "ciphertext": scenario.ciphertexts["user1"],
    }


def test_admin_scenario_rejects_non_localhost():
    with TestClient(app, client=("192.0.2.1", 50000)) as client:
        response = client.get("/admin/scenarios/nonexistent")

    assert response.status_code == 403
