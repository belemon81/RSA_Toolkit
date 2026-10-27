"""
FastAPI application for Vulnerable RSA Server.

This module provides REST API endpoints for interacting with attack scenarios.
"""

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Dict, List, Optional
import uvicorn

from rsa_toolkit.server.scenario_manager import ScenarioManager, ScenarioType


app = FastAPI(
    title="RSA Attack Toolkit - Vulnerable Server",
    description="Server with intentionally weak RSA configurations for security testing",
    version="1.0.0"
)

scenario_manager = ScenarioManager()


class ScenarioCreateRequest(BaseModel):
    """Request model for creating a scenario."""
    scenario_type: str
    seed: Optional[int] = None


class ScenarioResponse(BaseModel):
    """Response model for scenario information."""
    scenario_id: str
    scenario_type: str
    description: str
    users: List[str]


class PublicKeyResponse(BaseModel):
    """Response model for public key."""
    n: int
    e: int


class CiphertextResponse(BaseModel):
    """Response model for ciphertext."""
    ciphertext: int


class VerificationRequest(BaseModel):
    """Request model for verification."""
    user_id: str
    proposed_value: int


class VerificationResponse(BaseModel):
    """Response model for verification."""
    is_correct: bool


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "RSA Attack Toolkit - Vulnerable Server",
        "version": "1.0.0",
        "endpoints": {
            "scenarios": "/scenarios",
            "create": "/scenarios/create",
            "public_key": "/scenarios/{scenario_id}/users/{user_id}/public_key",
            "ciphertext": "/scenarios/{scenario_id}/users/{user_id}/ciphertext",
            "verify_d": "/scenarios/{scenario_id}/users/{user_id}/verify_d",
            "verify_message": "/scenarios/{scenario_id}/users/{user_id}/verify_message"
        }
    }


@app.get("/scenarios")
async def list_scenarios():
    """
    List all available scenarios.

    Returns:
        List of scenario IDs
    """
    scenarios = scenario_manager.list_scenarios()
    return {"scenarios": scenarios}


@app.post("/scenarios/create")
async def create_scenario(request: ScenarioCreateRequest):
    """
    Create a new attack scenario.

    Args:
        request: ScenarioCreateRequest with scenario type and optional seed

    Returns:
        Scenario information
    """
    try:
        scenario_type = ScenarioType(request.scenario_type)
    except ValueError:
        available = [st.value for st in ScenarioType]
        raise HTTPException(
            status_code=400,
            detail=f"Invalid scenario type. Available: {available}"
        )

    scenario = scenario_manager.create_scenario(scenario_type, request.seed)

    return ScenarioResponse(
        scenario_id=scenario.scenario_id,
        scenario_type=scenario.scenario_type.value,
        description=scenario.description,
        users=list(scenario.keys.keys())
    )


@app.get("/scenarios/{scenario_id}")
async def get_scenario(scenario_id: str):
    """
    Get scenario information.

    Args:
        scenario_id: Scenario identifier

    Returns:
        Scenario details
    """
    scenario = scenario_manager.get_scenario(scenario_id)
    if scenario is None:
        raise HTTPException(status_code=404, detail="Scenario not found")

    return ScenarioResponse(
        scenario_id=scenario.scenario_id,
        scenario_type=scenario.scenario_type.value,
        description=scenario.description,
        users=list(scenario.keys.keys())
    )


@app.get("/scenarios/{scenario_id}/users/{user_id}/public_key")
async def get_public_key(scenario_id: str, user_id: str):
    """
    Get public key for a user in a scenario.

    Args:
        scenario_id: Scenario identifier
        user_id: User identifier

    Returns:
        Public key (n, e)
    """
    scenario = scenario_manager.get_scenario(scenario_id)
    if scenario is None:
        raise HTTPException(status_code=404, detail="Scenario not found")

    key = scenario.keys.get(user_id)
    if key is None:
        raise HTTPException(status_code=404, detail="User not found")

    return PublicKeyResponse(n=key.n, e=key.e)


@app.get("/scenarios/{scenario_id}/users/{user_id}/ciphertext")
async def get_ciphertext(scenario_id: str, user_id: str):
    """
    Get ciphertext for a user in a scenario.

    Args:
        scenario_id: Scenario identifier
        user_id: User identifier

    Returns:
        Ciphertext
    """
    scenario = scenario_manager.get_scenario(scenario_id)
    if scenario is None:
        raise HTTPException(status_code=404, detail="Scenario not found")

    ciphertext = scenario.ciphertexts.get(user_id)
    if ciphertext is None:
        raise HTTPException(status_code=404, detail="User not found")

    return CiphertextResponse(ciphertext=ciphertext)


@app.get("/scenarios/{scenario_id}/users")
async def list_users(scenario_id: str):
    """
    List all users in a scenario.

    Args:
        scenario_id: Scenario identifier

    Returns:
        List of user IDs
    """
    scenario = scenario_manager.get_scenario(scenario_id)
    if scenario is None:
        raise HTTPException(status_code=404, detail="Scenario not found")

    return {"users": list(scenario.keys.keys())}


@app.post("/scenarios/{scenario_id}/users/{user_id}/verify_d")
async def verify_private_key(scenario_id: str, user_id: str, request: VerificationRequest):
    """
    Verify if a proposed private key is correct.

    Args:
        scenario_id: Scenario identifier
        user_id: User identifier
        request: VerificationRequest with proposed d

    Returns:
        Verification result
    """
    scenario = scenario_manager.get_scenario(scenario_id)
    if scenario is None:
        raise HTTPException(status_code=404, detail="Scenario not found")

    is_correct = scenario_manager.verify_private_key(
        scenario_id,
        user_id,
        request.proposed_value
    )

    return VerificationResponse(is_correct=is_correct)


@app.post("/scenarios/{scenario_id}/users/{user_id}/verify_message")
async def verify_message(scenario_id: str, user_id: str, request: VerificationRequest):
    """
    Verify if a proposed message is correct.

    Args:
        scenario_id: Scenario identifier
        user_id: User identifier
        request: VerificationRequest with proposed message

    Returns:
        Verification result
    """
    scenario = scenario_manager.get_scenario(scenario_id)
    if scenario is None:
        raise HTTPException(status_code=404, detail="Scenario not found")

    is_correct = scenario_manager.verify_message(
        scenario_id,
        user_id,
        request.proposed_value
    )

    return VerificationResponse(is_correct=is_correct)


def run_server(host: str = "127.0.0.1", port: int = 8000):
    """
    Run the FastAPI server.

    Args:
        host: Host to bind to
        port: Port to bind to
    """
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    run_server()
