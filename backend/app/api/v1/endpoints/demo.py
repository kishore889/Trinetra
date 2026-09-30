"""
TRINETRA — Phase 16: Controlled Attack / Defense Demo Center Endpoints

API routes:
  GET  /api/v1/demo/scenarios              -> List all 10 scenario definitions
  GET  /api/v1/demo/scenarios/{scenario_id} -> Scenario details & raw email preview
  POST /api/v1/demo/run/{scenario_id}       -> Execute genuine 10-stage detection pipeline
  POST /api/v1/demo/run-custom             -> Run custom raw MIME through the same pipeline
"""

from __future__ import annotations

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.services.demo_pipeline_service import (
    SCENARIOS,
    SCENARIO_MAP,
    DemoScenarioDefinition,
    DemoExecutionResult,
    execute_demo_pipeline,
)

router = APIRouter()


class CustomRunRequest(BaseModel):
    raw_mime: str
    scenario_name: Optional[str] = "Custom Injected Email"


@router.get("/scenarios", response_model=List[DemoScenarioDefinition])
def list_demo_scenarios():
    """Returns all 10 controlled attack / defense demonstration scenarios."""
    return SCENARIOS


@router.get("/scenarios/{scenario_id}", response_model=DemoScenarioDefinition)
def get_demo_scenario(scenario_id: str):
    """Retrieves full specification for a single demonstration scenario."""
    scenario = SCENARIO_MAP.get(scenario_id)
    if not scenario:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scenario '{scenario_id}' not found. Available: scen-1 to scen-10",
        )
    return scenario


@router.post("/run/{scenario_id}", response_model=DemoExecutionResult)
async def run_scenario(
    scenario_id: str,
    db: Session = Depends(get_db),
):
    """
    Executes the genuine 10-stage detection pipeline for the selected scenario.
    NO hardcoded scores or decisions: calculates scores live via all intelligence engines.
    """
    scenario = SCENARIO_MAP.get(scenario_id)
    if not scenario:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scenario '{scenario_id}' not found. Available: scen-1 to scen-10",
        )

    try:
        result = await execute_demo_pipeline(scenario_id=scenario_id, db=db)
        return result
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Pipeline execution error: {str(exc)}",
        )


@router.post("/run-custom", response_model=DemoExecutionResult)
async def run_custom_email(
    request: CustomRunRequest,
    db: Session = Depends(get_db),
):
    """
    Executes the genuine 10-stage detection pipeline on arbitrary synthetic RFC 822 MIME bytes.
    """
    if not request.raw_mime or len(request.raw_mime.strip()) < 10:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="raw_mime string must contain valid RFC 822 email content.",
        )

    try:
        result = await execute_demo_pipeline(
            scenario_id="custom",
            db=db,
            custom_mime=request.raw_mime,
        )
        return result
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Custom pipeline execution error: {str(exc)}",
        )
