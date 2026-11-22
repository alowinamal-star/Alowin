"""Adaptive Testing Laboratory endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status

from .. import auth, db, service, testing
from ..models import TestingRunRequest

router = APIRouter(prefix="/api/testing", tags=["testing"])


@router.post("/run", status_code=status.HTTP_201_CREATED)
def run_evaluation(payload: TestingRunRequest, user: dict = Depends(auth.require("testing"))) -> dict:
    """Run the detector over the held-out dataset splits and report metrics.

    This measures the *current* shipped model and rules. It is evaluation, not
    online learning: no weights are updated by this endpoint.
    """
    result = testing.run_evaluation(subsets=payload.subsets, mutate=payload.mutate, compare_baseline=payload.compare_baseline, user=user)
    db.audit(
        user,
        "testing.run",
        f"Evaluation run over {', '.join(payload.subsets)}",
        {"run_id": result.get("run_id"), "recall": result.get("overall", {}).get("recall")},
    )
    return result


@router.get("/runs")
def list_runs(limit: int = Query(20, ge=1, le=100), user: dict = Depends(auth.require("read"))) -> dict:
    return {"runs": service.list_testing_runs(limit=limit)}


@router.get("/runs/{run_id}")
def get_run(run_id: str, user: dict = Depends(auth.require("read"))) -> dict:
    run = service.get_testing_run(run_id)
    if not run:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Evaluation run not found.")
    return run


@router.get("/dataset")
def dataset_summary(user: dict = Depends(auth.require("read"))) -> dict:
    """Describe the bundled dataset splits without exposing the raw payloads."""
    return testing.dataset_summary()
