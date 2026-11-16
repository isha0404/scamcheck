"""FastAPI web service.

    uvicorn scamcheck.api:app --reload

POST /api/check   {"message": "..."}  ->  verdict, reasons, highlights
GET  /api/health                       ->  model status and test metrics
GET  /                                 ->  the React web app (if built)

Privacy: messages are analysed in memory and never stored or logged.
"""
from __future__ import annotations

import os
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import __version__
from .checker import MAX_LENGTH, check
from .model import DEFAULT_MODEL_PATH, ScamModel

FRONTEND_DIST = Path(os.environ.get("SCAMCHECK_FRONTEND",
                                    Path(__file__).resolve().parents[2] / "frontend" / "dist"))
RATE_LIMIT = int(os.environ.get("SCAMCHECK_RATE_LIMIT", "30"))        # requests per minute per IP


class CheckRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=MAX_LENGTH,
                         examples=["Royal Mail: pay a £1.45 redelivery fee at royalmail-redelivery-uk.com"])


class RateLimiter:
    """Small in-memory sliding-window limiter, so one client can't hammer the API.
    (For several servers you'd use Redis or the reverse proxy instead.)"""

    def __init__(self, per_minute: int):
        self.per_minute = per_minute
        self.hits: dict[str, deque] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        q = self.hits[key]
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= self.per_minute:
            return False
        q.append(now)
        return True


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.model = ScamModel.load(Path(os.environ.get("SCAMCHECK_MODEL", DEFAULT_MODEL_PATH)))
    app.state.limiter = RateLimiter(RATE_LIMIT)
    yield


app = FastAPI(title="ScamCheck", version=__version__, lifespan=lifespan,
              description="Check whether a text message is likely to be a scam, and see why.")

# Only needed when the React dev server (port 5173) talks to the API (port 8000).
app.add_middleware(CORSMiddleware, allow_origins=os.environ.get(
    "SCAMCHECK_CORS_ORIGINS", "http://localhost:5173").split(","), allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"])


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "frame-ancestors 'none'")
    response.headers["Cache-Control"] = "no-store" if request.url.path.startswith("/api") else \
        response.headers.get("Cache-Control", "no-cache")
    return response


@app.post("/api/check")
def api_check(body: CheckRequest, request: Request):
    client = request.client.host if request.client else "unknown"
    if not request.app.state.limiter.allow(client):
        return JSONResponse({"detail": "Too many checks. Please wait a minute and try again."}, status_code=429)
    try:
        result = check(body.message, request.app.state.model)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return result.to_dict()


@app.get("/api/health")
def health(request: Request):
    meta = request.app.state.model.metadata
    return {"status": "ok", "version": __version__, "model_trained_at": meta.get("trained_at"),
            "metrics": meta.get("metrics", {}).get("model_plus_rules")}


if FRONTEND_DIST.is_dir():
    app.mount("/", StaticFiles(directory=FRONTEND_DIST, html=True), name="frontend")
else:
    @app.get("/")
    def no_frontend():
        return {"message": "ScamCheck API is running. Build the web app (cd frontend && npm run build) "
                           "or see the API docs at /docs."}
