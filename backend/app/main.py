from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
import json

from fastapi.responses import JSONResponse, Response

from .i18n_ar import translate_obj

from .config import settings
from .routers import analyze, auth, calls, dashboard, mobile, emails, endpoints, incidents, response, system
from .seed import seed

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logging.getLogger("RapidOCR").setLevel(logging.WARNING)

@asynccontextmanager
async def lifespan(_app: FastAPI):
    seed()
    yield


app = FastAPI(title="WOLVE AI", version="0.1.0", lifespan=lifespan,
              description="AI-powered scam, phishing and threat analysis platform (hackathon MVP)")
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=False,
                   allow_methods=["*"], allow_headers=["*"])


@app.middleware("http")
async def arabic_responses(request: Request, call_next):
    """Translate display text in JSON responses when the client asks for Arabic (X-WOLVE-Lang: ar)."""
    response = await call_next(request)
    if request.headers.get("x-wolve-lang") != "ar" or "application/json" not in response.headers.get("content-type", ""):
        return response
    body = b"".join([chunk async for chunk in response.body_iterator])
    try:
        data = translate_obj(json.loads(body))
    except Exception:
        return Response(content=body, status_code=response.status_code, headers=dict(response.headers), media_type=response.media_type)
    headers = {k: v for k, v in response.headers.items() if k.lower() not in ("content-length", "content-type")}
    return JSONResponse(data, status_code=response.status_code, headers=headers)


@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError):
    msgs = []
    for e in exc.errors():
        loc = ".".join(str(x) for x in e.get("loc", []) if x != "body")
        msgs.append(f"{loc}: {e.get('msg')}" if loc else e.get("msg"))
    return JSONResponse(status_code=422, content={"detail": "; ".join(msgs)})


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    logging.getLogger("wolve").exception("Unhandled error on %s", request.url.path)
    return JSONResponse(status_code=500, content={"detail": f"Internal error: {exc.__class__.__name__}. See server log."})


for r in (auth.router, system.router, system.public_router, calls.router, mobile.router, dashboard.router, analyze.router, emails.router, endpoints.router, endpoints.agent_router, incidents.router, response.router):
    app.include_router(r)
