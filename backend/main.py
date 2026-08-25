import os
import sys
from contextlib import asynccontextmanager

# project root (one level up) holds security_gateway/, security_db.py,
# skills/, policies/ used by the routers and the gateway itself.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import auth
from common import security_db
from common.config import get_settings
from common.logging_config import get_logger, setup_logging
from common.observability import setup_tracing
from routers import (admin_router, agent_router, auth_router, conversations_router, query_router, security_router,
                      upload_router)
from security_gateway import agent_registry

setup_logging()
setup_tracing()
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    logger.info("Starting Cyber Defense Assistant API (llm_provider=%s, model=%s)",
                settings.llm_provider, settings.active_model())
    auth.init_users()
    security_db.init_db()
    agent_registry.seed_default_agents()

    # gateway.analyze()'s `model` param is left unset by every router now -
    # security_gateway/llm_discussion.py resolves the active provider/model
    # itself, per call, via security_gateway/runtime_config.py, so an admin
    # switching providers at runtime (POST /api/security/llm-config) takes
    # effect on the very next request, not just after a restart. Pinning a
    # startup-time model here would silently defeat that switch.
    app.state.log = logger.info
    try:
        yield
    finally:
        logger.info("Shutting down Cyber Defense Assistant API")


app = FastAPI(title="Cyber Defense Assistant API - AI Security Gateway", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().cors_origins_list(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router.router)
app.include_router(conversations_router.router)
app.include_router(query_router.router)
app.include_router(upload_router.router)
app.include_router(admin_router.router)
app.include_router(security_router.router)
app.include_router(agent_router.router)


@app.get("/api/health")
def health():
    return {"status": "ok"}
