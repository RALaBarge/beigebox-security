"""FastAPI application for BeigeBox Security microservice."""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from beigebox_security.config import get_config
from beigebox_security.routers import (
    poisoning_router,
    parameter_validator_router,
    anomaly_detector_router,
    memory_validator_router,
    health_router,
)


def create_app() -> FastAPI:
    """Create and configure FastAPI application."""
    config = get_config()

    app = FastAPI(
        title="BeigeBox Security",
        description="Comprehensive security orchestration for LLM/RAG stacks",
        version="0.1.0",
        docs_url="/docs",
        openapi_url="/openapi.json",
    )

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Routers
    app.include_router(health_router.router, prefix="", tags=["health"])
    app.include_router(
        poisoning_router.router,
        prefix="/v1/security/poisoning",
        tags=["RAG Poisoning Detection"],
    )
    app.include_router(
        parameter_validator_router.router,
        prefix="/v1/security/parameters",
        tags=["MCP Parameter Validation"],
    )
    app.include_router(
        anomaly_detector_router.router,
        prefix="/v1/security/anomaly",
        tags=["API Anomaly Detection"],
    )
    app.include_router(
        memory_validator_router.router,
        prefix="/v1/security/memory",
        tags=["Memory Integrity Validation"],
    )

    return app


# Application instance for uvicorn
app = create_app()
