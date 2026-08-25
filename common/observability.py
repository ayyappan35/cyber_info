"""Optional tracing (CLAUDE.md section 15): MLflow or LangSmith, selected
via config.py's TRACING_BACKEND env var. Neither package is a hard
dependency of this project - both integrations degrade to a logged no-op if
their package isn't installed, rather than crashing startup. "Support
MLflow and/or LangSmith through configuration" doesn't mean force-install
one; this project's own agents already work fully without either.

Never logs secrets: LangSmith's API key is only ever read into an env var
LangChain itself consumes, never printed (see logging_config.py's redaction
filter as a second layer of defense on top of that).
"""
from common.config import get_settings
from common.logging_config import get_logger

logger = get_logger(__name__)


def setup_tracing() -> None:
    settings = get_settings()
    backend = settings.tracing_backend

    if backend == "none":
        return

    if backend == "mlflow":
        try:
            import mlflow
        except ImportError:
            logger.warning("tracing_backend='mlflow' but the mlflow package isn't installed - "
                            "tracing disabled. Install it with `pip install mlflow` to enable.")
            return
        if settings.mlflow_tracking_uri:
            mlflow.set_tracking_uri(settings.mlflow_tracking_uri)
        mlflow.set_experiment(settings.mlflow_experiment_name)
        mlflow.langchain.autolog()
        logger.info("MLflow tracing enabled (experiment=%s)", settings.mlflow_experiment_name)
        return

    if backend == "langsmith":
        if not settings.langsmith_api_key:
            logger.warning("tracing_backend='langsmith' but no langsmith_api_key is set - "
                            "tracing disabled.")
            return
        import os
        # LangChain/LangGraph read these standard env vars natively - no
        # separate langsmith SDK call needed for the tracing this project
        # already does through langchain_ollama/langgraph.
        os.environ["LANGCHAIN_TRACING_V2"] = "true"
        os.environ["LANGCHAIN_API_KEY"] = settings.langsmith_api_key
        os.environ["LANGCHAIN_PROJECT"] = settings.langsmith_project
        logger.info("LangSmith tracing enabled (project=%s)", settings.langsmith_project)
