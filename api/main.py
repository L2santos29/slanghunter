"""
SlangHunter REST API
FastAPI wrapper around the SlangHunter core engine.
Run with: uvicorn api.main:app --reload
"""

from collections import deque
import logging
import math
import os
import secrets
import threading
import time
from typing import Annotated, Any

try:
    from fastapi import FastAPI, Header, HTTPException, Request, status
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse, Response
except ImportError as exc:
    raise ImportError(
        "Install slanghunter[api] for REST API support"
    ) from exc

try:
    from api.models import AnalyzeRequest, AnalyzeResponse, CategoryInfo
except ImportError as exc:
    raise ImportError(
        "Install slanghunter[api] for REST API support"
    ) from exc

from src import SlangHunter, __version__

LOGGER = logging.getLogger(__name__)
RELOAD_KEY_ENV_VAR = "SLANGHUNTER_RELOAD_KEY"
CORS_ORIGINS_ENV_VAR = "SLANGHUNTER_CORS_ORIGINS"
RATE_LIMIT_WINDOW_ENV_VAR = "SLANGHUNTER_RATE_LIMIT_WINDOW_SECONDS"
RATE_LIMIT_MAX_REQUESTS_ENV_VAR = "SLANGHUNTER_RATE_LIMIT_MAX_REQUESTS"
TRUST_PROXY_HEADERS_ENV_VAR = "SLANGHUNTER_TRUST_PROXY_HEADERS"
RELOAD_API_KEY = os.getenv(RELOAD_KEY_ENV_VAR) or None


def _parse_positive_int_env(name: str, default: int) -> int:
    """Harden env parsing so invalid values cannot disable safeguards."""
    raw_value = os.getenv(name)
    if raw_value is None:
        return default

    try:
        parsed_value = int(raw_value)
    except ValueError:
        LOGGER.warning(
            "%s=%r is invalid; defaulting to %s",
            name,
            raw_value,
            default,
        )
        return default

    if parsed_value < 1:
        LOGGER.warning(
            "%s=%r is below the minimum of 1; defaulting to %s",
            name,
            raw_value,
            default,
        )
        return default

    return parsed_value


def _parse_bool_env(name: str, default: bool = False) -> bool:
    """Parse opt-in booleans without letting malformed values weaken defaults."""
    raw_value = os.getenv(name)
    if raw_value is None:
        return default

    normalized_value = raw_value.strip().lower()
    if normalized_value in {"1", "true", "yes", "on"}:
        return True
    if normalized_value in {"0", "false", "no", "off"}:
        return False

    LOGGER.warning(
        "%s=%r is invalid; defaulting to %s",
        name,
        raw_value,
        default,
    )
    return default


def _parse_cors_origins() -> list[str]:
    """Parse explicit CORS origins while keeping same-origin as the default."""
    raw_origins = os.getenv(CORS_ORIGINS_ENV_VAR, "")
    return [origin.strip() for origin in raw_origins.split(",") if origin.strip()]


CORS_ALLOWED_ORIGINS = _parse_cors_origins()
TRUST_PROXY_HEADERS = _parse_bool_env(TRUST_PROXY_HEADERS_ENV_VAR, default=False)
RATE_LIMIT_WINDOW_SECONDS = _parse_positive_int_env(
    RATE_LIMIT_WINDOW_ENV_VAR,
    60,
)
RATE_LIMIT_MAX_REQUESTS = _parse_positive_int_env(
    RATE_LIMIT_MAX_REQUESTS_ENV_VAR,
    60,
)
RATE_LIMIT_LOCK = threading.Lock()
RATE_LIMIT_BUCKETS: dict[str, deque[float]] = {}

# Module-level singleton keeps the server and tests on the same knowledge-base
# initialization path, including JSON loading and fallback behavior.
hunter = SlangHunter.from_data_dir()

app = FastAPI(
    title="SlangHunter API",
    description=(
        "FastAPI wrapper around the SlangHunter rule engine with JSON-backed "
        "knowledge-base reload support."
    ),
    version=__version__,
)

if CORS_ALLOWED_ORIGINS:
    # Keep browser access opt-in so deployments must explicitly declare which
    # frontends may call the API cross-origin.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ALLOWED_ORIGINS,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "X-Reload-Key"],
        expose_headers=[
            "Retry-After",
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "X-RateLimit-Window",
        ],
    )


@app.on_event("startup")
async def log_startup() -> None:
    """Log startup metadata for operational visibility."""
    LOGGER.info(
        "SlangHunter API started with %s loaded categories",
        len(hunter.get_categories()),
    )
    LOGGER.info(
        "Rate limiting enabled: %s requests per %s seconds",
        RATE_LIMIT_MAX_REQUESTS,
        RATE_LIMIT_WINDOW_SECONDS,
    )
    LOGGER.info("Trust proxy headers: %s", TRUST_PROXY_HEADERS)
    if RELOAD_API_KEY is None:
        LOGGER.warning(
            "WARNING: /reload endpoint is unauthenticated. "
            "Set SLANGHUNTER_RELOAD_KEY env var in production."
        )
    if CORS_ALLOWED_ORIGINS:
        LOGGER.info(
            "CORS enabled for %s explicit origin(s)",
            len(CORS_ALLOWED_ORIGINS),
        )
    else:
        LOGGER.info(
            "CORS middleware disabled; same-origin policy remains in effect"
        )


def _require_reload_key(x_reload_key: str | None) -> None:
    """Protect the admin reload endpoint when a production key is configured."""
    if RELOAD_API_KEY is None:
        return

    # Use constant-time comparison so the header check does not leak partial
    # key information through timing side channels.
    if x_reload_key is None or not secrets.compare_digest(
        x_reload_key,
        RELOAD_API_KEY,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing reload key",
        )


def _client_identifier(request: Request) -> str:
    """Prefer proxy-forwarded client IPs so throttling works behind ingress."""
    forwarded_for = request.headers.get("x-forwarded-for")
    if TRUST_PROXY_HEADERS and forwarded_for:
        return forwarded_for.split(",", 1)[0].strip() or "unknown"
    if request.client is not None and request.client.host:
        return request.client.host
    return "unknown"


def _consume_rate_limit(request: Request) -> tuple[bool, int, int] | None:
    """Apply a lightweight in-process throttle to blunt scraping and DoS bursts."""
    if request.url.path == "/health" or request.method == "OPTIONS":
        return None

    now = time.monotonic()
    client_key = _client_identifier(request)
    oldest_allowed = now - RATE_LIMIT_WINDOW_SECONDS

    with RATE_LIMIT_LOCK:
        bucket = RATE_LIMIT_BUCKETS.setdefault(client_key, deque())
        while bucket and bucket[0] <= oldest_allowed:
            bucket.popleft()

        if len(bucket) >= RATE_LIMIT_MAX_REQUESTS:
            retry_after = max(
                1,
                math.ceil(bucket[0] + RATE_LIMIT_WINDOW_SECONDS - now),
            )
            return False, 0, retry_after

        bucket.append(now)
        remaining = max(RATE_LIMIT_MAX_REQUESTS - len(bucket), 0)
        return True, remaining, 0


@app.middleware("http")
async def apply_rate_limit(request: Request, call_next: Any) -> Response:
    """Reject burst traffic before it reaches the CPU-heavy analysis pipeline."""
    request_started_at = time.perf_counter()
    client_key = _client_identifier(request)
    rate_limit_result = _consume_rate_limit(request)
    if rate_limit_result is None:
        try:
            response = await call_next(request)
        except Exception:
            LOGGER.exception(
                "Unhandled request failure method=%s path=%s client=%s",
                request.method,
                request.url.path,
                client_key,
            )
            raise
        LOGGER.info(
            "Request method=%s path=%s status=%s client=%s duration_ms=%s",
            request.method,
            request.url.path,
            response.status_code,
            client_key,
            int((time.perf_counter() - request_started_at) * 1000),
        )
        return response

    is_allowed, remaining, retry_after = rate_limit_result
    common_headers = {
        "X-RateLimit-Limit": str(RATE_LIMIT_MAX_REQUESTS),
        "X-RateLimit-Window": str(RATE_LIMIT_WINDOW_SECONDS),
    }
    if not is_allowed:
        LOGGER.warning(
            "Rate limit exceeded method=%s path=%s client=%s retry_after=%s",
            request.method,
            request.url.path,
            client_key,
            retry_after,
        )
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={
                "detail": "Rate limit exceeded. Slow down and retry later.",
            },
            headers=common_headers | {
                "Retry-After": str(retry_after),
                "X-RateLimit-Remaining": "0",
            },
        )

    try:
        response = await call_next(request)
    except Exception:
        LOGGER.exception(
            "Unhandled request failure method=%s path=%s client=%s",
            request.method,
            request.url.path,
            client_key,
        )
        raise
    response.headers.update(
        common_headers | {"X-RateLimit-Remaining": str(remaining)}
    )
    LOGGER.info(
        "Request method=%s path=%s status=%s client=%s duration_ms=%s",
        request.method,
        request.url.path,
        response.status_code,
        client_key,
        int((time.perf_counter() - request_started_at) * 1000),
    )
    return response


@app.get("/health")
def health() -> dict[str, str]:
    """Expose a minimal health-check contract for deployments."""
    return {"status": "ok", "version": __version__}


@app.get("/categories")
def list_categories() -> dict[str, list[str]]:
    """Return the currently loaded knowledge-base categories."""
    return {"categories": hunter.get_categories()}


@app.get("/categories/{category_name}", response_model=CategoryInfo)
def get_category(category_name: str) -> CategoryInfo:
    """Return metadata for a single category or raise HTTP 404."""
    category_info = hunter.get_category_info(category_name)
    if category_info is None:
        raise HTTPException(
            status_code=404,
            detail=f"Category '{category_name}' not found",
        )
    return CategoryInfo.model_validate(category_info)


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze_listing(request: AnalyzeRequest) -> AnalyzeResponse:
    """Analyze listing text and return the normalized risk verdict."""
    try:
        verdict = hunter.analyze(request.text, request.price)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    level = hunter.classify_risk(verdict["risk_score"])
    return AnalyzeResponse(
        risk_score=verdict["risk_score"],
        risk_level=level.label,
        risk_emoji=level.emoji,
        risk_action=level.action,
        flags=verdict["flags"],
        matched_categories=verdict["matched_categories"],
        reasoning=verdict["reasoning"],
    )


@app.post("/reload")
def reload_knowledge_base(
    x_reload_key: Annotated[str | None, Header(alias="X-Reload-Key")] = None,
) -> dict[str, Any]:
    """Hot-reload JSON rule files into the module-level engine instance."""
    _require_reload_key(x_reload_key)
    hunter.reload_from_data_dir()
    return {
        "status": "reloaded",
        "categories": hunter.get_categories(),
    }
