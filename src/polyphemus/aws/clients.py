"""AWS client factory — the mock/real seam.

Pipeline modules obtain every AWS-facing dependency here. In ``mock`` mode the
factories return the in-memory fakes (fully offline). In ``aws`` mode they build
real boto3 clients / an OpenSearch wrapper.

**boto3 is imported lazily inside the ``aws`` branches only.** In mock mode it is
never imported, so the offline demo and tests never touch AWS — and no AWS call
is reachable in mock mode.

The mock instances are process-singletons so the same seeded vector store is
shared across the pipeline within a run.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from polyphemus.aws.mock_bedrock import MockBedrock
from polyphemus.aws.mock_s3 import MockS3
from polyphemus.aws.mock_vector_store import MockVectorStore
from polyphemus.config import Settings, get_settings


@lru_cache(maxsize=1)
def _mock_s3_singleton() -> MockS3:
    return MockS3()


@lru_cache(maxsize=1)
def _mock_vector_singleton() -> MockVectorStore:
    return MockVectorStore()


@lru_cache(maxsize=1)
def _mock_bedrock_singleton() -> MockBedrock:
    return MockBedrock(embed_dim=get_settings().embed_dim)


def get_s3(settings: Settings | None = None) -> Any:
    """Return an S3 client (mock in-memory, or real boto3 in aws mode)."""
    settings = settings or get_settings()
    if settings.is_mock:
        return _mock_s3_singleton()
    import boto3  # lazy import: only in aws mode

    return boto3.client("s3", region_name=settings.region)


def get_bedrock(settings: Settings | None = None) -> Any:
    """Return a Bedrock client.

    Mock mode returns :class:`MockBedrock`. AWS mode returns a thin wrapper over
    ``bedrock-runtime`` exposing the same ``embed`` / ``invoke`` interface the
    pipeline expects, so callers are agnostic to the backend.
    """
    settings = settings or get_settings()
    if settings.is_mock:
        return _mock_bedrock_singleton()
    return _RealBedrock(settings)


def get_vector_store(settings: Settings | None = None) -> Any:
    """Return the vector store (mock in-memory, or an OpenSearch wrapper)."""
    settings = settings or get_settings()
    if settings.is_mock:
        return _mock_vector_singleton()
    return _RealOpenSearchStore(settings)


def reset_mock_clients() -> None:
    """Clear cached mock singletons (used between test scenarios)."""
    _mock_s3_singleton.cache_clear()
    _mock_vector_singleton.cache_clear()
    _mock_bedrock_singleton.cache_clear()


# ---------------------------------------------------------------------------
# Real-mode wrappers. These are intentionally thin and are NEVER imported or
# executed in mock mode. They document the shape of a real integration.
# ---------------------------------------------------------------------------
class _RealBedrock:
    """Wrapper over Amazon Bedrock Runtime (reference; requires AWS creds)."""

    def __init__(self, settings: Settings) -> None:
        import boto3  # lazy import

        self._settings = settings
        self._client = boto3.client("bedrock-runtime", region_name=settings.region)

    def embed(self, text: str) -> list[float]:
        import json

        resp = self._client.invoke_model(
            modelId=self._settings.bedrock_embed_model_id,
            body=json.dumps({"inputText": text}),
        )
        payload = json.loads(resp["body"].read())
        return payload["embedding"]

    def invoke(self, system: str, messages: list[dict[str, str]]) -> tuple[str, int, int]:
        import json

        body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": self._settings.max_output_tokens,
            "system": system,
            "messages": [{"role": m["role"], "content": m["content"]} for m in messages],
        }
        resp = self._client.invoke_model(
            modelId=self._settings.bedrock_text_model_id,
            body=json.dumps(body),
        )
        payload = json.loads(resp["body"].read())
        text = payload["content"][0]["text"]
        # Bedrock returns exact token usage in the response metadata.
        usage = payload.get("usage", {})
        input_tokens = int(usage.get("input_tokens", 0))
        output_tokens = int(usage.get("output_tokens", 0))
        return text, input_tokens, output_tokens


class _RealOpenSearchStore:
    """Wrapper over Amazon OpenSearch Serverless vector search (reference)."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        # A real implementation would build an opensearch-py client with SigV4
        # auth here. Left unconstructed so importing this module never requires
        # the optional dependency.
        raise NotImplementedError(
            "aws-mode OpenSearch client is a reference stub; run with "
            "POLYPHEMUS_MODE=mock for the offline demo."
        )
