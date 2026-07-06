"""Runtime configuration for Polyphemus.

Settings load from environment variables (prefix ``POLYPHEMUS_``) and an optional
``.env`` file. The single most important setting is ``mode``: ``mock`` (default)
wires the in-memory AWS fakes so everything runs offline; ``aws`` would wire real
boto3 clients. Pipeline code reads configuration only through :func:`get_settings`.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict

Mode = Literal["mock", "aws"]
VectorBackend = Literal["opensearch", "pgvector"]


class Settings(BaseSettings):
    """Central configuration object."""

    model_config = SettingsConfigDict(
        env_prefix="POLYPHEMUS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Execution mode (the mock/real seam) ---
    mode: Mode = "mock"
    region: str = "us-east-1"

    # --- Bedrock model ids ---
    bedrock_text_model_id: str = "anthropic.claude-3-5-sonnet-20240620-v1:0"
    bedrock_embed_model_id: str = "amazon.titan-embed-text-v2:0"

    # --- Vector store ---
    vector_backend: VectorBackend = "opensearch"
    index_name: str = "polyphemus-chunks"

    # --- Storage ---
    documents_bucket: str = "polyphemus-documents-local"

    # --- Retrieval tuning ---
    top_k: int = 5
    similarity_floor: float = 0.05

    # --- Chunking ---
    chunk_size: int = 600
    chunk_overlap: int = 80

    # --- Embeddings ---
    embed_dim: int = 256

    # --- Audit ---
    audit_dir: str = "audit"
    audit_file: str = "audit.log"

    @property
    def is_mock(self) -> bool:
        return self.mode == "mock"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached Settings instance built from the environment."""
    return Settings()


def reset_settings_cache() -> None:
    """Clear the cached settings (used by tests that flip env vars)."""
    get_settings.cache_clear()
