"""In-memory S3 fake.

A tiny dict-backed store supporting the handful of operations the ingestion
layer needs: ``put_object``, ``get_object``, ``list_objects_v2`` and per-object
metadata. Keys are ``s3://bucket/key`` style but stored flat per bucket.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field


@dataclass
class _S3Object:
    body: bytes
    metadata: dict[str, str] = field(default_factory=dict)


class MockS3:
    """A minimal, deterministic S3 replacement for offline ingestion."""

    def __init__(self) -> None:
        self._buckets: dict[str, dict[str, _S3Object]] = {}

    def _bucket(self, name: str) -> dict[str, _S3Object]:
        return self._buckets.setdefault(name, {})

    def put_object(
        self,
        Bucket: str,  # noqa: N803 (match boto3 signature)
        Key: str,  # noqa: N803
        Body: bytes | str,  # noqa: N803
        Metadata: dict[str, str] | None = None,  # noqa: N803
    ) -> dict[str, str]:
        body = Body.encode("utf-8") if isinstance(Body, str) else Body
        self._bucket(Bucket)[Key] = _S3Object(body=body, metadata=dict(Metadata or {}))
        # Deterministic ETag over the actual object bytes (like S3's content MD5).
        # hashlib is used instead of the builtin hash(), which is salted per-process.
        etag = hashlib.sha256(body).hexdigest()
        return {"ETag": f'"{etag}"'}

    def get_object(self, Bucket: str, Key: str) -> dict[str, object]:  # noqa: N803
        obj = self._bucket(Bucket)[Key]
        return {
            "Body": _BytesBody(obj.body),
            "Metadata": dict(obj.metadata),
        }

    def list_objects_v2(self, Bucket: str, Prefix: str = "") -> dict[str, object]:  # noqa: N803
        keys = sorted(k for k in self._bucket(Bucket) if k.startswith(Prefix))
        return {
            "Contents": [{"Key": k, "Size": len(self._bucket(Bucket)[k].body)} for k in keys],
            "KeyCount": len(keys),
        }


class _BytesBody:
    """Mimics the boto3 StreamingBody ``.read()`` interface."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    def read(self) -> bytes:
        return self._data
