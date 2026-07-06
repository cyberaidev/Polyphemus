"""Upload sample documents into (mock) S3 with object metadata.

In mock mode this populates the in-memory S3 fake so the rest of the pipeline can
demonstrate an S3-backed ingest flow without any AWS account. Object metadata
mirrors the ACL fields (department, classification) as S3 user metadata.
"""

from __future__ import annotations

from polyphemus.aws.clients import get_s3
from polyphemus.config import get_settings
from polyphemus.ingestion.loader import load_documents
from polyphemus.models import Document


def upload_sample_documents(include_malicious: bool = True) -> list[Document]:
    """Put every sample document into (mock) S3 and return the documents."""
    settings = get_settings()
    s3 = get_s3(settings)
    documents = load_documents(include_malicious=include_malicious)
    for doc in documents:
        key = doc.source_uri.replace("file://data/documents/", "")
        s3.put_object(
            Bucket=settings.documents_bucket,
            Key=key,
            Body=doc.text,
            Metadata={
                "department": doc.department,
                "classification": doc.classification,
                "doc_id": doc.doc_id,
            },
        )
    return documents
