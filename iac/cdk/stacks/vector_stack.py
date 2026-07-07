"""Vector stack — OpenSearch Serverless collection (mirrors opensearch_serverless)."""

from __future__ import annotations

import json

from aws_cdk import Stack
from aws_cdk import aws_opensearchserverless as aoss
from constructs import Construct


class VectorStack(Stack):
    def __init__(
        self,
        scope: Construct,
        cid: str,
        *,
        name_prefix: str,
        data_access_principals: list[str] | None = None,
        **kwargs,
    ) -> None:
        super().__init__(scope, cid, **kwargs)

        collection_name = f"{name_prefix}-vectors"

        encryption = aoss.CfnSecurityPolicy(
            self,
            "EncryptionPolicy",
            name=f"{name_prefix}-enc",
            type="encryption",
            policy=json.dumps(
                {
                    "Rules": [
                        {
                            "ResourceType": "collection",
                            "Resource": [f"collection/{collection_name}"],
                        }
                    ],
                    "AWSOwnedKey": True,
                }
            ),
        )

        network = aoss.CfnSecurityPolicy(
            self,
            "NetworkPolicy",
            name=f"{name_prefix}-net",
            type="network",
            policy=json.dumps(
                [
                    {
                        "Description": "Private access to the Polyphemus vector collection",
                        "Rules": [
                            {
                                "ResourceType": "collection",
                                "Resource": [f"collection/{collection_name}"],
                            },
                            # Mirror the Terraform network policy: the dashboard
                            # endpoint is also private (AllowFromPublic=false).
                            {
                                "ResourceType": "dashboard",
                                "Resource": [f"collection/{collection_name}"],
                            },
                        ],
                        "AllowFromPublic": False,
                    }
                ]
            ),
        )

        # Data-access policy — least-privilege index read/write for the pipeline
        # principal(s). Mirrors the Terraform opensearch_serverless access policy.
        # Principals are wired at deploy time (e.g. the Lambda role ARN); left empty
        # here so the reference synths without a concrete account/role.
        data_access = aoss.CfnAccessPolicy(
            self,
            "DataAccessPolicy",
            name=f"{name_prefix}-data",
            type="data",
            policy=json.dumps(
                [
                    {
                        "Description": "Pipeline read/write to the vector index",
                        "Rules": [
                            {
                                "ResourceType": "index",
                                "Resource": [f"index/{collection_name}/*"],
                                "Permission": [
                                    "aoss:CreateIndex",
                                    "aoss:UpdateIndex",
                                    "aoss:DescribeIndex",
                                    "aoss:ReadDocument",
                                    "aoss:WriteDocument",
                                ],
                            }
                        ],
                        "Principal": data_access_principals or [],
                    }
                ]
            ),
        )

        self.collection = aoss.CfnCollection(
            self,
            "VectorCollection",
            name=collection_name,
            type="VECTORSEARCH",
        )
        self.collection.add_dependency(encryption)
        self.collection.add_dependency(network)
        self.collection.add_dependency(data_access)
