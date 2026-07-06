"""Vector stack — OpenSearch Serverless collection (mirrors opensearch_serverless)."""

from __future__ import annotations

import json

from aws_cdk import Stack
from aws_cdk import aws_opensearchserverless as aoss
from constructs import Construct


class VectorStack(Stack):
    def __init__(self, scope: Construct, cid: str, *, name_prefix: str, **kwargs) -> None:
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
                            }
                        ],
                        "AllowFromPublic": False,
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
