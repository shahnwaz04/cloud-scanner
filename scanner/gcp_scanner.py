from __future__ import annotations

import json

from google.cloud import compute_v1
from google.cloud import storage
from google.oauth2 import service_account

from scanner.utils import create_finding


def _build_credentials(service_account_json: str):
    info = json.loads(service_account_json)
    return service_account.Credentials.from_service_account_info(
        info,
        scopes=["https://www.googleapis.com/auth/cloud-platform"],
    )


def _is_public_member(member: str) -> bool:
    return member in {"allUsers", "allAuthenticatedUsers"}


def scan_gcp(project_id: str, service_account_json: str):
    credentials = _build_credentials(service_account_json)
    findings = []

    firewall_client = compute_v1.FirewallsClient(credentials=credentials)
    for rule in firewall_client.list(project=project_id):
        if rule.direction != "INGRESS":
            continue
        if "0.0.0.0/0" not in (rule.source_ranges or []):
            continue

        for allowed in rule.allowed or []:
            ports = list(allowed.ports or [])
            if not ports:
                ports = ["*"]

            if "22" in ports or "*" in ports:
                findings.append(
                    create_finding(
                        "VPC Firewall",
                        rule.name,
                        "Port 22 open to 0.0.0.0/0",
                        "HIGH",
                        "global",
                        "GCP",
                    )
                )
            elif "3389" in ports:
                findings.append(
                    create_finding(
                        "VPC Firewall",
                        rule.name,
                        "Port 3389 open to 0.0.0.0/0",
                        "HIGH",
                        "global",
                        "GCP",
                    )
                )
            else:
                findings.append(
                    create_finding(
                        "VPC Firewall",
                        rule.name,
                        "Public ingress firewall rule detected",
                        "MEDIUM",
                        "global",
                        "GCP",
                    )
                )

    storage_client = storage.Client(project=project_id, credentials=credentials)
    for bucket in storage_client.list_buckets(project=project_id):
        policy = bucket.get_iam_policy(requested_policy_version=3)
        is_public = False
        for binding in policy.bindings:
            members = binding.get("members", [])
            if any(_is_public_member(member) for member in members):
                is_public = True
                break
        if is_public:
            findings.append(
                create_finding(
                    "Cloud Storage",
                    bucket.name,
                    "Bucket has public IAM binding",
                    "CRITICAL",
                    bucket.location or "global",
                    "GCP",
                )
            )

    return findings
