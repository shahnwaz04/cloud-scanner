from __future__ import annotations

from azure.identity import ClientSecretCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.storage import StorageManagementClient

from scanner.utils import create_finding


def _parse_resource_group(resource_id: str) -> str:
    parts = resource_id.split("/")
    for idx, part in enumerate(parts):
        if part.lower() == "resourcegroups" and idx + 1 < len(parts):
            return parts[idx + 1]
    return ""


def _is_public_source(prefix: str | None, prefixes: list[str] | None) -> bool:
    public_values = {"*", "internet", "0.0.0.0/0"}
    if prefix and prefix.lower() in public_values:
        return True
    if prefixes:
        for item in prefixes:
            if item and item.lower() in public_values:
                return True
    return False


def _contains_sensitive_port(port_ranges: list[str]) -> tuple[bool, bool]:
    has_ssh = False
    has_rdp = False
    for port in port_ranges:
        if port in {"*", "22"}:
            has_ssh = True
        if port in {"*", "3389"}:
            has_rdp = True
    return has_ssh, has_rdp


def scan_azure(
    tenant_id: str,
    client_id: str,
    client_secret: str,
    subscription_id: str,
):
    credential = ClientSecretCredential(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
    )
    network_client = NetworkManagementClient(credential, subscription_id)
    storage_client = StorageManagementClient(credential, subscription_id)

    findings = []

    for nsg in network_client.network_security_groups.list_all():
        for rule in nsg.security_rules or []:
            if rule.access != "Allow" or rule.direction != "Inbound":
                continue

            if not _is_public_source(rule.source_address_prefix, rule.source_address_prefixes):
                continue

            ports = rule.destination_port_ranges or []
            if not ports and rule.destination_port_range:
                ports = [rule.destination_port_range]
            if not ports:
                ports = ["*"]

            has_ssh, has_rdp = _contains_sensitive_port(ports)

            if has_ssh:
                findings.append(
                    create_finding(
                        "NSG",
                        f"{nsg.name}/{rule.name}",
                        "Port 22 open to 0.0.0.0/0",
                        "HIGH",
                        nsg.location,
                        "AZURE",
                    )
                )
            elif has_rdp:
                findings.append(
                    create_finding(
                        "NSG",
                        f"{nsg.name}/{rule.name}",
                        "Port 3389 open to 0.0.0.0/0",
                        "HIGH",
                        nsg.location,
                        "AZURE",
                    )
                )
            else:
                findings.append(
                    create_finding(
                        "NSG",
                        f"{nsg.name}/{rule.name}",
                        "Public inbound rule detected",
                        "MEDIUM",
                        nsg.location,
                        "AZURE",
                    )
                )

    for account in storage_client.storage_accounts.list():
        resource_group = _parse_resource_group(account.id)
        if not resource_group:
            continue
        props = storage_client.storage_accounts.get_properties(resource_group, account.name)
        if getattr(props, "allow_blob_public_access", False):
            findings.append(
                create_finding(
                    "Storage",
                    account.name,
                    "Storage account allows blob public access",
                    "CRITICAL",
                    account.location,
                    "AZURE",
                )
            )

    return findings
