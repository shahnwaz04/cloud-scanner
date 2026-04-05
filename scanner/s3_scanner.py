import boto3
import json
from botocore.exceptions import ClientError
from scanner.utils import create_finding

# def create_finding(service, resource, issue, severity):
#     return {
#         "service": service,
#         "resource": resource,
#         "issue": issue,
#         "severity": severity
#     }


def scan_s3(session=None):
    findings = []
    active_session = session or boto3.session.Session()
    s3 = active_session.client("s3")

    try:
        buckets = s3.list_buckets()["Buckets"]

        for bucket in buckets:
            bucket_name = bucket["Name"]

            # 🔴 Check Bucket Policy
            try:
                policy = s3.get_bucket_policy(Bucket=bucket_name)
                policy_json = json.loads(policy["Policy"])

                for statement in policy_json.get("Statement", []):
                    if (
                        statement.get("Effect") == "Allow"
                        and statement.get("Principal") == "*"
                    ):
                        findings.append(
                            create_finding(
                                "S3",
                                bucket_name,
                                "Bucket has public policy",
                                "CRITICAL"
                            )
                        )

            except ClientError as e:
                if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
                    print(f"S3 policy error ({bucket_name}): {e}")

            # 🔴 Check Bucket ACL
            try:
                acl = s3.get_bucket_acl(Bucket=bucket_name)

                for grant in acl["Grants"]:
                    grantee = grant.get("Grantee", {})
                    if grantee.get("URI") in [
                        "http://acs.amazonaws.com/groups/global/AllUsers",
                        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
                    ]:
                        findings.append(
                            create_finding(
                                "S3",
                                bucket_name,
                                "Bucket is public via ACL",
                                "CRITICAL"
                            )
                        )

            except ClientError as e:
                print(f"S3 ACL error ({bucket_name}): {e}")

    except ClientError as e:
        print(f"S3 scan error: {e}")

    return findings
