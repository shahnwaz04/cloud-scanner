import boto3


def get_all_regions(session=None):
    active_session = session or boto3.session.Session()
    ec2 = active_session.client("ec2")
    response = ec2.describe_regions(AllRegions=False)
    return [region["RegionName"] for region in response["Regions"]]



def create_finding(service, resource, issue, severity, region=None, provider="AWS"):
    recommendations = {
        "User has AdministratorAccess policy":
            "Apply least privilege principle. Remove AdministratorAccess and assign granular IAM roles.",
        "User does not have MFA enabled":
            "Enable Multi-Factor Authentication (MFA) for this IAM user.",
        "Bucket has public policy":
            "Remove public access from bucket policy and restrict access via IAM roles.",
        "Bucket is public via ACL":
            "Disable public ACL and enable Block Public Access setting.",
        "Port 22 open to 0.0.0.0/0":
            "Restrict SSH access to specific IP addresses instead of 0.0.0.0/0.",
        "Port 3389 open to 0.0.0.0/0":
            "Restrict RDP access to trusted IP ranges only.",
        "Public inbound rule detected":
            "Restrict inbound access to trusted CIDRs and minimum required ports only.",
        "Storage account allows blob public access":
            "Disable public blob access and use private endpoints or scoped identities.",
        "Public ingress firewall rule detected":
            "Limit ingress ranges and exposed ports to trusted networks only.",
        "Bucket has public IAM binding":
            "Remove public IAM members (allUsers/allAuthenticatedUsers) and apply least privilege."
    }

    severity_score = {
        "CRITICAL": 9.5,
        "HIGH": 8.0,
        "MEDIUM": 6.0
    }

    return {
        "provider": provider,
        "service": service,
        "resource": resource,
        "issue": issue,
        "severity": severity,
        "region": region,
        "risk_score": severity_score.get(severity, 5),
        "recommendation": recommendations.get(issue, "Review configuration and apply security best practices."),
        "cis_control": "CIS AWS Foundations Benchmark"
    }
