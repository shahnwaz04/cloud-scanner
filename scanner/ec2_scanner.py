import boto3
from botocore.exceptions import ClientError
from scanner.utils import get_all_regions
from scanner.utils import create_finding


# def create_finding(service, resource, issue, severity, region=None):
#     return {
#         "service": service,
#         "resource": resource,
#         "issue": issue,
#         "severity": severity,
#         "region": region
#     }


def scan_ec2(session=None):
    findings = []
    active_session = session or boto3.session.Session()
    regions = get_all_regions(active_session)

    for region in regions:
        ec2 = active_session.client("ec2", region_name=region)

        try:
            security_groups = ec2.describe_security_groups()["SecurityGroups"]

            for sg in security_groups:
                sg_id = sg["GroupId"]

                for permission in sg.get("IpPermissions", []):
                    from_port = permission.get("FromPort")
                    to_port = permission.get("ToPort")

                    for ip_range in permission.get("IpRanges", []):
                        cidr = ip_range.get("CidrIp")

                        if cidr == "0.0.0.0/0":

                            # 🔴 SSH Open
                            if from_port == 22:
                                findings.append(
                                    create_finding(
                                        "EC2",
                                        sg_id,
                                        "Port 22 (SSH) open to 0.0.0.0/0",
                                        "HIGH",
                                        region
                                    )
                                )

                            # 🔴 RDP Open
                            elif from_port == 3389:
                                findings.append(
                                    create_finding(
                                        "EC2",
                                        sg_id,
                                        "Port 3389 (RDP) open to 0.0.0.0/0",
                                        "HIGH",
                                        region
                                    )
                                )

                            # 🟠 Other Public Port
                            else:
                                findings.append(
                                    create_finding(
                                        "EC2",
                                        sg_id,
                                        f"Port {from_port} open to world",
                                        "MEDIUM",
                                        region
                                    )
                                )

        except ClientError as e:
            print(f"EC2 scan error in {region}: {e}")
            continue

    return findings 


