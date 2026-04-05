COMPLIANCE_PROFILES = {
    "BASIC": ["IAM", "S3"],
    "CIS": ["IAM", "S3", "EC2"],
    "STRICT": ["IAM", "S3", "EC2"]
}

def get_services(mode):
    return COMPLIANCE_PROFILES.get(mode.upper(), ["IAM", "S3"])