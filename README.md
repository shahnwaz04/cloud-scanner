# Cloud Security Scanner

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Docker](https://img.shields.io/badge/Docker-Containerized-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-Minikube-326CE5?logo=kubernetes&logoColor=white)](https://kubernetes.io/)
[![AWS](https://img.shields.io/badge/AWS-IAM%20%7C%20S3%20%7C%20EC2-FF9900?logo=amazonaws&logoColor=white)](https://aws.amazon.com/)

Cloud Security Scanner is a cloud-native AWS misconfiguration scanner built with FastAPI, Boto3, Docker, and Kubernetes.

It analyzes IAM, S3, and EC2 configurations, assigns severity-based findings, calculates risk posture, and visualizes scan results in a modern web dashboard.

## Table of Contents

- [Why This Project](#why-this-project)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Quick Start (2 Minutes)](#quick-start-2-minutes)
- [Local Development](#local-development)
- [Docker Deployment](#docker-deployment)
- [Kubernetes Deployment (Minikube)](#kubernetes-deployment-minikube)
- [API Reference](#api-reference)
- [Security Model](#security-model)
- [Operational Validation](#operational-validation)
- [Troubleshooting](#troubleshooting)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

## Why This Project

Cloud environments fail mostly due to misconfiguration, not just software vulnerabilities. This project demonstrates a practical DevSecOps workflow by combining:

- Automated AWS configuration checks
- API-first backend design
- Cloud-native packaging and orchestration
- Usable frontend for non-terminal users

## Key Features

### AWS Security Checks

- IAM
  - Detect IAM users with `AdministratorAccess`
  - Detect IAM users without MFA
- S3
  - Detect public bucket policies
  - Detect public ACL exposure
- EC2
  - Detect security groups exposing SSH (`22`) to `0.0.0.0/0`
  - Detect security groups exposing RDP (`3389`) to `0.0.0.0/0`
  - Detect other public ports

### Risk & Reporting

- Severity levels: `CRITICAL`, `HIGH`, `MEDIUM`
- Weighted risk score
- Security level classification
- JSON report persisted to `reports/report.json`
- PDF report generation

### Frontend Dashboard

- AWS credential connect flow (`Connect AWS`)
- Credential validation using AWS STS
- Severity and service charts
- Searchable/filtered findings table
- In-browser recent scan history

## Architecture

```text
Browser Dashboard
   -> FastAPI API (api/main.py)
      -> AWS Session (UI credentials or default session)
         -> Scanners (IAM, S3, EC2)
            -> Report JSON + PDF
               -> Dashboard Rendering
```

## Project Structure

```text
cloud-security-scanner/
|- api/
|  |- main.py
|- frontend/
|  |- index.html
|  |- script.js
|  |- style.css
|- scanner/
|  |- iam_scanner.py
|  |- s3_scanner.py
|  |- ec2_scanner.py
|  |- compliance.py
|  |- utils.py
|- reports/
|- deployment.yaml
|- service.yaml
|- Dockerfile
|- requirements.txt
|- README.md
```

## Quick Start (2 Minutes)

```powershell
cd "D:\COLLEGE 25-26\CLOUD\cloud-security-scanner"
pip install -r requirements.txt
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```

Open:

- Dashboard: `http://localhost:8000/`
- Swagger: `http://localhost:8000/docs`

Then in UI:

1. Click `Connect AWS`
2. Enter credentials
3. Click `Run New Scan`

## Local Development

### Prerequisites

- Python 3.11+
- AWS credentials with read permissions for IAM, S3, EC2

### Run

```powershell
cd "D:\COLLEGE 25-26\CLOUD\cloud-security-scanner"
pip install -r requirements.txt
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```

## Docker Deployment

```powershell
cd "D:\COLLEGE 25-26\CLOUD\cloud-security-scanner"
docker build -t aws-scanner:1.0 .
docker run -p 8000:8000 aws-scanner:1.0
```

Open `http://localhost:8000/` and use `Connect AWS`.

## Kubernetes Deployment (Minikube)

Current Kubernetes config is UI-auth based. No `aws-credentials` secret is required.

```powershell
cd "D:\COLLEGE 25-26\CLOUD\cloud-security-scanner"
minikube start --driver=docker
minikube -p minikube docker-env --shell powershell | Invoke-Expression
docker build -t aws-scanner .
kubectl delete -f deployment.yaml --ignore-not-found
kubectl delete -f service.yaml --ignore-not-found
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
kubectl get deployments
kubectl get pods
kubectl get svc
minikube service aws-scanner-service --url
```

Alternative access:

```powershell
kubectl port-forward svc/aws-scanner-service 8000:8000
```

## API Reference

### `GET /`
Serves frontend dashboard.

### `POST /auth/aws`
Validates submitted AWS credentials via STS.

Request body:

```json
{
  "credentials": {
    "access_key_id": "AKIA...",
    "secret_access_key": "...",
    "session_token": null,
    "default_region": "eu-north-1"
  }
}
```

### `POST /scan?mode=BASIC|CIS|STRICT`
Runs scanner and returns report.

- `BASIC`: IAM + S3
- `CIS` / `STRICT`: IAM + S3 + EC2

### `GET /report`
Returns last full report JSON.

### `GET /summary`
Returns summary-only response (score, level, mode, regions).

## Security Model

### Current

- Credentials entered via UI
- Backend validates with STS
- Frontend stores credentials in browser `sessionStorage` (session scope)

### Recommended for Production

- Use IAM roles instead of long-lived keys
- Add authentication and RBAC to scanner UI/API
- Add HTTPS + secure session handling
- Add audit logging and centralized monitoring
- Restrict CORS and network exposure

## Operational Validation

### Kubernetes self-healing check

```powershell
kubectl get pods
kubectl delete pod <pod-name>
kubectl get pods -w
```

Expected: Deployment recreates pod automatically.

## Troubleshooting

- If terminal shows `>>`, press `Ctrl + C` to cancel multiline input.
- If `ImagePullBackOff` occurs:
  - Re-run: `minikube -p minikube docker-env --shell powershell | Invoke-Expression`
  - Rebuild image.
- If scans fail:
  - Reconnect credentials from `Connect AWS`
  - Ensure IAM user/role has required read permissions

## Roadmap

- Add RDS and Lambda checks
- Export trend analytics over time
- Add auth layer (JWT/OAuth)
- Add CI/CD pipeline with security gates
- Deploy to managed Kubernetes (EKS)

## Contributing

Contributions are welcome.

1. Fork the repository
2. Create a feature branch
3. Make changes with tests/docs updates
4. Open a pull request

## License

This project is licensed under the MIT License.
See the [LICENSE](LICENSE) file for details.

## Author

Md Umar Faisal
