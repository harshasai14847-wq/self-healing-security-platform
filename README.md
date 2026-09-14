# Self-Healing Security Platform

An automated container security platform that detects vulnerabilities, analyzes their severity, applies safe remediation, verifies the result, and deploys the improved application using blue-green deployment with automatic rollback.

## Overview

The Self-Healing Security Platform combines vulnerability scanning, threat intelligence, automated remediation, security verification, health testing, and deployment automation into one pipeline.

## Architecture

User Application
        ↓
Security Dashboard
        ↓
Host Security Controller
        ↓
Trivy Vulnerability Scanner
        ↓
CISA KEV Check
        ↓
Vulnerability Analysis
        ↓
Automatic Remediation
        ↓
Docker Rebuild
        ↓
Rescan + Security Comparison
        ↓
SBOM Generation
        ↓
Health Testing
        ↓
Blue-Green Deployment
        ↓
Monitoring / Automatic Rollback

## Main Features

- Dockerized application security
- Trivy vulnerability scanning
- CISA Known Exploited Vulnerabilities (KEV) monitoring
- Vulnerability severity analysis
- Automatic remediation when a safe fixed version is available
- Docker image rebuilding
- Post-remediation security verification
- SBOM generation using CycloneDX
- Application health testing
- Blue-green deployment
- Automatic traffic switching
- Automatic rollback when the candidate application fails health checks
- Security CI/CD using GitHub Actions
- Web-based security dashboard

## Self-Healing Pipeline

The pipeline performs the following steps:

1. Scan the application image.
2. Analyze discovered vulnerabilities.
3. Check vulnerabilities against CISA KEV.
4. Create a remediation decision.
5. Automatically update fixable dependencies.
6. Build a new Docker image.
7. Rescan the rebuilt image.
8. Compare the security posture before and after remediation.
9. Generate an SBOM.
10. Run application health checks.
11. Deploy the candidate using blue-green deployment.
12. Roll back automatically if the candidate fails health checks.

The system does not claim to fix every vulnerability. It only performs automatic remediation when an appropriate safe fix is available.

## Technologies

- Python
- Flask
- Docker
- Trivy
- Nginx
- CISA KEV
- GitHub Actions
- CycloneDX SBOM
- PowerShell

## Project Structure

```text
self-healing-security-platform/
│
├── .github/
│   └── workflows/
│       └── security.yml
│
├── app/
│   ├── app.py
│   └── templates/
│
├── Dockerfile
├── nginx.conf
├── application_scanner.py
├── auto_remediation.py
├── auto_rollback.py
├── cisa_kev_monitor.py
├── self_healing_pipeline.py
└── README.md
