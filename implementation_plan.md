# Implementation Plan - Improve Financial System Simulation

## Goal
Enhance the Financial System simulation to provide better data for Filebeat, Metricbeat, and Auditbeat. This involves turning the Python script into a proper service and adding real network activity.

## User Review Required
> [!NOTE]
> The Financial App will now open port **5000** (Flask default) to simulate a real web application backend. This allows Metricbeat and Auditbeat to detect actual network socket usage.

## Proposed Changes

### Source Code

#### [MODIFY] [src/financial_app.py](file:///e:/UIT/Cybersecurity%20Threat%20Detection%20System%20on%20AWS/src/financial_app.py)
- Import `flask` and `threading`.
- Create a simple Flask app with a `/` and `/health` route.
- Run the Flask app in a daemon thread so it runs alongside the log generator.
- This creates a real listening process `python3` on port 5000.

### Infrastructure

#### [MODIFY] [infrastructure/main.tf](file:///e:/UIT/Cybersecurity%20Threat%20Detection%20System%20on%20AWS/infrastructure/main.tf)
- **Security Group (`aws_security_group.financial_sg`)**: Add ingress rule for port 5000 (Custom TCP) to allow internal VPC traffic (simulating internal API access).
- **User Data (`aws_instance.financial_server.user_data`)**:
    - Remove the `nohup python3 /opt/financial_app/app.py ...` line.
    - Add logic to create `/etc/systemd/system/financial-app.service`.
    - Enable and start the `financial-app` service.

## Verification Plan

### Automated
- **Terraform Validate**: Run `terraform validate` to ensure the configuration is correct.

### Manual
- Since I cannot deploy this to AWS, I will verify the file contents:
    - Check `src/financial_app.py` for the Flask integration.
    - Check `infrastructure/main.tf` for the Systemd service definition and SG rules.
