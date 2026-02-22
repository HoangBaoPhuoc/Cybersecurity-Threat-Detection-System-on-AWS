# Default Incident Response Playbook

## Purpose

Provide baseline actions for high-risk security events when no specific playbook match is found.

## Approved Actions

- BLOCK_WAF
- RESTRICT_IAM
- RUN_SSM

## Actions

1. Block the source IP in AWS WAF if the event includes a suspicious IP.
2. Restrict IAM user access for privileged accounts showing anomalous behavior.
3. Run the containment SSM runbook on affected instances.

## Jira Guidance

- Summary: "SOC Alert - Automated Containment"
- Description: Include risk score, entity, and detection signals.
